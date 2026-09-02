package dev.gaphunter.spelinjectionsinkcompanion.detect

import com.intellij.psi.JavaPsiFacade
import com.intellij.psi.JavaRecursiveElementWalkingVisitor
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiExpression
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiMethod
import com.intellij.psi.PsiMethodCallExpression
import com.intellij.psi.PsiNewExpression
import com.intellij.psi.PsiReferenceExpression
import com.intellij.psi.PsiVariable
import dev.gaphunter.spelinjectionsinkcompanion.model.SpelSinkHit
import dev.gaphunter.spelinjectionsinkcompanion.model.SpelSinkKind
import dev.gaphunter.spelinjectionsinkcompanion.spel.SpelDangerousTypeChecker
import dev.gaphunter.spelinjectionsinkcompanion.spel.SpelParser

/**
 * Finds `parser.parseExpression(ARG)` call sites (where `parser`'s
 * declared type mentions `ExpressionParser`, see
 * [looksLikeExpressionParser]) and produces one of two real,
 * independent findings:
 *
 * 1. **Tainted argument** -- ARG is built (directly, or via a one-hop
 *    reference inside a simple concatenation) from a parameter of an
 *    HTTP endpoint method ([ControllerEndpointSignals]). This alone is
 *    CWE-917: the attacker's raw string becomes SpEL SOURCE TEXT
 *    re-parsed as an expression, exactly the mechanism CVE-2022-22963
 *    (Spring Cloud Function) exploited -- no AST-shape nuance changes
 *    that, since the attacker controls what shape the substituted text
 *    takes. Same same-method, one-hop taint discipline as
 *    `unsafe-deserialization-sink-companion`'s own finder.
 * 2. **Hardcoded dangerous type** -- ARG is a genuine compile-time
 *    constant (real IntelliJ constant-folding via
 *    [JavaPsiFacade.getConstantEvaluationHelper], not a hand-rolled
 *    literal check -- returns null the moment ARG references anything
 *    non-constant, which is also how case 1 and case 2 stay mutually
 *    exclusive) whose parsed SpEL AST ([SpelParser], this plugin's own
 *    grammar) contains a `T(...)` reference to a class real RCE
 *    payloads use ([SpelDangerousTypeChecker]) -- a hardcoded backdoor/
 *    mistake, not an injection, but a distinct real risk worth its own
 *    finding.
 *
 * **v0.1 scope, stated honestly:** only Java; only same-method taint
 * (case 1 never crosses a method boundary); `looksLikeExpressionParser`
 * is a declared-type-TEXT heuristic, never resolved against the real
 * Spring classpath (works even in a project/test with no Spring
 * dependency present at all -- same reasoning
 * `unsafe-deserialization-sink-companion` uses for `ObjectInputStream`
 * by simple name only); never distinguishes `SimpleEvaluationContext`
 * (restricted) from `StandardEvaluationContext` (full power) at the
 * `.getValue(...)` call site -- left for a future version.
 */
object JavaSpelInjectionSinkFinder {

    fun findAll(file: PsiFile): List<SpelSinkHit> {
        val hits = mutableListOf<SpelSinkHit>()
        file.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethod(method: PsiMethod) {
                super.visitMethod(method)
                hits += hitsForMethod(method)
            }
        })
        return hits
    }

    private fun hitsForMethod(method: PsiMethod): List<SpelSinkHit> {
        val body = method.body ?: return emptyList()
        val taintedNames = if (ControllerEndpointSignals.isEndpointMethod(method)) {
            method.parameterList.parameters.map { it.name }.toSet()
        } else {
            emptySet()
        }

        val hits = mutableListOf<SpelSinkHit>()
        body.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitMethodCallExpression(call: PsiMethodCallExpression) {
                super.visitMethodCallExpression(call)
                if (call.methodExpression.referenceName != "parseExpression") return
                if (!looksLikeExpressionParser(call.methodExpression.qualifierExpression)) return
                val argument = call.argumentList.expressions.getOrNull(0) ?: return

                // The precise "parseExpression" name identifier -- NOT a naive
                // firstChild walk of the whole call: a bare (unqualified)
                // PsiReferenceExpression's child order can put an EMPTY
                // PsiReferenceParameterList (generic type arguments, unused
                // here) before its real identifier token, and IntelliJ
                // rejects a zero-length element as a problem anchor. Found
                // the hard way via this plugin's own test suite.
                val anchor = call.methodExpression.referenceNameElement ?: anchorOf(call)

                if (taintedNames.isNotEmpty()) {
                    val taintedName = firstTaintedReference(argument, taintedNames)
                    if (taintedName != null) {
                        hits += SpelSinkHit(anchor, SpelSinkKind.TAINTED_ARGUMENT, taintedName)
                        return
                    }
                }

                val constantValue = constantStringValue(argument) ?: return
                val ast = SpelParser.parse(constantValue) ?: return
                val dangerousType = SpelDangerousTypeChecker.findDangerousTypeReference(ast) ?: return
                hits += SpelSinkHit(anchor, SpelSinkKind.HARDCODED_DANGEROUS_TYPE, dangerousType)
            }
        })
        return hits
    }

    private fun firstTaintedReference(expression: PsiElement, taintedNames: Set<String>): String? {
        var found: String? = null
        expression.accept(object : JavaRecursiveElementWalkingVisitor() {
            override fun visitReferenceExpression(expr: PsiReferenceExpression) {
                if (found != null) return
                super.visitReferenceExpression(expr)
                val name = expr.referenceName
                if (name != null && name in taintedNames) found = name
            }
        })
        return found
    }

    /** Real IntelliJ constant folding -- returns null the moment [expression] references anything that isn't itself a compile-time constant (a method parameter included), never a hand-rolled "literal-only" approximation. */
    private fun constantStringValue(expression: PsiExpression): String? {
        val value = JavaPsiFacade.getInstance(expression.project).constantEvaluationHelper.computeConstantExpression(expression)
        return value as? String
    }

    /**
     * `new SpelExpressionParser().parseExpression(...)` (qualifier IS
     * the `new` expression), or `parser.parseExpression(...)` where
     * `parser`'s declared type TEXT mentions `ExpressionParser` --
     * text-only, never resolved against the real Spring classpath (see
     * class doc).
     */
    private fun looksLikeExpressionParser(qualifier: PsiExpression?): Boolean {
        if (qualifier is PsiNewExpression) {
            return qualifier.classReference?.referenceName?.contains("ExpressionParser") == true
        }
        val resolved = (qualifier as? PsiReferenceExpression)?.resolve() as? PsiVariable ?: return false
        return resolved.type.presentableText.contains("ExpressionParser")
    }

    private fun anchorOf(element: PsiElement): PsiElement {
        var current = element
        while (current.firstChild != null) current = current.firstChild
        return current
    }
}
