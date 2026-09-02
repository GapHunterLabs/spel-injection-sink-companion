package dev.gaphunter.spelinjectionsinkcompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.psi.PsiFile
import dev.gaphunter.spelinjectionsinkcompanion.detect.JavaSpelInjectionSinkFinder
import dev.gaphunter.spelinjectionsinkcompanion.model.SpelSinkHit
import dev.gaphunter.spelinjectionsinkcompanion.model.SpelSinkKind
import dev.gaphunter.spelinjectionsinkcompanion.review.ReviewPrompt

/**
 * Flags a Spring `ExpressionParser.parseExpression(...)` call whose
 * argument is either tainted by an HTTP endpoint parameter (CWE-917,
 * the CVE-2022-22963 mechanism) or a hardcoded constant whose parsed
 * SpEL AST references a dangerous `T(...)` type. See
 * [JavaSpelInjectionSinkFinder] for the real mechanism.
 */
class SpelInjectionSinkInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        if (file.text.length > MAX_FILE_LENGTH) return null

        val hits = JavaSpelInjectionSinkFinder.findAll(file)
        if (hits.isEmpty()) return null

        val problems = hits.map { hit ->
            manager.createProblemDescriptor(
                hit.anchor,
                messageFor(hit),
                isOnTheFly,
                emptyArray(),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
            )
        }

        val path = file.virtualFile?.path
        if (path != null) {
            for (hit in hits) {
                val lineNumber = file.viewProvider.document?.getLineNumber(hit.anchor.textRange.startOffset) ?: -1
                ReviewPrompt.recordHit(file.project, "$path:$lineNumber:${hit.kind}")
            }
        }

        return problems.toTypedArray()
    }

    private fun messageFor(hit: SpelSinkHit): String = when (hit.kind) {
        SpelSinkKind.TAINTED_ARGUMENT ->
            "SpEL expression built from endpoint parameter '${hit.detail}' -- an attacker's raw input becomes " +
                "expression SOURCE TEXT re-parsed by SpEL (CWE-917), the exact mechanism CVE-2022-22963 exploited"
        SpelSinkKind.HARDCODED_DANGEROUS_TYPE ->
            "Hardcoded SpEL expression references T(${hit.detail}) -- the concrete construct real SpEL-injection " +
                "RCE payloads use to reach an arbitrary static method"
    }
}
