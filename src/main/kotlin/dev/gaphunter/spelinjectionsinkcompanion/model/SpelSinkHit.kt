package dev.gaphunter.spelinjectionsinkcompanion.model

import com.intellij.psi.PsiElement

enum class SpelSinkKind { TAINTED_ARGUMENT, HARDCODED_DANGEROUS_TYPE }

/**
 * One finding from [dev.gaphunter.spelinjectionsinkcompanion.detect.JavaSpelInjectionSinkFinder]:
 * either a controller parameter flowing (same-method, one-hop) into a
 * `parseExpression(...)` argument ([SpelSinkKind.TAINTED_ARGUMENT],
 * [detail] is the tainted parameter's name), or a fully compile-time-
 * constant expression string whose parsed AST references a dangerous
 * `T(...)` type ([SpelSinkKind.HARDCODED_DANGEROUS_TYPE], [detail] is
 * the type name found).
 */
data class SpelSinkHit(val anchor: PsiElement, val kind: SpelSinkKind, val detail: String)
