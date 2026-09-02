package dev.gaphunter.spelinjectionsinkcompanion.spel

/**
 * Walks a [SpelNode] tree looking for a `T(...)` reference to one of a
 * small, curated list of classes whose static methods are the go-to
 * payload primitives in every published SpEL-injection RCE writeup
 * (`T(java.lang.Runtime).getRuntime().exec(...)`,
 * `T(java.lang.ProcessBuilder)`, `T(java.lang.System)`) -- never a
 * general "any T(...) is suspicious" rule, which would flag entirely
 * ordinary, safe expressions like `T(java.lang.Math).PI`.
 */
object SpelDangerousTypeChecker {

    private val DANGEROUS_SIMPLE_OR_QUALIFIED_NAMES = setOf(
        "Runtime", "java.lang.Runtime",
        "ProcessBuilder", "java.lang.ProcessBuilder",
        "System", "java.lang.System",
        "Class", "java.lang.Class",
        "ClassLoader", "java.lang.ClassLoader",
    )

    /** The dangerous type name found (from a `T(...)` reference OR a `new X(...)` constructor call -- both let a hardcoded expression reach the same dangerous static/instance surface), or null if none of [DANGEROUS_SIMPLE_OR_QUALIFIED_NAMES] appears anywhere in the tree. */
    fun findDangerousTypeReference(node: SpelNode): String? {
        val ownTypeName = when (node) {
            is SpelTypeReference -> node.typeName
            is SpelConstructorCall -> node.typeName
            else -> null
        }
        if (ownTypeName != null && ownTypeName in DANGEROUS_SIMPLE_OR_QUALIFIED_NAMES) return ownTypeName

        for (child in childrenOf(node)) {
            findDangerousTypeReference(child)?.let { return it }
        }
        return null
    }

    private fun childrenOf(node: SpelNode): List<SpelNode> = when (node) {
        is SpelLiteral, is SpelVariableRef, is SpelTypeReference -> emptyList()
        is SpelPropertyAccess -> listOfNotNull(node.target)
        is SpelMethodCall -> listOfNotNull(node.target) + node.args
        is SpelIndexAccess -> listOf(node.target, node.index)
        is SpelConstructorCall -> node.args
        is SpelUnary -> listOf(node.operand)
        is SpelBinary -> listOf(node.left, node.right)
        is SpelGrouping -> listOf(node.inner)
    }
}
