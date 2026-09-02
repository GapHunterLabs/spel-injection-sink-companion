package dev.gaphunter.spelinjectionsinkcompanion.spel

/**
 * A hand-built AST for a real, useful subset of Spring Expression
 * Language -- the second full custom grammar in this catalog (after
 * `redos-catastrophic-backtracking-companion`'s regex grammar). No
 * operator-precedence structure ([SpelBinary] is a flat left-to-right
 * chain) -- this plugin never EVALUATES an expression, only asks
 * "does this tree contain a `T(...)` type reference", so precedence
 * between operands is irrelevant to that question.
 */
sealed class SpelNode

data class SpelLiteral(val text: String) : SpelNode()

/** `#name` (a SpEL variable, or `#root`/`#this`). */
data class SpelVariableRef(val name: String) : SpelNode()

/** `target.name`, or a bare `name` when [target] is null. */
data class SpelPropertyAccess(val target: SpelNode?, val name: String) : SpelNode()

/** `target.name(args)`, a bare `name(args)` when [target] is null, or `#name(args)` (SpEL function call) when [target] is null and the name came from a `#`. */
data class SpelMethodCall(val target: SpelNode?, val name: String, val args: List<SpelNode>) : SpelNode()

data class SpelIndexAccess(val target: SpelNode, val index: SpelNode) : SpelNode()

/** `T(java.lang.Runtime)` -- SpEL's real syntax for referencing a `java.lang.Class`, the concrete construct real SpEL-injection RCE payloads use to reach an arbitrary static method. */
data class SpelTypeReference(val typeName: String) : SpelNode()

data class SpelConstructorCall(val typeName: String, val args: List<SpelNode>) : SpelNode()

data class SpelUnary(val operator: String, val operand: SpelNode) : SpelNode()

data class SpelBinary(val left: SpelNode, val operator: String, val right: SpelNode) : SpelNode()

data class SpelGrouping(val inner: SpelNode) : SpelNode()
