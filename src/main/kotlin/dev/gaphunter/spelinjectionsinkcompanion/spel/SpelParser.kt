package dev.gaphunter.spelinjectionsinkcompanion.spel

/**
 * Recursive-descent parser over [SpelLexer]'s tokens, building a real
 * [SpelNode] tree. Deliberately flat on binary operators (no
 * precedence climbing) -- this plugin only ever asks "does this tree
 * contain a `T(...)` node", never evaluates the expression, so
 * precedence between operands doesn't change that answer.
 *
 * Every `parseXxx` function returns null (never a best-effort partial
 * tree) the instant something doesn't match the expected shape --
 * [parse] treats that, or any trailing unconsumed input, as
 * "unparseable", the same "never guess" discipline as this catalog's
 * other hand-rolled parsers (`RegexParser`, `HclJsonEncodeScanner`).
 */
class SpelParser private constructor(private val tokens: List<SpelToken>) {

    private var pos = 0

    companion object {
        fun parse(text: String): SpelNode? {
            val tokens = SpelLexer.tokenize(text) ?: return null
            val parser = SpelParser(tokens)
            val node = parser.parseExpression() ?: return null
            return if (parser.check(SpelTokenType.EOF)) node else null
        }
    }

    private fun peek(): SpelToken = tokens[pos]
    private fun advance(): SpelToken = tokens[pos++]
    private fun check(type: SpelTokenType): Boolean = peek().type == type
    private fun match(type: SpelTokenType): SpelToken? = if (check(type)) advance() else null

    private fun parseExpression(): SpelNode? {
        var left = parseUnary() ?: return null
        while (check(SpelTokenType.OP)) {
            val operator = advance().text
            val right = parseUnary() ?: return null
            left = SpelBinary(left, operator, right)
        }
        return left
    }

    private fun parseUnary(): SpelNode? {
        if (check(SpelTokenType.OP) && peek().text in UNARY_OPERATORS) {
            val operator = advance().text
            val operand = parseUnary() ?: return null
            return SpelUnary(operator, operand)
        }
        return parsePostfix()
    }

    private fun parsePostfix(): SpelNode? {
        var node = parsePrimary() ?: return null
        while (true) {
            node = when {
                check(SpelTokenType.DOT) -> {
                    advance()
                    val nameToken = match(SpelTokenType.IDENTIFIER) ?: return null
                    if (check(SpelTokenType.LPAREN)) {
                        SpelMethodCall(node, nameToken.text, parseArguments() ?: return null)
                    } else {
                        SpelPropertyAccess(node, nameToken.text)
                    }
                }
                check(SpelTokenType.LBRACKET) -> {
                    advance()
                    val index = parseExpression() ?: return null
                    if (match(SpelTokenType.RBRACKET) == null) return null
                    SpelIndexAccess(node, index)
                }
                check(SpelTokenType.LPAREN) && node is SpelVariableRef -> {
                    SpelMethodCall(null, node.name, parseArguments() ?: return null)
                }
                else -> return node
            }
        }
    }

    private fun parseArguments(): List<SpelNode>? {
        if (match(SpelTokenType.LPAREN) == null) return null
        val args = mutableListOf<SpelNode>()
        if (!check(SpelTokenType.RPAREN)) {
            while (true) {
                args += parseExpression() ?: return null
                if (match(SpelTokenType.COMMA) != null) continue
                break
            }
        }
        if (match(SpelTokenType.RPAREN) == null) return null
        return args
    }

    private fun parsePrimary(): SpelNode? {
        val token = peek()
        return when {
            token.type == SpelTokenType.STRING -> { advance(); SpelLiteral(token.text) }
            token.type == SpelTokenType.NUMBER -> { advance(); SpelLiteral(token.text) }
            token.isKeyword("true") || token.isKeyword("false") || token.isKeyword("null") -> { advance(); SpelLiteral(token.text) }
            token.isKeyword("T") && tokens.getOrNull(pos + 1)?.type == SpelTokenType.LPAREN -> {
                advance(); advance() // consume `T` and `(`
                val typeName = parseTypeName() ?: return null
                if (match(SpelTokenType.RPAREN) == null) return null
                SpelTypeReference(typeName)
            }
            token.isKeyword("new") -> {
                advance()
                val typeName = parseTypeName() ?: return null
                SpelConstructorCall(typeName, parseArguments() ?: return null)
            }
            token.type == SpelTokenType.LPAREN -> {
                advance()
                val inner = parseExpression() ?: return null
                if (match(SpelTokenType.RPAREN) == null) return null
                SpelGrouping(inner)
            }
            token.type == SpelTokenType.HASH -> {
                advance()
                val nameToken = match(SpelTokenType.IDENTIFIER) ?: return null
                SpelVariableRef(nameToken.text)
            }
            token.type == SpelTokenType.IDENTIFIER -> {
                advance()
                if (check(SpelTokenType.LPAREN)) {
                    SpelMethodCall(null, token.text, parseArguments() ?: return null)
                } else {
                    SpelPropertyAccess(null, token.text)
                }
            }
            else -> null
        }
    }

    /** A dotted type name (`java.lang.Runtime`) -- raw text only, never resolved against the real classpath (no PSI dependency inside this grammar). */
    private fun parseTypeName(): String? {
        val sb = StringBuilder()
        sb.append(match(SpelTokenType.IDENTIFIER)?.text ?: return null)
        while (check(SpelTokenType.DOT)) {
            advance()
            sb.append('.').append(match(SpelTokenType.IDENTIFIER)?.text ?: return null)
        }
        return sb.toString()
    }

    private fun SpelToken.isKeyword(text: String): Boolean = type == SpelTokenType.IDENTIFIER && this.text == text

    private val UNARY_OPERATORS = setOf("-", "+", "!")
}
