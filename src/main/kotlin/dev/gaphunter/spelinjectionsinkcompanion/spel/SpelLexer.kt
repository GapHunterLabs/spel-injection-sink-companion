package dev.gaphunter.spelinjectionsinkcompanion.spel

enum class SpelTokenType { IDENTIFIER, NUMBER, STRING, DOT, LPAREN, RPAREN, LBRACKET, RBRACKET, COMMA, HASH, OP, EOF }

data class SpelToken(val type: SpelTokenType, val text: String)

/**
 * Hand-rolled tokenizer for the SpEL subset [dev.gaphunter.spelinjectionsinkcompanion.spel.SpelParser]
 * consumes -- no `java.util.regex` dependency internally, same
 * "second custom grammar" discipline as this catalog's ReDoS plugin's
 * own regex grammar not depending on the platform's regex engine
 * either.
 *
 * Returns null (never a partial/best-effort token list) the moment an
 * unrecognized character or an unterminated string literal is hit --
 * the parser treats that as "this text can't be confidently analyzed
 * as SpEL", never a guess.
 */
object SpelLexer {

    private val OPERATOR_CHARS = "+-*/%<>=!&|?:^".toSet()

    fun tokenize(input: String): List<SpelToken>? {
        val tokens = mutableListOf<SpelToken>()
        var i = 0
        while (i < input.length) {
            val c = input[i]
            when {
                c.isWhitespace() -> i++
                c == '.' -> { tokens += SpelToken(SpelTokenType.DOT, "."); i++ }
                c == '(' -> { tokens += SpelToken(SpelTokenType.LPAREN, "("); i++ }
                c == ')' -> { tokens += SpelToken(SpelTokenType.RPAREN, ")"); i++ }
                c == '[' -> { tokens += SpelToken(SpelTokenType.LBRACKET, "["); i++ }
                c == ']' -> { tokens += SpelToken(SpelTokenType.RBRACKET, "]"); i++ }
                c == ',' -> { tokens += SpelToken(SpelTokenType.COMMA, ","); i++ }
                c == '#' -> { tokens += SpelToken(SpelTokenType.HASH, "#"); i++ }
                c == '\'' -> {
                    val result = readStringLiteral(input, i) ?: return null
                    tokens += SpelToken(SpelTokenType.STRING, result.first)
                    i = result.second
                }
                c.isDigit() -> {
                    val end = scanNumber(input, i)
                    tokens += SpelToken(SpelTokenType.NUMBER, input.substring(i, end))
                    i = end
                }
                c.isLetter() || c == '_' -> {
                    val start = i
                    while (i < input.length && (input[i].isLetterOrDigit() || input[i] == '_')) i++
                    tokens += SpelToken(SpelTokenType.IDENTIFIER, input.substring(start, i))
                }
                c in OPERATOR_CHARS -> { tokens += SpelToken(SpelTokenType.OP, c.toString()); i++ }
                else -> return null
            }
        }
        tokens += SpelToken(SpelTokenType.EOF, "")
        return tokens
    }

    /** SpEL strings are single-quoted, with `''` as an escaped single quote (no backslash escapes). Returns the unescaped text and the index right after the closing quote, or null if never closed. */
    private fun readStringLiteral(input: String, openIndex: Int): Pair<String, Int>? {
        var i = openIndex + 1
        val sb = StringBuilder()
        while (i < input.length) {
            if (input[i] == '\'') {
                if (i + 1 < input.length && input[i + 1] == '\'') {
                    sb.append('\'')
                    i += 2
                    continue
                }
                return sb.toString() to (i + 1)
            }
            sb.append(input[i])
            i++
        }
        return null
    }

    private fun scanNumber(input: String, start: Int): Int {
        var i = start
        while (i < input.length && input[i].isDigit()) i++
        if (i < input.length && input[i] == '.' && i + 1 < input.length && input[i + 1].isDigit()) {
            i++
            while (i < input.length && input[i].isDigit()) i++
        }
        if (i < input.length && (input[i] == 'e' || input[i] == 'E')) {
            val expStart = i
            var j = i + 1
            if (j < input.length && (input[j] == '+' || input[j] == '-')) j++
            if (j < input.length && input[j].isDigit()) {
                while (j < input.length && input[j].isDigit()) j++
                i = j
            } else {
                i = expStart // not really an exponent (e.g. a bare trailing 'e') -- back off, let it lex separately
            }
        }
        if (i < input.length && input[i] in "LlDdFf") i++
        return i
    }
}
