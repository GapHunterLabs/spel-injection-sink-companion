package dev.gaphunter.spelinjectionsinkcompanion.spel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SpelParserTest {

    @Test
    fun `a simple property access chain parses without any dangerous node`() {
        val ast = SpelParser.parse("#root.user.name")!!
        assertNull(SpelDangerousTypeChecker.findDangerousTypeReference(ast))
        assertTrue(ast is SpelPropertyAccess)
    }

    @Test
    fun `a string literal concatenation parses as a binary chain`() {
        val ast = SpelParser.parse("'Hello, ' + name + '!'")!!
        assertTrue(ast is SpelBinary)
    }

    @Test
    fun `T(java lang Runtime) getRuntime exec is parsed as a type reference plus two method calls`() {
        val ast = SpelParser.parse("T(java.lang.Runtime).getRuntime().exec('calc')")!!
        assertTrue(ast is SpelMethodCall)
        val outer = ast as SpelMethodCall
        assertEquals("exec", outer.name)
        val inner = outer.target as SpelMethodCall
        assertEquals("getRuntime", inner.name)
        assertTrue(inner.target is SpelTypeReference)
        assertEquals("java.lang.Runtime", (inner.target as SpelTypeReference).typeName)
    }

    @Test
    fun `dangerous type checker finds Runtime anywhere in the tree`() {
        val ast = SpelParser.parse("T(java.lang.Runtime).getRuntime().exec('calc')")!!
        assertEquals("java.lang.Runtime", SpelDangerousTypeChecker.findDangerousTypeReference(ast))
    }

    @Test
    fun `dangerous type checker does not flag an ordinary safe type reference`() {
        val ast = SpelParser.parse("T(java.lang.Math).PI")!!
        assertNull(SpelDangerousTypeChecker.findDangerousTypeReference(ast))
    }

    @Test
    fun `a method call reachable through a binary operand is still found`() {
        val ast = SpelParser.parse("1 + T(java.lang.Runtime).getRuntime().exec('calc')")!!
        assertEquals("java.lang.Runtime", SpelDangerousTypeChecker.findDangerousTypeReference(ast))
    }

    @Test
    fun `new ProcessBuilder construction is parsed and flagged`() {
        val ast = SpelParser.parse("new ProcessBuilder('calc').start()")!!
        assertTrue(ast is SpelMethodCall)
        assertEquals("ProcessBuilder", SpelDangerousTypeChecker.findDangerousTypeReference(ast))
    }

    @Test
    fun `an unterminated string literal fails to parse`() {
        assertNull(SpelParser.parse("'unterminated"))
    }

    @Test
    fun `trailing garbage after a valid expression fails to parse`() {
        assertNull(SpelParser.parse("#root.name )"))
    }

    @Test
    fun `an unrecognized character fails to parse`() {
        assertNull(SpelParser.parse("#root.name @ 3"))
    }

    @Test
    fun `escaped single quote inside a string literal is handled`() {
        val ast = SpelParser.parse("'it''s ok'")!!
        assertEquals("it's ok", (ast as SpelLiteral).text)
    }

    @Test
    fun `indexed access parses`() {
        val ast = SpelParser.parse("#root.items[0]")!!
        assertTrue(ast is SpelIndexAccess)
    }
}
