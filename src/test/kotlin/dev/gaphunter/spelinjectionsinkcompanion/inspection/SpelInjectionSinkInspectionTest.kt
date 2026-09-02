package dev.gaphunter.spelinjectionsinkcompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class SpelInjectionSinkInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(SpelInjectionSinkInspection::class.java)
    }

    fun `test a request parameter passed directly to parseExpression is flagged as tainted`() {
        myFixture.configureByText(
            "RouteController.java",
            """
            import org.springframework.expression.ExpressionParser;
            import org.springframework.expression.spel.standard.SpelExpressionParser;
            import org.springframework.web.bind.annotation.GetMapping;

            class RouteController {
                @GetMapping("/route")
                Object route(String routingExpression) {
                    ExpressionParser parser = new SpelExpressionParser();
                    return parser.parseExpression(routingExpression).getValue();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CVE-2022-22963") == true })
    }

    fun `test a request parameter reaching parseExpression via concatenation is flagged as tainted`() {
        myFixture.configureByText(
            "GreetController.java",
            """
            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.expression.spel.standard.SpelExpressionParser;

            class GreetController {
                @GetMapping("/greet")
                Object greet(String name) {
                    return new SpelExpressionParser().parseExpression("'Hello, ' + " + name).getValue();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("CVE-2022-22963") == true })
    }

    fun `test a hardcoded expression referencing T Runtime is flagged as a dangerous type`() {
        myFixture.configureByText(
            "Backdoor.java",
            """
            import org.springframework.expression.spel.standard.SpelExpressionParser;

            class Backdoor {
                Object run() {
                    SpelExpressionParser parser = new SpelExpressionParser();
                    return parser.parseExpression("T(java.lang.Runtime).getRuntime().exec('calc')").getValue();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("T(java.lang.Runtime)") == true })
    }

    fun `test a hardcoded ordinary property expression is never flagged`() {
        myFixture.configureByText(
            "Safe.java",
            """
            import org.springframework.expression.spel.standard.SpelExpressionParser;

            class Safe {
                Object run() {
                    SpelExpressionParser parser = new SpelExpressionParser();
                    return parser.parseExpression("name.length()").getValue();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("SpEL") == true })
    }

    fun `test a non-ExpressionParser type with a coincidentally named method is not flagged`() {
        myFixture.configureByText(
            "OtherParser.java",
            """
            import org.springframework.web.bind.annotation.GetMapping;

            class MyOwnParser {
                Object parseExpression(String s) { return s; }
            }

            class OtherParser {
                @GetMapping("/x")
                Object handle(String expr) {
                    MyOwnParser parser = new MyOwnParser();
                    return parser.parseExpression(expr);
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("SpEL") == true })
    }

    fun `test a non-endpoint method with an unrelated parameter is not flagged`() {
        myFixture.configureByText(
            "Helper.java",
            """
            import org.springframework.expression.spel.standard.SpelExpressionParser;

            class Helper {
                Object run(String unrelated) {
                    SpelExpressionParser parser = new SpelExpressionParser();
                    return parser.parseExpression(unrelated).getValue();
                }
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("SpEL") == true })
    }
}
