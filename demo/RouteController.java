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
