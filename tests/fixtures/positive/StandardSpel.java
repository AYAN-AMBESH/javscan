package run.halo.fixture;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Positive fixture (JS105): a request parameter parsed as SpEL and evaluated
 * against a StandardEvaluationContext — full RCE. JS501/JS105 must fire at
 * full severity with a NETWORK source.
 */
public class StandardSpel {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/eval")
    public Object evaluate(@RequestParam String expr) {
        Expression expression = parser.parseExpression(expr);
        StandardEvaluationContext context = new StandardEvaluationContext();
        return expression.getValue(context);
    }
}
