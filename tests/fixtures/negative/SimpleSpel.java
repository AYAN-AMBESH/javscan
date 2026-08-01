package run.halo.fixture;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

/**
 * Negative fixture (JS105): the parsed expression is evaluated against a
 * SimpleEvaluationContext, which forbids `T(...)` type references and
 * constructor invocation — the primitives SpEL RCE depends on.
 */
public class SimpleSpel {

    private final SpelExpressionParser parser = new SpelExpressionParser();

    public Object evaluate(String expressionText, Object root) {
        Expression expression = parser.parseExpression(expressionText);
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        return expression.getValue(context, root);
    }
}
