package ro.thedotin.springcloudgwdemo.config;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

@Component
public class AuthoritiesGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AuthoritiesGatewayFilterFactory.Config> {

    private static final SpelExpressionParser parser = new SpelExpressionParser();
    private static final MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
    private static Method triggerCheckMethod;

    static {
        try {
            triggerCheckMethod = SecurityObject.class.getMethod("triggerCheck");
        } catch (NoSuchMethodException e) {
        }
    }

    public AuthoritiesGatewayFilterFactory() {
        super(Config.class);
    }

    private static boolean check(String securityExpression, Authentication whatever) {
        EvaluationContext evaluationContext = expressionHandler.createEvaluationContext(whatever,
                new SimpleMethodInvocation(SecurityObject.class, triggerCheckMethod));
        return ExpressionUtils.evaluateAsBoolean(
                parser.parseExpression(securityExpression), evaluationContext);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) ->
                exchange.getPrincipal()
                        .flatMap(principal -> {
                                    if (!check(config.getExpression(), (Authentication) principal)) {
                                        throw new ResponseStatusException(HttpStatus.I_AM_A_TEAPOT);
                                    }
                                    return chain.filter(exchange);
                                }
                        );
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Collections.singletonList("expression");
    }

    @Override
    public Config newConfig() {
        return new Config();
    }

    private static class SecurityObject {
        public void triggerCheck() { /*NOP*/ }
    }

    public static class Config {
        private String expression;

        public String getExpression() {
            return expression;
        }

        public void setExpression(String expression) {
            this.expression = expression;
        }
    }
}
