package ro.thedotin.springcloudgwdemo.config;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

@Component
public class AuthoritiesGatewayFilterFactory
        extends AbstractGatewayFilterFactory<AuthoritiesGatewayFilterFactory.Config> {

    private final SpelExpressionParser parser = new SpelExpressionParser();
    private final EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().withInstanceMethods().build();

    private final Map<String, UserDetails> dataSource;

    public AuthoritiesGatewayFilterFactory() {
        super(Config.class);
        this.dataSource = new HashMap<>();
        this.dataSource.put("valentin.raduti@mindit.io", new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return Set.of(() -> "ADMIN");
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return "valentin.raduti@mindit.io";
            }

            @Override
            public boolean isAccountNonExpired() {
                return true;
            }

            @Override
            public boolean isAccountNonLocked() {
                return true;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return true;
            }

            @Override
            public boolean isEnabled() {
                return true;
            }
        });
    }

    private boolean check(String securityExpression, Authentication jwt) {
        Expression expression = parser.parseExpression(securityExpression);
        return Optional.ofNullable(expression.getValue(context,
                new AccessValidation(this.dataSource.get(((JwtAuthenticationToken) jwt).getTokenAttributes().get("email"))), Boolean.class))
                .orElse(false);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) ->
                exchange.getPrincipal()
                        .flatMap(principal -> {
                            if (!check(config.getExpression(), (Authentication) principal)) {
                                throw new ResponseStatusException(HttpStatus.FORBIDDEN);
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
