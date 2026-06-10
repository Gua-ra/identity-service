package me.sarahlacerda.gua.identityservice.web.ratelimit;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletRequest;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitConfig;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitRule;
import me.sarahlacerda.gua.identityservice.security.OidcAuthenticationToken;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import io.github.resilience4j.ratelimiter.RateLimiter;
import io.github.resilience4j.ratelimiter.RateLimiterConfig;
import io.github.resilience4j.ratelimiter.RateLimiterRegistry;

@Component
public class EndpointRateLimiter {

    private final boolean enabled;
    private final RateLimiterRegistry registry;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final List<Rule> rules;
    private final Rule defaultRule;

    public EndpointRateLimiter(IdentityServiceProperties properties) {
        RateLimitProperties rateLimitProps = properties.getRateLimits();
        this.enabled = rateLimitProps.isEnabled();
        this.registry = RateLimiterRegistry.ofDefaults();
        this.rules = new ArrayList<>();

        AtomicInteger counter = new AtomicInteger(0);
        for (RateLimitRule ruleProps : rateLimitProps.getEndpoints()) {
            Rule rule = new Rule(
                "endpoint-" + counter.incrementAndGet(),
                ruleProps.getPath(),
                ruleProps.getMethods(),
                buildRateLimiterConfig(ruleProps),
                ruleProps.getTimeoutDuration(),
                this.pathMatcher
            );
            rules.add(rule);
        }

        RateLimitConfig defaultConfigProps = rateLimitProps.getDefaultConfig();
        this.defaultRule = new Rule(
            "default",
            "**",
            Set.of(),
            buildRateLimiterConfig(defaultConfigProps),
            defaultConfigProps.getTimeoutDuration(),
            this.pathMatcher
        );
    }

    public Optional<ResolvedLimiter> resolve(HttpServletRequest request) {
        if (!enabled) {
            return Optional.empty();
        }

        HttpMethod httpMethod;
        try {
            httpMethod = HttpMethod.valueOf(request.getMethod());
        } catch (IllegalArgumentException ex) {
            httpMethod = HttpMethod.GET;
        }

        if (HttpMethod.OPTIONS.equals(httpMethod) || HttpMethod.TRACE.equals(httpMethod)) {
            return Optional.empty();
        }

        String path = request.getRequestURI();
        final HttpMethod methodForMatch = httpMethod;
        Rule matchedRule = rules.stream()
            .filter(rule -> rule.matches(path, methodForMatch))
            .findFirst()
            .orElse(defaultRule);

        if (matchedRule == null) {
            return Optional.empty();
        }

        String limiterName = buildLimiterName(matchedRule, request);
        RateLimiter rateLimiter = registry.rateLimiter(limiterName, matchedRule.config());
        return Optional.of(new ResolvedLimiter(rateLimiter, matchedRule.timeoutDuration(), matchedRule.config().getLimitRefreshPeriod()));
    }

    private RateLimiterConfig buildRateLimiterConfig(RateLimitConfig config) {
        return RateLimiterConfig.custom()
            .limitForPeriod(config.getLimitForPeriod())
            .limitRefreshPeriod(config.getRefreshPeriod())
            .timeoutDuration(config.getTimeoutDuration())
            .build();
    }

    private String buildLimiterName(Rule rule, HttpServletRequest request) {
        StringBuilder builder = new StringBuilder(rule.name());
        String userKey = resolveUserKey();
        if (StringUtils.hasText(userKey)) {
            builder.append(":user:").append(userKey);
        }
        String ip = request.getRemoteAddr();
        if (StringUtils.hasText(ip)) {
            builder.append(":ip:").append(ip);
        }
        builder.append(":path:").append(rule.path());
        return builder.toString();
    }

    private String resolveUserKey() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        if (authentication instanceof OidcAuthenticationToken oidcAuthentication) {
            Object principal = oidcAuthentication.getPrincipal();
            if (principal instanceof OidcAuthenticatedPrincipal oidcPrincipal) {
                return oidcPrincipal.userId();
            }
            return principal != null ? principal.toString() : null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof OidcAuthenticatedPrincipal oidcPrincipal) {
            return oidcPrincipal.userId();
        }
        return principal != null ? principal.toString() : null;
    }

    private record Rule(String name, String path, Set<HttpMethod> methods, RateLimiterConfig config, Duration timeoutDuration, AntPathMatcher matcher) {
        private boolean matches(String requestPath, HttpMethod method) {
            boolean methodMatches = methods == null || methods.isEmpty() || methods.contains(method);
            return methodMatches && matcher.match(path, requestPath);
        }
    }

    public record ResolvedLimiter(RateLimiter rateLimiter, Duration timeout, Duration refreshPeriod) { }
}
