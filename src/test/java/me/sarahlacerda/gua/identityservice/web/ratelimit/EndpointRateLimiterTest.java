package me.sarahlacerda.gua.identityservice.web.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitConfig;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitRule;
import me.sarahlacerda.gua.identityservice.security.MatrixAuthentication;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;

import io.github.resilience4j.ratelimiter.RateLimiter;

class EndpointRateLimiterTest {

    private EndpointRateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        RateLimitProperties rateLimitProperties = properties.getRateLimits();
        rateLimitProperties.setEnabled(true);

        RateLimitRule otpSendRule = new IdentityServiceProperties.RateLimitRule();
        otpSendRule.setPath("/otp/send");
        otpSendRule.setMethods(Set.of(HttpMethod.POST));
        otpSendRule.setLimitForPeriod(3);
        otpSendRule.setRefreshPeriod(Duration.ofSeconds(30));
        otpSendRule.setTimeoutDuration(Duration.ofSeconds(1));

        RateLimitRule directoryRule = new IdentityServiceProperties.RateLimitRule();
        directoryRule.setPath("/directory/**");
        directoryRule.setMethods(Set.of(HttpMethod.POST));
        directoryRule.setLimitForPeriod(10);
        directoryRule.setRefreshPeriod(Duration.ofMinutes(5));
        directoryRule.setTimeoutDuration(Duration.ZERO);

        rateLimitProperties.getEndpoints().add(otpSendRule);
        rateLimitProperties.getEndpoints().add(directoryRule);

        RateLimitConfig defaultConfig = rateLimitProperties.getDefaultConfig();
        defaultConfig.setLimitForPeriod(50);
        defaultConfig.setRefreshPeriod(Duration.ofMinutes(1));
        defaultConfig.setTimeoutDuration(Duration.ofSeconds(1));

        rateLimiter = new EndpointRateLimiter(properties);
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void resolveShouldMatchSpecificRuleAndEmbedIdentity() {
        SecurityContextHolder.getContext().setAuthentication(new MatrixAuthentication("@alice:gua.local", "token"));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/otp/send");
        request.setRemoteAddr("192.168.1.10");

        Optional<EndpointRateLimiter.ResolvedLimiter> limiterOptional = rateLimiter.resolve(request);

        assertThat(limiterOptional).isPresent();
        EndpointRateLimiter.ResolvedLimiter limiter = limiterOptional.get();

        RateLimiter backingLimiter = limiter.rateLimiter();
        assertThat(backingLimiter.getName()).contains("endpoint-1");
        assertThat(backingLimiter.getName()).contains("@alice:gua.local");
        assertThat(backingLimiter.getName()).contains("192.168.1.10");
        assertThat(limiter.refreshPeriod()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void resolveShouldFallbackToDefaultWhenNoSpecificRuleMatches() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/health");
        request.setRemoteAddr("127.0.0.1");

        Optional<EndpointRateLimiter.ResolvedLimiter> limiter = rateLimiter.resolve(request);

        assertThat(limiter).isPresent();
        assertThat(limiter.get().rateLimiter().getName()).startsWith("default");
        assertThat(limiter.get().refreshPeriod()).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void resolveShouldReturnEmptyWhenGloballyDisabled() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getRateLimits().setEnabled(false);
        EndpointRateLimiter disabled = new EndpointRateLimiter(properties);

        HttpServletRequest request = new MockHttpServletRequest("POST", "/otp/send");
        assertThat(disabled.resolve(request)).isEmpty();
    }
}
