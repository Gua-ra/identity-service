package me.sarahlacerda.gua.identityservice.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;

import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

/**
 * Pins the shipped {@code identity.rate-limits} rules of {@code application.yml} for
 * the endpoints that check a credential. Each must resolve to its own per-address
 * rule, never to {@code default-config}: 120 a minute is a throughput guard, not a
 * guess budget. Bound through the same binder the application uses, so a rule that
 * is dropped or misspelt in the YAML fails here instead of in production.
 */
class RateLimitConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(PropertiesOnly.class)
            .withPropertyValues(
                    "identity.matrix.admin-api-base-url=http://synapse:8008",
                    "identity.matrix.client-api-base-url=http://synapse:8008",
                    "identity.matrix.homeserver-domain=example.test",
                    "identity.matrix.admin-access-token=admin-token",
                    "identity.matrix.user-localpart-prefix=gua",
                    "identity.directory.pepper=pepper");

    @ParameterizedTest(name = "POST {0} allows {1} per {2} per address")
    @CsvSource({
            "/otp/verify, 10, PT1M",
            "/signin/verify-pin, 10, PT1M",
            "/login/otp, 10, PT1M",
            "/login/pin, 10, PT1M",
            "/login/passkey/auth/options, 20, PT1M",
            "/login/passkey/auth/verify, 20, PT1M",
            // Mints a WebAuthn challenge that can be spent as a step-up factor, so it needs
            // its own rule for the same reason the credential checks above do.
            "/security/passkey/stepup/options, 20, PT5M"
    })
    void credentialEndpointsHaveTheirOwnPerAddressRule(String path, int limit, Duration refresh) {
        runner.run(ctx -> {
            assertThat(ctx).hasNotFailed();
            EndpointRateLimiter limiter = new EndpointRateLimiter(ctx.getBean(IdentityServiceProperties.class));

            EndpointRateLimiter.ResolvedLimiter resolved = limiter.resolve(request("POST", path)).orElseThrow();

            assertThat(resolved.rateLimiter().getName()).startsWith("endpoint-");
            assertThat(resolved.rateLimiter().getRateLimiterConfig().getLimitForPeriod()).isEqualTo(limit);
            assertThat(resolved.refreshPeriod()).isEqualTo(refresh);
        });
    }

    @Test
    void unlistedPathsStillFallUnderTheDefaultRule() {
        runner.run(ctx -> {
            EndpointRateLimiter limiter = new EndpointRateLimiter(ctx.getBean(IdentityServiceProperties.class));

            EndpointRateLimiter.ResolvedLimiter resolved = limiter.resolve(request("GET", "/login/context")).orElseThrow();

            assertThat(resolved.rateLimiter().getName()).startsWith("default");
            assertThat(resolved.rateLimiter().getRateLimiterConfig().getLimitForPeriod()).isEqualTo(120);
        });
    }

    @Test
    void otpGuessBudgetDefaultsToFive() {
        runner.run(ctx -> assertThat(ctx.getBean(IdentityServiceProperties.class).getOtp().getMaxVerifyAttempts())
                .isEqualTo(5));
    }

    private static MockHttpServletRequest request(String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRemoteAddr("203.0.113.7");
        return request;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(IdentityServiceProperties.class)
    static class PropertiesOnly {
    }
}
