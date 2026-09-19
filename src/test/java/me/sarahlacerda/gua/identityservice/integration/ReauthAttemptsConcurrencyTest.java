package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.exception.ReauthPhoneMismatchException;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Pins the budget of wrong numbers against a real Redis under a parallel burst. The account's
 * own number is what a stolen session guesses at, and the cap only bounds that guessing if the
 * attempt is reserved atomically before the number is compared: a read followed by a later
 * increment bounds a sequence of guesses and lets a burst of them all read the same value, all
 * pass the gate and all get compared.
 *
 * <p>
 * Needs Docker for Postgres and Redis, and is skipped where Docker is not available.
 */
@SpringBootTest
@Testcontainers(disabledWithoutDocker = true)
class ReauthAttemptsConcurrencyTest {

    private static final String USER = "@burst:example.com";
    private static final String MISMATCH_KEY = "reauth:phone-mismatch:" + USER;
    private static final String REQUESTER_IP = "203.0.113.9";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("identity")
            .withUsername("identity")
            .withPassword("identity");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379).toString());

        registry.add("identity.matrix.admin-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.client-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.matrix.user-localpart-prefix", () -> "gua");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");
        registry.add("oidc.issuer", () -> "http://localhost");
    }

    @Autowired
    AccountReauthService accountReauthService;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Autowired
    IdentityServiceProperties properties;

    @Test
    void parallelWrongNumbersAreComparedAtMostMaxTimes() throws Exception {
        redisTemplate.delete(MISMATCH_KEY);
        int max = properties.getSecurity().getMaxReauthPhoneAttemptsPerHour();

        int threads = 32;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger compared = new AtomicInteger();
        AtomicInteger refusedByTheCap = new AtomicInteger();
        List<Throwable> unexpected = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            // A different candidate number per thread, which is the shape of the attack: one
            // stolen session working through numbers to find the account's own.
            String candidate = String.format("+1202555%04d", 200 + i);
            executor.submit(() -> {
                try {
                    start.await();
                    accountReauthService.startReauth(USER, candidate, REQUESTER_IP, null);
                    synchronized (unexpected) {
                        unexpected.add(new AssertionError("a number that is not the account's was accepted"));
                    }
                } catch (ReauthPhoneMismatchException e) {
                    compared.incrementAndGet();
                } catch (RateLimiterException e) {
                    refusedByTheCap.incrementAndGet();
                } catch (Throwable t) {
                    synchronized (unexpected) {
                        unexpected.add(t);
                    }
                } finally {
                    done.countDown();
                }
            });
        }

        start.countDown();
        assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(unexpected).as("no unexpected outcomes").isEmpty();
        // Only the reservations inside the budget reached a comparison, however many arrived at
        // once. Everything past it was refused without the account being consulted at all.
        assertThat(compared.get()).as("numbers compared against the account").isEqualTo(max);
        assertThat(compared.get() + refusedByTheCap.get()).isEqualTo(threads);

        // Every attempt is counted, the refused ones included, and the window the in-budget ones
        // opened is still running, so the budget refills an hour after it opened and not later.
        assertThat(redisTemplate.opsForValue().get(MISMATCH_KEY)).isEqualTo(String.valueOf(threads));
        assertThat(redisTemplate.getExpire(MISMATCH_KEY)).isPositive();

        // And the cap is a cap on the account: once it is spent, the next number is refused
        // before anything is compared, whoever it belongs to.
        assertThatThrownBy(() -> accountReauthService.startReauth(USER, "+12025550123", REQUESTER_IP, null))
                .isInstanceOf(RateLimiterException.class)
                .hasMessageNotContaining(USER);
    }
}
