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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.service.OtpService;
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
 * Pins the guess budget against a real Redis under a parallel burst. The cap only
 * holds if every guess is counted before it is compared and the spent counter is
 * not reset by the guess that trips it: otherwise callers that fetched the code
 * before the last allowed guess would each get a full comparison.
 */
@SpringBootTest
@Testcontainers
class OtpAttemptsConcurrencyTest {

    private static final String PHONE = "+12025550177";
    private static final String CODE_KEY = "otp:code:" + PHONE;
    private static final String ATTEMPTS_KEY = "otp:attempts:" + PHONE;
    private static final String INVALID_MESSAGE = "Invalid or expired verification code";
    private static final String EXHAUSTED_MESSAGE = "Too many incorrect verification codes; request a new code";

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
    OtpService otpService;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Autowired
    IdentityServiceProperties properties;

    @Autowired
    MeterRegistry metrics;

    @Test
    void parallelWrongGuessesAreComparedAtMostMaxTimesAndBurnTheCode() throws Exception {
        otpService.sendOtp(PHONE, null, null);
        String code = redisTemplate.opsForValue().get(CODE_KEY);
        assertThat(code).isNotBlank();
        String wrongCode = "000000".equals(code) ? "111111" : "000000";
        int max = properties.getOtp().getMaxVerifyAttempts();
        double invalidBefore = count("invalid");
        double exhaustedBefore = count("exhausted");
        double validBefore = count("valid");

        int threads = 32;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger invalidReplies = new AtomicInteger();
        AtomicInteger exhaustedReplies = new AtomicInteger();
        List<Throwable> unexpected = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    start.await();
                    otpService.verifyOtp(PHONE, wrongCode);
                    synchronized (unexpected) {
                        unexpected.add(new AssertionError("a wrong guess was accepted"));
                    }
                } catch (InvalidOtpException e) {
                    if (EXHAUSTED_MESSAGE.equals(e.getMessage())) {
                        exhaustedReplies.incrementAndGet();
                    } else if (INVALID_MESSAGE.equals(e.getMessage())) {
                        invalidReplies.incrementAndGet();
                    } else {
                        synchronized (unexpected) {
                            unexpected.add(e);
                        }
                    }
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
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(unexpected).as("no unexpected outcomes").isEmpty();
        assertThat(invalidReplies.get() + exhaustedReplies.get()).isEqualTo(threads);

        // Every caller that saw the code took one slot; the code is gone and the spent
        // counter outlives it, so nobody could start a fresh budget at 1.
        String countedValue = redisTemplate.opsForValue().get(ATTEMPTS_KEY);
        assertThat(countedValue).as("spent counter survives the burst").isNotNull();
        long counted = Long.parseLong(countedValue);
        assertThat(counted).isBetween((long) max, (long) threads);
        assertThat(redisTemplate.hasKey(CODE_KEY)).isFalse();
        assertThat(redisTemplate.getExpire(ATTEMPTS_KEY)).isPositive();

        // The callers that found the code already deleted were neither counted nor compared.
        long absent = threads - counted;

        // Slots 1..max-1 answer "invalid"; slot max and every slot past the cap answer
        // "exhausted", the latter without a comparison.
        assertThat(invalidReplies.get()).isEqualTo(max - 1 + absent);
        assertThat(exhaustedReplies.get()).isEqualTo(counted - max + 1);

        // The invalid series counts a compared mismatch and an absent code alike, so the
        // comparisons are what is left after the absent callers: exactly max of them.
        double compared = count("invalid") - invalidBefore - absent;
        assertThat(compared).as("comparisons against one code").isEqualTo(max);
        assertThat(count("exhausted") - exhaustedBefore).isEqualTo(counted - max + 1);
        assertThat(count("valid") - validBefore).isZero();

        // After the burst the right code is worthless and nothing more is counted.
        assertThatThrownBy(() -> otpService.verifyOtp(PHONE, code))
                .isInstanceOf(InvalidOtpException.class)
                .hasMessage(INVALID_MESSAGE);
        assertThat(redisTemplate.opsForValue().get(ATTEMPTS_KEY)).isEqualTo(countedValue);
        assertThat(count("valid") - validBefore).isZero();
    }

    private double count(String result) {
        Counter counter = metrics.find("gua.identity.otp.verify").tag("result", result).counter();
        return counter == null ? 0.0 : counter.count();
    }
}
