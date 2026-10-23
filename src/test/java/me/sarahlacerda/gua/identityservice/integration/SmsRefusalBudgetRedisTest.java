package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.ReviewLogin;

/** Pins against a real Redis that a send the provider refused spends none of the send limits. */
@Testcontainers
class SmsRefusalBudgetRedisTest {

    private static final String PHONE = "+46701740605";
    private static final String IP = "198.51.100.7";
    private static final String PHONE_KEY = "otp:rate:phone:" + PHONE;
    private static final String IP_KEY = "otp:rate:ip:" + IP;
    private static final String CODE_KEY = "otp:code:" + PHONE;

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redisTemplate;

    private final AtomicReference<RuntimeException> providerFailure = new AtomicReference<>();
    private IdentityServiceProperties properties;
    private RateLimiter rateLimiter;
    private OtpService otpService;

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(redis.getHost(), redis.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(connectionFactory);
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        redisTemplate.execute(connection -> {
            connection.serverCommands().flushAll();
            return null;
        }, true);
        properties = new IdentityServiceProperties();
        SimpleMeterRegistry metrics = new SimpleMeterRegistry();
        ReviewLogin reviewLogin = Mockito.mock(ReviewLogin.class);
        rateLimiter = new RateLimiter(redisTemplate);
        otpService = new OtpService(redisTemplate, properties, new OtpCodeGenerator(), (to, body) -> {
            RuntimeException failure = providerFailure.get();
            if (failure != null) {
                throw failure;
            }
        }, rateLimiter, metrics, reviewLogin);
    }

    @Test
    void refusedSendsNeverReachTheLimitsAndLeaveNoCode() {
        providerFailure.set(new SmsRefusedException(SmsRefusedException.Reason.DESTINATION_UNAVAILABLE));
        int attempts = properties.getOtp().getMaxRequestsPerIpPerHour() + 3;

        for (int i = 0; i < attempts; i++) {
            assertThatThrownBy(() -> otpService.sendOtp(PHONE, IP, null)).isInstanceOf(SmsRefusedException.class);
        }

        assertThat(redisTemplate.opsForValue().get(PHONE_KEY)).isEqualTo("0");
        assertThat(redisTemplate.opsForValue().get(IP_KEY)).isEqualTo("0");
        assertThat(redisTemplate.hasKey(CODE_KEY)).isFalse();

        // Once the destination is reachable the whole budget is still there, and no more.
        providerFailure.set(null);
        for (int i = 0; i < properties.getOtp().getMaxRequestsPerPhonePerHour(); i++) {
            otpService.sendOtp(PHONE, IP, null);
        }
        assertThat(redisTemplate.hasKey(CODE_KEY)).isTrue();
        assertThatThrownBy(() -> otpService.sendOtp(PHONE, IP, null)).isInstanceOf(OtpRateLimitedException.class);
    }

    @Test
    void refundKeepsTheWindow() {
        rateLimiter.checkRate(PHONE_KEY, 5, Duration.ofHours(1));
        rateLimiter.checkRate(PHONE_KEY, 5, Duration.ofHours(1));

        rateLimiter.refund(PHONE_KEY);

        assertThat(redisTemplate.opsForValue().get(PHONE_KEY)).isEqualTo("1");
        assertThat(redisTemplate.getExpire(PHONE_KEY)).isPositive();
    }

    @Test
    void refundNeverCreatesACounterOrTakesOneBelowZero() {
        rateLimiter.refund(PHONE_KEY);
        assertThat(redisTemplate.hasKey(PHONE_KEY)).isFalse();

        rateLimiter.checkRate(PHONE_KEY, 5, Duration.ofHours(1));
        rateLimiter.refund(PHONE_KEY);
        rateLimiter.refund(PHONE_KEY);
        assertThat(redisTemplate.opsForValue().get(PHONE_KEY)).isEqualTo("0");
    }
}
