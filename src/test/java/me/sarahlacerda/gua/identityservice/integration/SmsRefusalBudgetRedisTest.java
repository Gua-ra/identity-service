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
import me.sarahlacerda.gua.identityservice.exception.SmsUnavailableException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpCodeGenerator;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.ReviewLogin;
import me.sarahlacerda.gua.identityservice.service.SmsSendGuard;
import me.sarahlacerda.gua.identityservice.service.SmsSender;
import me.sarahlacerda.gua.identityservice.service.security.PhoneChangeOtpService;

/**
 * Pins against a real Redis that a send the provider refused spends none of the send limits or
 * ceilings, and that any other outcome keeps every counter the send charged.
 */
@Testcontainers
class SmsRefusalBudgetRedisTest {

    private static final String PHONE = "+46701740605";
    private static final String IP = "198.51.100.7";
    private static final String PHONE_KEY = "otp:rate:phone:" + PHONE;
    private static final String IP_KEY = "otp:rate:ip:" + IP;
    private static final String CODE_KEY = "otp:code:" + PHONE;
    private static final String SIGN_UP_HOURLY_KEY = "otp:rate:sign-up:hour";
    private static final String SIGN_UP_DAILY_KEY = "otp:rate:sign-up:day";
    private static final String ACCOUNT_HOURLY_KEY = "otp:rate:account:hour";
    private static final String ACCOUNT_DAILY_KEY = "otp:rate:account:day";

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redisTemplate;

    private final AtomicReference<RuntimeException> providerFailure = new AtomicReference<>();
    private IdentityServiceProperties properties;
    private RateLimiter rateLimiter;
    private OtpService otpService;
    private PhoneChangeOtpService phoneChangeOtpService;

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
        SmsSendGuard sendGuard = new SmsSendGuard(redisTemplate, properties, metrics,
                Mockito.mock(DirectoryService.class), Mockito.mock(PhoneNumberHasher.class), rateLimiter,
                new PhoneNumberMasker());
        SmsSender provider = (to, body) -> {
            RuntimeException failure = providerFailure.get();
            if (failure != null) {
                throw failure;
            }
        };
        otpService = new OtpService(redisTemplate, properties, new OtpCodeGenerator(), provider, sendGuard, metrics,
                reviewLogin);
        phoneChangeOtpService = new PhoneChangeOtpService(redisTemplate, properties, new OtpCodeGenerator(),
                provider, sendGuard, metrics);
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
    void refusedSendsGiveBackTheSignUpCeilings() {
        properties.getOtp().setMaxSignUpSendsPerHour(2);
        properties.getOtp().setMaxSignUpSendsPerDay(2);
        providerFailure.set(new SmsRefusedException(SmsRefusedException.Reason.DESTINATION_UNAVAILABLE));

        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> otpService.sendOtp(PHONE, IP, null)).isInstanceOf(SmsRefusedException.class);
        }

        assertThat(redisTemplate.opsForValue().get(SIGN_UP_HOURLY_KEY)).isEqualTo("0");
        assertThat(redisTemplate.opsForValue().get(SIGN_UP_DAILY_KEY)).isEqualTo("0");
        assertThat(redisTemplate.getExpire(SIGN_UP_DAILY_KEY)).isGreaterThan(Duration.ofHours(23).toSeconds());

        // Both ceiling slots are still there once the destination is reachable, and no more.
        providerFailure.set(null);
        otpService.sendOtp(PHONE, IP, null);
        otpService.sendOtp("+46701740606", "198.51.100.8", null);
        assertThatThrownBy(() -> otpService.sendOtp("+46701740607", "198.51.100.9", null))
                .isInstanceOf(OtpRateLimitedException.class);
    }

    @Test
    void refusedAccountSendsGiveBackTheAccountCeilings() {
        properties.getOtp().setMaxAccountSendsPerHour(1);
        properties.getOtp().setMaxAccountSendsPerDay(1);
        providerFailure.set(new SmsRefusedException(SmsRefusedException.Reason.RECIPIENT_OPTED_OUT));

        assertThatThrownBy(() -> otpService.sendAccountOtp(PHONE, IP, null)).isInstanceOf(SmsRefusedException.class);
        assertThatThrownBy(() -> phoneChangeOtpService.send("chal-1", PHONE, IP, null))
                .isInstanceOf(SmsRefusedException.class);

        assertThat(redisTemplate.opsForValue().get(ACCOUNT_HOURLY_KEY)).isEqualTo("0");
        assertThat(redisTemplate.opsForValue().get(ACCOUNT_DAILY_KEY)).isEqualTo("0");
        assertThat(redisTemplate.opsForValue().get(PHONE_KEY)).isEqualTo("0");
        assertThat(redisTemplate.hasKey("otp:code:change:chal-1")).isFalse();

        providerFailure.set(null);
        phoneChangeOtpService.send("chal-2", PHONE, IP, null);
        assertThatThrownBy(() -> otpService.sendAccountOtp(PHONE, IP, null))
                .isInstanceOf(OtpRateLimitedException.class);
    }

    @Test
    void aDeliveredSendKeepsEveryCounterItCharged() {
        properties.getOtp().setMaxSignUpSendsPerHour(5);
        properties.getOtp().setMaxSignUpSendsPerDay(5);

        otpService.sendOtp(PHONE, IP, null);

        for (String key : new String[] { PHONE_KEY, IP_KEY, SIGN_UP_HOURLY_KEY, SIGN_UP_DAILY_KEY }) {
            assertThat(redisTemplate.opsForValue().get(key)).as(key).isEqualTo("1");
        }
        assertThat(redisTemplate.hasKey(CODE_KEY)).isTrue();
    }

    @Test
    void aProviderFailureKeepsEveryCounterItCharged() {
        properties.getOtp().setMaxAccountSendsPerHour(5);
        properties.getOtp().setMaxAccountSendsPerDay(5);
        providerFailure.set(new SmsUnavailableException("SMS provider unavailable"));

        assertThatThrownBy(() -> otpService.sendAccountOtp(PHONE, IP, null))
                .isInstanceOf(SmsUnavailableException.class);

        for (String key : new String[] { PHONE_KEY, IP_KEY, ACCOUNT_HOURLY_KEY, ACCOUNT_DAILY_KEY }) {
            assertThat(redisTemplate.opsForValue().get(key)).as(key).isEqualTo("1");
        }
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
