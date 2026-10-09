package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.UnsupportedPhoneCountryException;

@Testcontainers
class SmsSendGuardTest {

    private static final String BR = "+5511999998888";
    private static final String CA = "+16042259911";
    private static final String US = "+12025550123";
    private static final String ADDRESS = "198.51.100.7";
    private static final String OTHER_ADDRESS = "203.0.113.9";

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;

    private StringRedisTemplate redisTemplate;
    private IdentityServiceProperties properties;
    private SimpleMeterRegistry metrics;
    private SmsSendGuard guard;

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(redis.getHost(), redis.getMappedPort(6379)));
        connectionFactory.afterPropertiesSet();
        connectionFactory.start();
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
        redisTemplate.execute((org.springframework.data.redis.core.RedisCallback<Void>) connection -> {
            connection.serverCommands().flushAll();
            return null;
        });
        properties = new IdentityServiceProperties();
        metrics = new SimpleMeterRegistry();
        guard = new SmsSendGuard(redisTemplate, properties, metrics);
    }

    // -------------------- ceilings --------------------

    @Test
    void theHourlyCeilingRefusesEveryNumberAndAddressUntilItsWindowEnds() throws InterruptedException {
        properties.getOtp().setMaxSendsPerHour(3);
        for (int i = 0; i < 3; i++) {
            guard.admit("+1604225990" + i, "198.51.100." + i);
        }

        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofMinutes(59))
                        .isLessThanOrEqualTo(Duration.ofHours(1)));
        assertThat(refusals(SmsSendGuard.Refusal.HOURLY_CEILING)).isEqualTo(1.0);
        // The refused send spent nothing of its own number's or address's budget.
        assertThat(redisTemplate.hasKey(SmsSendGuard.PHONE_KEY_PREFIX + BR)).isFalse();
        assertThat(redisTemplate.hasKey(SmsSendGuard.IP_KEY_PREFIX + OTHER_ADDRESS)).isFalse();
        assertThat(count(SmsSendGuard.HOURLY_KEY)).isEqualTo(3);
        assertThat(redisTemplate.getExpire(SmsSendGuard.HOURLY_KEY, TimeUnit.SECONDS)).isBetween(3500L, 3600L);

        endWindow(SmsSendGuard.HOURLY_KEY);

        assertThatCode(() -> guard.admit(BR, OTHER_ADDRESS)).doesNotThrowAnyException();
        assertThat(count(SmsSendGuard.HOURLY_KEY)).isEqualTo(1);
    }

    @Test
    void theDailyCeilingStillHoldsWhenTheHourlyWindowEnds() throws InterruptedException {
        properties.getOtp().setMaxSendsPerDay(2);
        guard.admit(CA, ADDRESS);
        guard.admit(US, OTHER_ADDRESS);

        endWindow(SmsSendGuard.HOURLY_KEY);

        assertThatThrownBy(() -> guard.admit(BR, "192.0.2.1"))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofHours(23)));
        assertThat(refusals(SmsSendGuard.Refusal.DAILY_CEILING)).isEqualTo(1.0);

        endWindow(SmsSendGuard.DAILY_KEY);

        assertThatCode(() -> guard.admit(BR, "192.0.2.1")).doesNotThrowAnyException();
    }

    @Test
    void theWaitIsTheLongestOfTheFullCounters() {
        properties.getOtp().setMaxSendsPerDay(1);
        properties.getOtp().setMaxRequestsPerPhonePerHour(1);
        guard.admit(BR, ADDRESS);

        // The number's hourly counter and the daily ceiling are both full: only the day reopens both.
        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofHours(23)));
        assertThat(refusals(SmsSendGuard.Refusal.DAILY_CEILING)).isEqualTo(1.0);
    }

    @Test
    void aCounterFoundWithoutAnExpiryIsGivenOne() {
        redisTemplate.opsForValue().set(SmsSendGuard.HOURLY_KEY, "0");

        guard.admit(BR, ADDRESS);

        assertThat(redisTemplate.getExpire(SmsSendGuard.HOURLY_KEY, TimeUnit.SECONDS)).isBetween(3500L, 3600L);
    }

    // -------------------- destinations --------------------

    @Test
    void aDisallowedCountryIsRefusedBeforeAnythingIsCounted() {
        // France, and Jamaica, which shares +1 with Canada and the US.
        for (String number : List.of("+33612345678", "+18765550123")) {
            assertThatThrownBy(() -> guard.admit(number, ADDRESS))
                    .isInstanceOf(UnsupportedPhoneCountryException.class);
        }

        assertThat(redisTemplate.keys("otp:*")).isEmpty();
        assertThat(refusals(SmsSendGuard.Refusal.COUNTRY)).isEqualTo(2.0);
    }

    @Test
    void theServedCountriesAreAdmittedByDefault() {
        guard.admit(BR, ADDRESS);
        guard.admit(CA, ADDRESS);
        guard.admit(US, ADDRESS);

        assertThat(count(SmsSendGuard.HOURLY_KEY)).isEqualTo(3);
        assertThat(count(SmsSendGuard.DAILY_KEY)).isEqualTo(3);
    }

    @Test
    void theAllowlistIsConfigurable() {
        properties.getOtp().setAllowedCountries(List.of(" fr", "BR "));
        guard = new SmsSendGuard(redisTemplate, properties, metrics);

        guard.admit("+33612345678", ADDRESS);
        assertThatThrownBy(() -> guard.admit(US, ADDRESS)).isInstanceOf(UnsupportedPhoneCountryException.class);
    }

    @Test
    void anUnknownRegionRefusesStartup() {
        properties.getOtp().setAllowedCountries(List.of("BR", "BRA"));

        assertThatThrownBy(() -> new SmsSendGuard(redisTemplate, properties, metrics))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("BRA");
    }

    @Test
    void anEmptyAllowlistRefusesStartup() {
        properties.getOtp().setAllowedCountries(List.of(" "));

        assertThatThrownBy(() -> new SmsSendGuard(redisTemplate, properties, metrics))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void anUnparseableNumberIsInvalid() {
        assertThatThrownBy(() -> guard.admit("not a number", ADDRESS)).isInstanceOf(InvalidPhoneNumberException.class);
        assertThat(redisTemplate.keys("otp:*")).isEmpty();
    }

    // -------------------- per address and per number --------------------

    @Test
    void anAddressRefusalLeavesTheNumbersBudgetIntact() {
        properties.getOtp().setMaxRequestsPerIpPerHour(2);
        guard.admit(CA, ADDRESS);
        guard.admit(US, ADDRESS);

        assertThatThrownBy(() -> guard.admit(BR, ADDRESS)).isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.IP)).isEqualTo(1.0);
        assertThat(redisTemplate.hasKey(SmsSendGuard.PHONE_KEY_PREFIX + BR)).isFalse();

        // The number still has its whole hourly budget from any other address.
        int perNumber = properties.getOtp().getMaxRequestsPerPhonePerHour();
        for (int i = 0; i < perNumber; i++) {
            guard.admit(BR, "192.0.2." + i);
        }
        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS)).isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.PHONE)).isEqualTo(1.0);
    }

    @Test
    void aSendWithoutAnAddressCountsTheNumberAndTheCeilingsOnly() {
        guard.admit(BR, null);

        assertThat(redisTemplate.keys("otp:rate:*")).containsExactlyInAnyOrder(
                SmsSendGuard.PHONE_KEY_PREFIX + BR, SmsSendGuard.HOURLY_KEY, SmsSendGuard.DAILY_KEY);
    }

    // -------------------- through the send path --------------------

    @Test
    void aDisallowedCountryNeverReachesTheProviderAndAnAllowedOneDoes() {
        SmsSender provider = Mockito.mock(SmsSender.class);
        OtpService otpService = otpService(provider);

        assertThatThrownBy(() -> otpService.sendOtp("+33612345678", ADDRESS, "fr"))
                .isInstanceOf(UnsupportedPhoneCountryException.class);
        Mockito.verifyNoInteractions(provider);

        otpService.sendOtp(BR, ADDRESS, "pt-BR");
        Mockito.verify(provider).send(Mockito.eq(BR), Mockito.anyString());
    }

    @Test
    void aSendRefusedByTheCeilingNeverReachesTheProvider() {
        properties.getOtp().setMaxSendsPerHour(1);
        SmsSender provider = Mockito.mock(SmsSender.class);
        OtpService otpService = otpService(provider);
        otpService.sendOtp(CA, ADDRESS, null);

        assertThatThrownBy(() -> otpService.sendOtp(US, OTHER_ADDRESS, null))
                .isInstanceOf(OtpRateLimitedException.class);
        Mockito.verify(provider, Mockito.never()).send(Mockito.eq(US), Mockito.anyString());
        assertThat(redisTemplate.hasKey("otp:code:" + US)).isFalse();
    }

    private OtpService otpService(SmsSender provider) {
        ReviewLogin reviewLogin = new ReviewLogin(ReviewLoginProperties.off(), new PhoneNumberNormalizer(),
                new PhoneNumberMasker(), metrics, Mockito.mock(DirectoryService.class),
                Mockito.mock(PhoneNumberHasher.class), duration -> {
                }, new BCryptPasswordEncoder());
        return new OtpService(redisTemplate, properties, new OtpCodeGenerator(), provider, guard, metrics,
                reviewLogin);
    }

    private void endWindow(String key) throws InterruptedException {
        redisTemplate.expire(key, Duration.ofMillis(1));
        for (int i = 0; i < 100 && Boolean.TRUE.equals(redisTemplate.hasKey(key)); i++) {
            Thread.sleep(10);
        }
        assertThat(redisTemplate.hasKey(key)).isFalse();
    }

    private long count(String key) {
        String value = redisTemplate.opsForValue().get(key);
        return value == null ? 0 : Long.parseLong(value);
    }

    private double refusals(SmsSendGuard.Refusal refusal) {
        Counter counter = metrics.find("gua.identity.sms.refused").tag("reason", refusal.tagValue()).counter();
        return counter == null ? 0.0 : counter.count();
    }
}
