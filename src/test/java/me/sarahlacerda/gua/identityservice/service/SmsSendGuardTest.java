package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataAccessException;
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
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.OtpProperties;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.SmsRefusedException;
import me.sarahlacerda.gua.identityservice.exception.UnsupportedPhoneCountryException;

@Testcontainers
class SmsSendGuardTest {

    private static final String BR = "+5511999998888";
    private static final String CA = "+16042259911";
    private static final String US = "+12025550123";
    private static final List<String> SERVED = List.of("BR", "CA", "US");
    private static final String ADDRESS = "198.51.100.7";
    private static final String OTHER_ADDRESS = "203.0.113.9";

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;

    private StringRedisTemplate redisTemplate;
    private IdentityServiceProperties properties;
    private SimpleMeterRegistry metrics;
    private DirectoryService directoryService;
    private PhoneNumberHasher phoneNumberHasher;
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
        configureCeilings(properties.getOtp());
        metrics = new SimpleMeterRegistry();
        directoryService = Mockito.mock(DirectoryService.class);
        phoneNumberHasher = Mockito.mock(PhoneNumberHasher.class);
        Mockito.when(phoneNumberHasher.digest(Mockito.anyString()))
                .thenAnswer(invocation -> "digest:" + invocation.getArgument(0));
        Mockito.when(directoryService.findByDigest(Mockito.anyString())).thenReturn(Optional.empty());
        guard = newGuard();
    }

    // -------------------- ceilings --------------------

    @Test
    void noCeilingIsCountedOrCheckedByDefault() {
        properties = new IdentityServiceProperties();
        guard = newGuard();
        hasAccount(BR);

        for (int i = 0; i < 70; i++) {
            guard.admit(String.format("+160422599%02d", i), "198.51.100." + i);
            guard.admitForAccount(BR, "192.0.2." + (i / 5));
            redisTemplate.delete(SmsSendGuard.PHONE_KEY_PREFIX + BR);
        }

        assertThat(redisTemplate.keys("otp:rate:sign-up:*")).isEmpty();
        assertThat(redisTemplate.keys("otp:rate:account:*")).isEmpty();
    }

    @Test
    void theShippedConfigurationSetsNoCeilingAndNoLookupBudget() throws IOException {
        // application.yml with every IDENTITY_OTP_MAX_*_SENDS_* and the lookup budget unset.
        Binder binder = shippedConfiguration();
        OtpProperties otp = binder.bind("identity.otp", OtpProperties.class).get();
        IdentityServiceProperties.DirectoryProperties directory = binder
                .bind("identity.directory", IdentityServiceProperties.DirectoryProperties.class).get();

        assertThat(List.of(otp.getMaxSignUpSendsPerHour(), otp.getMaxSignUpSendsPerDay(),
                otp.getMaxAccountSendsPerHour(), otp.getMaxAccountSendsPerDay(),
                directory.getMaxLookupsPerAccountPerHour())).containsOnly(0);
        assertThat(otp.getMaxRequestsPerPhonePerHour()).isEqualTo(5);
        assertThat(otp.getMaxRequestsPerPhonePerDay()).isZero();
        assertThat(otp.getMaxRequestsPerIpPerHour()).isEqualTo(10);
    }

    @Test
    void theHourlyCeilingRefusesEveryNumberAndAddressUntilItsWindowEnds() throws InterruptedException {
        properties.getOtp().setMaxSignUpSendsPerHour(3);
        for (int i = 0; i < 3; i++) {
            guard.admit("+1604225990" + i, "198.51.100." + i);
        }

        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofMinutes(59))
                        .isLessThanOrEqualTo(Duration.ofHours(1)));
        assertThat(refusals(SmsSendGuard.Refusal.SIGN_UP_HOURLY_CEILING)).isEqualTo(1.0);
        // The refused send spent nothing of its own number's or address's budget.
        assertThat(redisTemplate.hasKey(SmsSendGuard.PHONE_KEY_PREFIX + BR)).isFalse();
        assertThat(redisTemplate.hasKey(SmsSendGuard.IP_KEY_PREFIX + OTHER_ADDRESS)).isFalse();
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(3);
        assertThat(redisTemplate.getExpire(SmsSendGuard.SIGN_UP_HOURLY_KEY, TimeUnit.SECONDS))
                .isBetween(3500L, 3600L);

        endWindow(SmsSendGuard.SIGN_UP_HOURLY_KEY);

        assertThatCode(() -> guard.admit(BR, OTHER_ADDRESS)).doesNotThrowAnyException();
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(1);
    }

    @Test
    void theDailyCeilingStillHoldsWhenTheHourlyWindowEnds() throws InterruptedException {
        properties.getOtp().setMaxSignUpSendsPerDay(2);
        guard.admit(CA, ADDRESS);
        guard.admit(US, OTHER_ADDRESS);

        endWindow(SmsSendGuard.SIGN_UP_HOURLY_KEY);

        assertThatThrownBy(() -> guard.admit(BR, "192.0.2.1"))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofHours(23)));
        assertThat(refusals(SmsSendGuard.Refusal.SIGN_UP_DAILY_CEILING)).isEqualTo(1.0);

        endWindow(SmsSendGuard.SIGN_UP_DAILY_KEY);

        assertThatCode(() -> guard.admit(BR, "192.0.2.1")).doesNotThrowAnyException();
    }

    @Test
    void theWaitIsTheLongestOfTheFullCounters() {
        properties.getOtp().setMaxSignUpSendsPerDay(1);
        properties.getOtp().setMaxRequestsPerPhonePerHour(1);
        guard.admit(BR, ADDRESS);

        // The number's hourly counter and the daily ceiling are both full: only the day reopens both.
        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofHours(23)));
        assertThat(refusals(SmsSendGuard.Refusal.SIGN_UP_DAILY_CEILING)).isEqualTo(1.0);
    }

    @Test
    void parallelSendsNeverOvershootACeiling() throws Exception {
        properties.getOtp().setMaxSignUpSendsPerHour(10);
        int senders = 48;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < senders; i++) {
                String number = String.format("+160422599%02d", i);
                String address = "198.51.100." + i;
                Callable<Boolean> send = () -> {
                    start.await();
                    try {
                        guard.admit(number, address);
                        return true;
                    } catch (OtpRateLimitedException refused) {
                        return false;
                    }
                };
                results.add(pool.submit(send));
            }
            start.countDown();
            long admitted = 0;
            for (Future<Boolean> result : results) {
                if (result.get(30, TimeUnit.SECONDS)) {
                    admitted++;
                }
            }

            assertThat(admitted).isEqualTo(10);
            assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(10);
            assertThat(refusals(SmsSendGuard.Refusal.SIGN_UP_HOURLY_CEILING)).isEqualTo(senders - 10.0);
            // A refused send charged no number or address of its own.
            assertThat(redisTemplate.keys(SmsSendGuard.PHONE_KEY_PREFIX + "*")).hasSize(10);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void aCounterFoundWithoutAnExpiryIsGivenOne() {
        redisTemplate.opsForValue().set(SmsSendGuard.SIGN_UP_HOURLY_KEY, "0");

        guard.admit(BR, ADDRESS);

        assertThat(redisTemplate.getExpire(SmsSendGuard.SIGN_UP_HOURLY_KEY, TimeUnit.SECONDS))
                .isBetween(3500L, 3600L);
    }

    // -------------------- per-number day --------------------

    @Test
    void theDailyNumberLimitHoldsWhenTheHourlyWindowEnds() throws InterruptedException {
        properties.getOtp().setMaxRequestsPerPhonePerDay(2);
        guard.admit(CA, ADDRESS);
        guard.admit(CA, OTHER_ADDRESS);

        endWindow(SmsSendGuard.PHONE_KEY_PREFIX + CA);

        assertThatThrownBy(() -> guard.admit(CA, "192.0.2.1"))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> {
                    assertThat(refused.getMessage()).isEqualTo("Too many OTP requests");
                    assertThat(refused.getRetryAfter()).isGreaterThan(Duration.ofHours(23));
                });
        assertThat(refusals(SmsSendGuard.Refusal.PHONE_DAILY)).isEqualTo(1.0);
        // The refused send spent none of the ceilings or of the new address's budget.
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(2);
        assertThat(redisTemplate.hasKey(SmsSendGuard.IP_KEY_PREFIX + "192.0.2.1")).isFalse();
        // Other numbers keep their own day.
        assertThatCode(() -> guard.admit(US, "192.0.2.1")).doesNotThrowAnyException();
    }

    @Test
    void theDailyNumberLimitCoversSignedInAccountSends() {
        properties.getOtp().setMaxRequestsPerPhonePerDay(1);
        hasAccount(BR);
        guard.admit(BR, ADDRESS);

        assertThatThrownBy(() -> guard.admitForAccount(BR, OTHER_ADDRESS)).isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.PHONE_DAILY)).isEqualTo(1.0);
    }

    @Test
    void aSignInThatTextsNothingSkipsTheDailyNumberLimit() {
        properties.getOtp().setMaxRequestsPerPhonePerDay(1);
        guard.admitWithoutSms(US, ADDRESS);
        guard.admitWithoutSms(US, OTHER_ADDRESS);

        assertThat(redisTemplate.hasKey(SmsSendGuard.PHONE_DAILY_KEY_PREFIX + US)).isFalse();
    }

    @Test
    void aRefundGivesBackTheNumbersDay() {
        properties.getOtp().setMaxRequestsPerPhonePerDay(1);
        SmsSendGuard.Admission admission = guard.admit(BR, ADDRESS);
        assertThat(admission.keys()).contains(SmsSendGuard.PHONE_DAILY_KEY_PREFIX + BR);

        guard.refund(admission);

        assertThatCode(() -> guard.admit(BR, OTHER_ADDRESS)).doesNotThrowAnyException();
    }

    // -------------------- sign-up and account budgets --------------------

    @Test
    void aFullSignUpCeilingLeavesExistingAccountsTheirOwn() {
        properties.getOtp().setMaxSignUpSendsPerHour(2);
        properties.getOtp().setMaxSignUpSendsPerDay(2);
        guard.admit("+16042259900", "198.51.100.1");
        guard.admit("+16042259901", "198.51.100.2");
        assertThatThrownBy(() -> guard.admit(US, OTHER_ADDRESS)).isInstanceOf(OtpRateLimitedException.class);

        hasAccount(BR);
        assertThatCode(() -> guard.admit(BR, OTHER_ADDRESS)).doesNotThrowAnyException();

        assertThat(count(SmsSendGuard.ACCOUNT_HOURLY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.ACCOUNT_DAILY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(2);
        assertThat(count(SmsSendGuard.SIGN_UP_DAILY_KEY)).isEqualTo(2);
    }

    @Test
    void theAccountCeilingRefusesAccountsAndLeavesSignUpsAlone() {
        properties.getOtp().setMaxAccountSendsPerHour(1);
        hasAccount(BR);
        hasAccount(CA);
        guard.admit(BR, ADDRESS);

        assertThatThrownBy(() -> guard.admit(CA, OTHER_ADDRESS))
                .isInstanceOfSatisfying(OtpRateLimitedException.class, refused -> assertThat(refused.getRetryAfter())
                        .isGreaterThan(Duration.ofMinutes(59)));
        assertThat(refusals(SmsSendGuard.Refusal.ACCOUNT_HOURLY_CEILING)).isEqualTo(1.0);

        assertThatCode(() -> guard.admit(US, OTHER_ADDRESS)).doesNotThrowAnyException();
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(1);
    }

    @Test
    void aSendForASignedInAccountCountsAgainstTheAccountCeilingsWithoutALookup() {
        guard.admitForAccount(US, ADDRESS);

        assertThat(count(SmsSendGuard.ACCOUNT_HOURLY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.ACCOUNT_DAILY_KEY)).isEqualTo(1);
        assertThat(redisTemplate.hasKey(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isFalse();
        Mockito.verifyNoInteractions(directoryService);
    }

    @Test
    void aSendForASignedInAccountStillNeedsAnAllowedCountry() {
        allowOnly(SERVED);

        assertThatThrownBy(() -> guard.admitForAccount("+33612345678", ADDRESS))
                .isInstanceOf(UnsupportedPhoneCountryException.class);
        assertThat(redisTemplate.keys("otp:*")).isEmpty();
    }

    @Test
    void aSignInThatTextsNothingSpendsNoCeilingAndNeedsNoAllowedCountry() {
        allowOnly(SERVED);
        properties.getOtp().setMaxSignUpSendsPerHour(1);
        properties.getOtp().setMaxAccountSendsPerHour(1);
        guard.admit(US, "198.51.100.1");
        guard.admitForAccount(CA, "198.51.100.2");
        Mockito.clearInvocations(directoryService);

        guard.admitWithoutSms("+33612345678", ADDRESS);

        assertThat(redisTemplate.keys("otp:rate:*")).containsExactlyInAnyOrder(
                SmsSendGuard.SIGN_UP_HOURLY_KEY, SmsSendGuard.SIGN_UP_DAILY_KEY,
                SmsSendGuard.ACCOUNT_HOURLY_KEY, SmsSendGuard.ACCOUNT_DAILY_KEY,
                SmsSendGuard.IP_KEY_PREFIX + "198.51.100.1", SmsSendGuard.IP_KEY_PREFIX + "198.51.100.2",
                SmsSendGuard.PHONE_KEY_PREFIX + US, SmsSendGuard.PHONE_KEY_PREFIX + CA,
                SmsSendGuard.IP_KEY_PREFIX + ADDRESS, SmsSendGuard.PHONE_KEY_PREFIX + "+33612345678");
        Mockito.verifyNoInteractions(directoryService);
    }

    @Test
    void aSignInThatTextsNothingKeepsThePerNumberLimit() {
        properties.getOtp().setMaxRequestsPerPhonePerHour(1);
        guard.admitWithoutSms(US, ADDRESS);

        assertThatThrownBy(() -> guard.admitWithoutSms(US, OTHER_ADDRESS)).isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.PHONE)).isEqualTo(1.0);
    }

    // -------------------- destinations --------------------

    @Test
    void aDisallowedCountryIsRefusedBeforeAnythingIsCounted() {
        allowOnly(SERVED);
        // France, and Jamaica, which shares +1 with Canada and the US.
        for (String number : List.of("+33612345678", "+18765550123")) {
            assertThatThrownBy(() -> guard.admit(number, ADDRESS))
                    .isInstanceOf(UnsupportedPhoneCountryException.class);
        }

        assertThat(redisTemplate.keys("otp:*")).isEmpty();
        assertThat(refusals(SmsSendGuard.Refusal.COUNTRY)).isEqualTo(2.0);
    }

    @Test
    void admittedSendsAreCountedByDestinationAndBudget() {
        hasAccount(BR);
        guard.admit("+212650123456", ADDRESS);
        guard.admit("+212650123457", OTHER_ADDRESS);
        guard.admit(BR, ADDRESS);
        guard.admitForAccount(CA, ADDRESS);
        guard.admitWithoutSms(US, ADDRESS);
        properties.getOtp().setMaxRequestsPerPhonePerHour(1);
        assertThatThrownBy(() -> guard.admit("+212650123456", "192.0.2.1"))
                .isInstanceOf(OtpRateLimitedException.class);

        assertThat(admitted("MA", "sign_up")).isEqualTo(2.0);
        assertThat(admitted("BR", "account")).isEqualTo(1.0);
        assertThat(admitted("CA", "account")).isEqualTo(1.0);
        // A send that texts nothing is not a destination.
        assertThat(metrics.find("gua.identity.sms.admitted").tag("country", "US").counter()).isNull();
    }

    @Test
    void theServedCountriesAreAdmittedByDefault() {
        guard.admit(BR, ADDRESS);
        guard.admit(CA, ADDRESS);
        guard.admit(US, ADDRESS);

        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(3);
        assertThat(count(SmsSendGuard.SIGN_UP_DAILY_KEY)).isEqualTo(3);
    }

    @Test
    void theDefaultAdmitsEveryRegion() {
        assertThat(properties.getOtp().getAllowedCountries()).isEmpty();

        admitsSwedenKosovoAndJersey();
    }

    @Test
    void theShippedConfigurationAdmitsEveryRegion() throws IOException {
        // application.yml with IDENTITY_OTP_ALLOWED_COUNTRIES unset.
        OtpProperties shipped = shippedConfiguration().bind("identity.otp", OtpProperties.class).get();
        assertThat(shipped.getAllowedCountries()).isEmpty();

        allowOnly(shipped.getAllowedCountries());
        admitsSwedenKosovoAndJersey();
    }

    private void admitsSwedenKosovoAndJersey() {
        // Sweden, Kosovo (+383, XK) and Jersey (+44, JE).
        for (String number : List.of("+46701740605", "+38343201234", "+447797712345")) {
            guard.admit(number, ADDRESS);
            guard.admitForAccount(number, OTHER_ADDRESS);
        }

        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isEqualTo(3);
        assertThat(count(SmsSendGuard.ACCOUNT_HOURLY_KEY)).isEqualTo(3);
        assertThat(refusals(SmsSendGuard.Refusal.COUNTRY)).isZero();
    }

    @Test
    void theAllowlistIsConfigurable() {
        properties.getOtp().setAllowedCountries(List.of(" fr", "BR "));
        guard = newGuard();

        guard.admit("+33612345678", ADDRESS);
        assertThatThrownBy(() -> guard.admit(US, ADDRESS)).isInstanceOf(UnsupportedPhoneCountryException.class);
    }

    @Test
    void anUnknownRegionRefusesStartup() {
        properties.getOtp().setAllowedCountries(List.of("BR", "BRA"));

        assertThatThrownBy(this::newGuard)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("BRA");
    }

    @Test
    void aBlankAllowlistAdmitsEveryRegion() {
        allowOnly(List.of(" ", ""));

        guard.admit("+33612345678", ADDRESS);
        guard.admitForAccount("+18765550123", ADDRESS);
    }

    @Test
    void anUnparseableNumberIsInvalid() {
        assertThatThrownBy(() -> guard.admit("not a number", ADDRESS)).isInstanceOf(InvalidPhoneNumberException.class);
        assertThat(redisTemplate.keys("otp:*")).isEmpty();
    }

    @Test
    void aNumberInAnAllowedRegionThatIsNotValidIsRefusedBeforeAnythingIsCounted() {
        for (String number : List.of("+5500000000000", "+550000000")) {
            assertThatThrownBy(() -> guard.admit(number, ADDRESS)).isInstanceOf(InvalidPhoneNumberException.class);
            assertThatThrownBy(() -> guard.admitForAccount(number, ADDRESS))
                    .isInstanceOf(InvalidPhoneNumberException.class);
        }
        assertThat(redisTemplate.keys("otp:*")).isEmpty();
        Mockito.verifyNoInteractions(directoryService);
    }

    @Test
    void everySpellingOfANumberSharesItsBudget() {
        List<String> spellings = List.of("+55 11 99999-8888", "+55 (11) 99999-8888", "tel:+55-11-99999-8888",
                "+5511999998888 ext 9", "\uFF0B5511999998888");
        for (int i = 0; i < spellings.size(); i++) {
            guard.admit(spellings.get(i), "192.0.2." + i);
        }

        assertThatThrownBy(() -> guard.admit(BR, OTHER_ADDRESS)).isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.PHONE)).isEqualTo(1.0);
        assertThat(redisTemplate.keys(SmsSendGuard.PHONE_KEY_PREFIX + "*"))
                .containsExactly(SmsSendGuard.PHONE_KEY_PREFIX + BR);
        Mockito.verify(directoryService, Mockito.times(spellings.size() + 1)).findByDigest("digest:" + BR);
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
                SmsSendGuard.PHONE_KEY_PREFIX + BR, SmsSendGuard.SIGN_UP_HOURLY_KEY, SmsSendGuard.SIGN_UP_DAILY_KEY);
    }

    // -------------------- refunds --------------------

    @Test
    void aRefundGivesBackExactlyWhatTheAdmissionCharged() {
        hasAccount(CA);
        guard.admit(CA, OTHER_ADDRESS);
        SmsSendGuard.Admission admission = guard.admit(BR, ADDRESS);
        assertThat(admission.keys()).containsExactlyInAnyOrder(SmsSendGuard.SIGN_UP_DAILY_KEY,
                SmsSendGuard.SIGN_UP_HOURLY_KEY, SmsSendGuard.IP_KEY_PREFIX + ADDRESS,
                SmsSendGuard.PHONE_KEY_PREFIX + BR);

        guard.refund(admission);

        for (String key : admission.keys()) {
            assertThat(count(key)).as(key).isZero();
            assertThat(redisTemplate.getExpire(key, TimeUnit.SECONDS)).as(key).isPositive();
        }
        assertThat(count(SmsSendGuard.ACCOUNT_HOURLY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.ACCOUNT_DAILY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.PHONE_KEY_PREFIX + CA)).isEqualTo(1);
        assertThat(count(SmsSendGuard.IP_KEY_PREFIX + OTHER_ADDRESS)).isEqualTo(1);
    }

    @Test
    void withTheCeilingsOffARefundGivesBackTheNumberAndTheAddressOnly() {
        properties = new IdentityServiceProperties();
        guard = newGuard();

        SmsSendGuard.Admission admission = guard.admitForAccount(BR, ADDRESS);
        assertThat(admission.keys()).containsExactlyInAnyOrder(SmsSendGuard.IP_KEY_PREFIX + ADDRESS,
                SmsSendGuard.PHONE_KEY_PREFIX + BR);

        guard.refund(admission);

        assertThat(count(SmsSendGuard.IP_KEY_PREFIX + ADDRESS)).isZero();
        assertThat(count(SmsSendGuard.PHONE_KEY_PREFIX + BR)).isZero();
        assertThat(redisTemplate.keys("otp:rate:sign-up:*")).isEmpty();
        assertThat(redisTemplate.keys("otp:rate:account:*")).isEmpty();
    }

    // -------------------- through the send path --------------------

    @Test
    void aSendTheProviderRefusesLeavesItsCeilingSlotForTheNextSend() {
        properties.getOtp().setMaxSignUpSendsPerHour(1);
        SmsSender provider = Mockito.mock(SmsSender.class);
        Mockito.doThrow(new SmsRefusedException(SmsRefusedException.Reason.DESTINATION_UNAVAILABLE))
                .when(provider).send(Mockito.eq(CA), Mockito.anyString());
        OtpService otpService = otpService(provider);

        assertThatThrownBy(() -> otpService.sendOtp(CA, ADDRESS, null)).isInstanceOf(SmsRefusedException.class);
        assertThat(count(SmsSendGuard.SIGN_UP_HOURLY_KEY)).isZero();
        assertThat(count(SmsSendGuard.SIGN_UP_DAILY_KEY)).isZero();

        otpService.sendOtp(US, OTHER_ADDRESS, null);
        Mockito.verify(provider).send(Mockito.eq(US), Mockito.anyString());
        assertThatThrownBy(() -> otpService.sendOtp(BR, "192.0.2.1", null))
                .isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.SIGN_UP_HOURLY_CEILING)).isEqualTo(1.0);
    }

    @Test
    void aDeliveredSendSpendsItsCeilingSlot() {
        properties.getOtp().setMaxAccountSendsPerHour(1);
        hasAccount(BR);
        SmsSender provider = Mockito.mock(SmsSender.class);
        OtpService otpService = otpService(provider);

        otpService.sendOtp(BR, ADDRESS, "pt-BR");

        assertThat(count(SmsSendGuard.ACCOUNT_HOURLY_KEY)).isEqualTo(1);
        assertThat(count(SmsSendGuard.ACCOUNT_DAILY_KEY)).isEqualTo(1);
        assertThatThrownBy(() -> otpService.sendOtp(BR, OTHER_ADDRESS, null))
                .isInstanceOf(OtpRateLimitedException.class);
        assertThat(refusals(SmsSendGuard.Refusal.ACCOUNT_HOURLY_CEILING)).isEqualTo(1.0);
    }

    @Test
    void aDisallowedCountryNeverReachesTheProviderAndAnAllowedOneDoes() {
        allowOnly(SERVED);
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
        properties.getOtp().setMaxSignUpSendsPerHour(1);
        SmsSender provider = Mockito.mock(SmsSender.class);
        OtpService otpService = otpService(provider);
        otpService.sendOtp(CA, ADDRESS, null);

        assertThatThrownBy(() -> otpService.sendOtp(US, OTHER_ADDRESS, null))
                .isInstanceOf(OtpRateLimitedException.class);
        Mockito.verify(provider, Mockito.never()).send(Mockito.eq(US), Mockito.anyString());
        assertThat(redisTemplate.hasKey("otp:code:" + US)).isFalse();
    }

    @Test
    void aRedisOutageSendsNothing() {
        LettuceConnectionFactory unreachable = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(redis.getHost(), 1));
        unreachable.afterPropertiesSet();
        unreachable.start();
        try {
            redisTemplate = new StringRedisTemplate(unreachable);
            redisTemplate.afterPropertiesSet();
            guard = newGuard();
            SmsSender provider = Mockito.mock(SmsSender.class);
            OtpService otpService = otpService(provider);

            assertThatThrownBy(() -> otpService.sendOtp(BR, ADDRESS, "pt-BR"))
                    .isInstanceOf(DataAccessException.class);
            Mockito.verifyNoInteractions(provider);
        } finally {
            unreachable.destroy();
        }
    }

    @Test
    void aSignUpFloodDoesNotStopAnExistingAccountsSignIn() {
        properties.getOtp().setMaxSignUpSendsPerHour(1);
        SmsSender provider = Mockito.mock(SmsSender.class);
        OtpService otpService = otpService(provider);
        otpService.sendOtp(CA, ADDRESS, null);
        assertThatThrownBy(() -> otpService.sendOtp(US, OTHER_ADDRESS, null))
                .isInstanceOf(OtpRateLimitedException.class);

        hasAccount(BR);
        otpService.sendOtp(BR, OTHER_ADDRESS, "pt-BR");

        Mockito.verify(provider).send(Mockito.eq(BR), Mockito.anyString());
    }

    private OtpService otpService(SmsSender provider) {
        ReviewLogin reviewLogin = new ReviewLogin(ReviewLoginProperties.off(), new PhoneNumberNormalizer(),
                new PhoneNumberMasker(), metrics, Mockito.mock(DirectoryService.class),
                Mockito.mock(PhoneNumberHasher.class), duration -> {
                }, new BCryptPasswordEncoder());
        return new OtpService(redisTemplate, properties, new OtpCodeGenerator(), provider, guard, metrics,
                reviewLogin);
    }

    private static Binder shippedConfiguration() throws IOException {
        MutablePropertySources sources = new MutablePropertySources();
        new YamlPropertySourceLoader().load("application.yml", new ClassPathResource("application.yml"))
                .forEach(sources::addLast);
        return new Binder(ConfigurationPropertySources.from(sources), new PropertySourcesPlaceholdersResolver(sources));
    }

    private static void configureCeilings(OtpProperties otp) {
        otp.setMaxSignUpSendsPerHour(60);
        otp.setMaxSignUpSendsPerDay(300);
        otp.setMaxAccountSendsPerHour(120);
        otp.setMaxAccountSendsPerDay(600);
    }

    private void allowOnly(List<String> regions) {
        properties.getOtp().setAllowedCountries(regions);
        guard = newGuard();
    }

    private SmsSendGuard newGuard() {
        return new SmsSendGuard(redisTemplate, properties, metrics, directoryService, phoneNumberHasher,
                new RateLimiter(redisTemplate));
    }

    private void hasAccount(String e164) {
        Mockito.when(directoryService.findByDigest("digest:" + e164)).thenReturn(Optional.of(DirectoryEntry.builder()
                .phoneDigest("digest:" + e164).userId("@account:" + e164).build()));
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

    private double admitted(String country, String budget) {
        Counter counter = metrics.find("gua.identity.sms.admitted").tag("country", country).tag("budget", budget)
                .counter();
        return counter == null ? 0.0 : counter.count();
    }

    private double refusals(SmsSendGuard.Refusal refusal) {
        Counter counter = metrics.find("gua.identity.sms.refused").tag("reason", refusal.tagValue()).counter();
        return counter == null ? 0.0 : counter.count();
    }
}
