package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;

class ReviewLoginTest {

    static final String REVIEW_PHONE = "+16042259901";
    static final String OTHER_PHONE = "+16042259902";
    static final String REVIEW_CODE = "135790";
    /** bcrypt of {@link #REVIEW_CODE} at the lowest cost startup accepts, to keep the tests quick. */
    static final String REVIEW_CODE_HASH = new BCryptPasswordEncoder(ReviewLogin.MIN_COST).encode(REVIEW_CODE);
    /** What the operator command in the README prints for {@link #REVIEW_CODE}: htpasswd writes $2y$. */
    private static final String HTPASSWD_HASH = "$2y$12$l6e7kk4cHubVejUuAh.w8.H50f.NEqmUEVbdJo96Q4mra.CoykzAG";

    private static final String REVIEW_DIGEST = "review-digest";
    private static final String REVIEW_ACCOUNT = "@review:gua.local";

    private final SimpleMeterRegistry metrics = new SimpleMeterRegistry();
    private final List<Duration> waits = new ArrayList<>();
    private final DirectoryService directory = mock(DirectoryService.class);
    private final PhoneNumberHasher hasher = mock(PhoneNumberHasher.class);
    private ListAppender<ILoggingEvent> logs;
    private Logger logger;

    @BeforeEach
    void captureLogs() {
        logger = (Logger) LoggerFactory.getLogger(ReviewLogin.class);
        logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logs);
    }

    static ReviewLoginProperties enabled(String phone, String hash) {
        return ReviewLoginProperties.of("true", phone, hash);
    }

    private ReviewLogin reviewLogin(ReviewLoginProperties properties) {
        return reviewLogin(properties, new BCryptPasswordEncoder());
    }

    private ReviewLogin reviewLogin(ReviewLoginProperties properties, BCryptPasswordEncoder encoder) {
        return new ReviewLogin(properties, new PhoneNumberNormalizer(), new PhoneNumberMasker(), metrics, directory,
                hasher, waits::add, encoder);
    }

    // -------------------- off --------------------

    @Test
    void offByDefaultAndInert() {
        ReviewLogin off = reviewLogin(ReviewLoginProperties.off());

        assertThat(off.isReviewNumber(REVIEW_PHONE)).isFalse();
        assertThat(off.matchesReviewCode(REVIEW_CODE)).isFalse();
        assertThat(off.isReviewAccount(REVIEW_ACCOUNT)).isFalse();
        assertThat(logs.list).isEmpty();
        assertThat(metrics.getMeters()).isEmpty();
        verifyNoInteractions(directory, hasher);
    }

    @Test
    void theOffSwitchWinsWhateverElseIsSet() {
        for (String off : new String[] { "false", "", null }) {
            ReviewLogin reviewLogin = reviewLogin(ReviewLoginProperties.of(off, "not a phone", "not a hash"));

            assertThat(reviewLogin.isReviewNumber("not a phone")).isFalse();
            assertThat(reviewLogin.matchesReviewCode(REVIEW_CODE)).isFalse();
        }
    }

    @Test
    void theConstructorSpringUsesNeedsNoTestSeam() {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                new SystemEnvironmentPropertySource(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                        Map.of()));

        assertThatCode(() -> new ReviewLogin(environment, new PhoneNumberNormalizer(), new PhoneNumberMasker(),
                metrics, directory, hasher)).doesNotThrowAnyException();
    }

    // -------------------- the switch --------------------

    /** Exactly true turns it on; exactly false, empty or unset is off; nothing else is guessed at. */
    @Test
    void onlyExactlyTrueOrFalseIsASwitch() {
        assertThat(ReviewLoginProperties.of("true", null, null).isEnabled()).isTrue();
        for (String off : new String[] { "false", "", null }) {
            assertThat(ReviewLoginProperties.of(off, REVIEW_PHONE, REVIEW_CODE_HASH).isEnabled()).isFalse();
        }
        for (String unreadable : new String[] { "TRUE", "True", "yes", "on", "1", " true", "true ", "FALSE", "no",
                "off", "0", "maybe" }) {
            assertThatThrownBy(() -> ReviewLoginProperties.of(unreadable, REVIEW_PHONE, REVIEW_CODE_HASH))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("GUA_REVIEW_LOGIN_ENABLED must be exactly true or false")
                    .hasMessageContaining("Refusing to start");
        }
    }

    // -------------------- startup validation --------------------

    @Test
    void onRefusesAMissingPhone() {
        for (String phone : new String[] { null, "", "   " }) {
            assertThatThrownBy(() -> reviewLogin(enabled(phone, REVIEW_CODE_HASH)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("GUA_REVIEW_LOGIN_PHONE is not set");
        }
    }

    @Test
    void onRefusesAPhoneThatIsNotANumber() {
        for (String phone : new String[] { "12345", "review", "+1999" }) {
            assertThatThrownBy(() -> reviewLogin(enabled(phone, REVIEW_CODE_HASH)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not a valid phone number");
        }
    }

    @Test
    void onRefusesAPhoneNotWrittenInE164() {
        // Each of these normalizes to the review number, but matching is on the exact canonical form,
        // so a value that is not already canonical is a configuration mistake.
        for (String phone : new String[] { "6042259901", "+1 604 225 9901", " +16042259901", "+1-604-225-9901" }) {
            assertThatThrownBy(() -> reviewLogin(enabled(phone, REVIEW_CODE_HASH)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("must be written in E.164");
        }
    }

    @Test
    void onRefusesAMissingHash() {
        for (String hash : new String[] { null, "", "  " }) {
            assertThatThrownBy(() -> reviewLogin(enabled(REVIEW_PHONE, hash)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("GUA_REVIEW_LOGIN_CODE_HASH is not set");
        }
    }

    @Test
    void onRefusesAnythingButABcryptHashAndNeverEchoesIt() {
        String[] notBcrypt = {
                // The code itself, the mistake this is most likely to catch.
                REVIEW_CODE,
                // A fast digest.
                "4d4f3f1b0e1d34bb7b9a53f1c1b8a3c2f4d1e0a9b8c7d6e5f4a3b2c1d0e9f8a7",
                // Spring's DelegatingPasswordEncoder spelling.
                "{bcrypt}" + REVIEW_CODE_HASH,
                // Truncated, and with trailing whitespace.
                REVIEW_CODE_HASH.substring(0, 40),
                REVIEW_CODE_HASH + " " };
        for (String hash : notBcrypt) {
            assertThatThrownBy(() -> reviewLogin(enabled(REVIEW_PHONE, hash)))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("not a bcrypt hash")
                    .hasMessageNotContaining(hash.trim())
                    .hasMessageNotContaining(REVIEW_PHONE);
        }
    }

    @Test
    void onRefusesACostOutsideTheAllowedRange() {
        String cheap = new BCryptPasswordEncoder(4).encode(REVIEW_CODE);
        // Well formed but far too slow to verify on every guess; only the cost field is checked.
        String tooSlow = REVIEW_CODE_HASH.replace("$2a$10$", "$2a$15$");

        assertThatThrownBy(() -> reviewLogin(enabled(REVIEW_PHONE, cheap)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cost 4")
                .hasMessageNotContaining(cheap);
        assertThatThrownBy(() -> reviewLogin(enabled(REVIEW_PHONE, tooSlow)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cost 15");
    }

    @Test
    void onAcceptsWhatTheOperatorCommandPrints() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, HTPASSWD_HASH));

        assertThat(on.matchesReviewCode(REVIEW_CODE)).isTrue();
        assertThat(on.matchesReviewCode("135791")).isFalse();
    }

    @Test
    void onAnnouncesItselfWithTheNumberMasked() {
        reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));

        assertThat(logs.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("ON").contains("••••9901");
        });
        assertNoSecretsLogged();
    }

    // -------------------- matching --------------------

    @Test
    void onlyTheExactReviewNumberIsTheReviewNumber() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));

        assertThat(on.isReviewNumber(REVIEW_PHONE)).isTrue();
        assertThat(on.isReviewNumber(OTHER_PHONE)).isFalse();
        assertThat(on.isReviewNumber("6042259901")).isFalse();
        assertThat(on.isReviewNumber(REVIEW_PHONE + " ")).isFalse();
        assertThat(on.isReviewNumber(null)).isFalse();
    }

    @Test
    void onlyTheReviewCodeMatches() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));

        assertThat(on.matchesReviewCode(REVIEW_CODE)).isTrue();
        assertThat(on.matchesReviewCode("135791")).isFalse();
        assertThat(on.matchesReviewCode("")).isFalse();
        assertThat(on.matchesReviewCode(null)).isFalse();
        // The hash is not a second code.
        assertThat(on.matchesReviewCode(REVIEW_CODE_HASH)).isFalse();
    }

    /**
     * The check a sign-in verify of any other number pays for: the same bcrypt comparison against
     * the same hash, so it costs the same, with the answer thrown away. Nothing while off.
     */
    // -------------------- the review account --------------------

    /** The account the review number's directory row names, and no other. */
    @Test
    void theReviewAccountIsTheOneTheReviewNumberResolvesTo() {
        when(hasher.digest(REVIEW_PHONE)).thenReturn(REVIEW_DIGEST);
        DirectoryEntry row = mock(DirectoryEntry.class);
        when(row.getUserId()).thenReturn(REVIEW_ACCOUNT);
        when(directory.findByDigest(REVIEW_DIGEST)).thenReturn(Optional.of(row));
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));

        assertThat(on.isReviewAccount(REVIEW_ACCOUNT)).isTrue();
        assertThat(on.isReviewAccount("@someone:gua.local")).isFalse();
        assertThat(on.isReviewAccount(null)).isFalse();
        assertThat(on.isReviewAccount("")).isFalse();
    }

    @Test
    void beforeTheReviewNumberSignsUpThereIsNoReviewAccount() {
        when(hasher.digest(REVIEW_PHONE)).thenReturn(REVIEW_DIGEST);
        when(directory.findByDigest(REVIEW_DIGEST)).thenReturn(Optional.empty());

        assertThat(reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH)).isReviewAccount(REVIEW_ACCOUNT)).isFalse();
    }

    @Test
    void aSpentCheckIsTheReviewCodeCheckWithItsAnswerDiscarded() {
        List<String> checkedAgainst = new CopyOnWriteArrayList<>();
        BCryptPasswordEncoder recording = new BCryptPasswordEncoder() {
            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                checkedAgainst.add(encodedPassword);
                return super.matches(rawPassword, encodedPassword);
            }
        };
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH), recording);
        logs.list.clear();

        on.spendAReviewCodeCheck("000000");
        on.spendAReviewCodeCheck(REVIEW_CODE);
        on.matchesReviewCode("000000");

        assertThat(checkedAgainst).containsExactly(REVIEW_CODE_HASH, REVIEW_CODE_HASH, REVIEW_CODE_HASH);
        // Spending a check records nothing: it is not a review sign-in.
        assertThat(logs.list).isEmpty();
        assertThat(metrics.getMeters()).isEmpty();

        ReviewLogin off = reviewLogin(ReviewLoginProperties.off(), recording);
        off.spendAReviewCodeCheck(REVIEW_CODE);
        assertThat(checkedAgainst).hasSize(3);
    }

    // -------------------- audit --------------------

    @Test
    void everyOutcomeIsLoggedMaskedAndCounted() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));
        logs.list.clear();

        for (ReviewLogin.Outcome outcome : ReviewLogin.Outcome.values()) {
            on.record(REVIEW_PHONE, outcome);
        }

        assertThat(logs.list).hasSize(ReviewLogin.Outcome.values().length).allSatisfy(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.WARN);
            assertThat(event.getFormattedMessage()).contains("••••9901");
        });
        for (ReviewLogin.Outcome outcome : ReviewLogin.Outcome.values()) {
            assertThat(count(metrics, outcome)).isEqualTo(1.0);
        }
        assertNoSecretsLogged();
    }

    /** A lockout writes one ERROR line, masked, and counts as locked. */
    @Test
    void aLockoutIsLoggedOnceAtErrorAndCounted() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));
        logs.list.clear();

        on.recordLockout(REVIEW_PHONE);

        assertThat(logs.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).startsWith("Store review login locked for ••••9901")
                    .contains("20 wrong codes within 24 hours");
        });
        assertThat(count(metrics, ReviewLogin.Outcome.LOCKED)).isEqualTo(1.0);
        assertNoSecretsLogged();
    }

    // -------------------- timing --------------------

    @Test
    void aReviewSendWaitsTheDefaultUntilARealSendHasBeenTimed() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));

        on.waitLikeAProviderCall();

        assertThat(waits).singleElement().satisfies(wait -> assertWithinJitter(wait,
                ReviewLogin.DEFAULT_PROVIDER_LATENCY));
    }

    @Test
    void aReviewSendWaitsAsLongAsRealSendsTake() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));
        for (int i = 0; i < 50; i++) {
            on.observeProviderLatency(Duration.ofMillis(900));
        }

        on.waitLikeAProviderCall();

        assertThat(waits).singleElement().satisfies(wait -> assertWithinJitter(wait, Duration.ofMillis(900)));
    }

    @Test
    void aStalledProviderCallDoesNotStallReviewSends() {
        ReviewLogin on = reviewLogin(enabled(REVIEW_PHONE, REVIEW_CODE_HASH));
        on.observeProviderLatency(Duration.ofMinutes(5));

        on.waitLikeAProviderCall();

        assertThat(waits.get(0)).isLessThanOrEqualTo(Duration.ofMillis(3750));
    }

    // -------------------- bound from the environment --------------------

    /**
     * Through a Spring context and the real application.yml, with the variables in the process
     * environment's own property source, the only place they are read from.
     */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(ReviewLoginOnly.class);

    private ApplicationContextRunner withEnv(Map<String, Object> env) {
        return runner.withInitializer(context -> context.getEnvironment().getPropertySources()
                .replace(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, new SystemEnvironmentPropertySource(
                        StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME, env)));
    }

    private static Map<String, Object> fullyConfigured() {
        return Map.of(
                "GUA_REVIEW_LOGIN_ENABLED", "true",
                "GUA_REVIEW_LOGIN_PHONE", REVIEW_PHONE,
                "GUA_REVIEW_LOGIN_CODE_HASH", REVIEW_CODE_HASH);
    }

    /** Also proves application.yml carries no identity.review-login property, which would refuse startup. */
    @Test
    void noVariablesMeansOff() {
        withEnv(Map.of()).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(ReviewLogin.class).isReviewNumber(REVIEW_PHONE)).isFalse();
        });
    }

    @Test
    void theDocumentedVariablesTurnItOn() {
        withEnv(fullyConfigured()).run(context -> {
                    assertThat(context).hasNotFailed();
                    ReviewLogin on = context.getBean(ReviewLogin.class);
                    assertThat(on.isReviewNumber(REVIEW_PHONE)).isTrue();
                    assertThat(on.matchesReviewCode(REVIEW_CODE)).isTrue();
                });
    }

    @Test
    void falseOrEmptyTurnsItOffWithTheRestStillSet() {
        for (String off : new String[] { "false", "" }) {
            withEnv(Map.of(
                    "GUA_REVIEW_LOGIN_ENABLED", off,
                    "GUA_REVIEW_LOGIN_PHONE", "junk",
                    "GUA_REVIEW_LOGIN_CODE_HASH", "junk")).run(context -> {
                        assertThat(context).hasNotFailed();
                        assertThat(context.getBean(ReviewLogin.class).isReviewNumber(REVIEW_PHONE)).isFalse();
                    });
        }
    }

    @Test
    void startupFailsOnABadConfigurationWithoutRevealingIt() {
        String plaintextCode = REVIEW_CODE;
        List<Map<String, Object>> bad = List.of(
                Map.of("GUA_REVIEW_LOGIN_ENABLED", "true", "GUA_REVIEW_LOGIN_CODE_HASH", REVIEW_CODE_HASH),
                Map.of("GUA_REVIEW_LOGIN_ENABLED", "true", "GUA_REVIEW_LOGIN_PHONE", REVIEW_PHONE),
                Map.of("GUA_REVIEW_LOGIN_ENABLED", "true", "GUA_REVIEW_LOGIN_PHONE", REVIEW_PHONE,
                        "GUA_REVIEW_LOGIN_CODE_HASH", plaintextCode),
                Map.of("GUA_REVIEW_LOGIN_ENABLED", "true", "GUA_REVIEW_LOGIN_PHONE", "6042259901",
                        "GUA_REVIEW_LOGIN_CODE_HASH", REVIEW_CODE_HASH));
        for (Map<String, Object> env : bad) {
            withEnv(env).run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("Refusing to start");
                assertThat(stackText(context.getStartupFailure()))
                        .doesNotContain(REVIEW_CODE_HASH)
                        .doesNotContain(plaintextCode);
            });
        }
    }

    /** What relaxed binding to a Boolean accepted before: each now refuses startup instead. */
    @Test
    void anUnreadableSwitchFailsRatherThanGuessing() {
        for (String unreadable : new String[] { "maybe", "TRUE", "yes", "on", "1", "FALSE", "no", "0" }) {
            withEnv(Map.of(
                    "GUA_REVIEW_LOGIN_ENABLED", unreadable,
                    "GUA_REVIEW_LOGIN_PHONE", REVIEW_PHONE,
                    "GUA_REVIEW_LOGIN_CODE_HASH", REVIEW_CODE_HASH)).run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).rootCause()
                                .hasMessageContaining("GUA_REVIEW_LOGIN_ENABLED must be exactly true or false");
                    });
        }
    }

    /**
     * The three names count only as environment variables. Set as properties or system
     * properties they are ignored, so nothing but the process environment can switch it on.
     */
    @Test
    void theVariablesAreReadFromTheEnvironmentOnly() {
        withEnv(Map.of())
                .withPropertyValues("GUA_REVIEW_LOGIN_ENABLED=true", "GUA_REVIEW_LOGIN_PHONE=" + REVIEW_PHONE,
                        "GUA_REVIEW_LOGIN_CODE_HASH=" + REVIEW_CODE_HASH)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(ReviewLogin.class).isReviewNumber(REVIEW_PHONE)).isFalse();
                });
        withEnv(Map.of())
                .withSystemProperties("GUA_REVIEW_LOGIN_ENABLED=true", "GUA_REVIEW_LOGIN_PHONE=" + REVIEW_PHONE,
                        "GUA_REVIEW_LOGIN_CODE_HASH=" + REVIEW_CODE_HASH)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(ReviewLogin.class).isReviewNumber(REVIEW_PHONE)).isFalse();
                });
    }

    /**
     * The probe that found the gap: relaxed binding read IDENTITY_REVIEW_LOGIN_ENABLED=true over
     * GUA_REVIEW_LOGIN_ENABLED=false and turned the feature on. Any spelling of an
     * identity.review-login property, from the environment or any other source, now refuses
     * startup, whatever the GUA_ variables say, and the refusal never carries the value.
     */
    @Test
    void anIdentityReviewLoginPropertyFromAnySourceRefusesStartup() {
        Map<String, Object> off = Map.of("GUA_REVIEW_LOGIN_ENABLED", "false");
        List<ApplicationContextRunner> foreign = List.of(
                withEnv(Map.of("GUA_REVIEW_LOGIN_ENABLED", "false", "IDENTITY_REVIEW_LOGIN_ENABLED", "true")),
                withEnv(Map.of("IDENTITY_REVIEWLOGIN_ENABLED", "true")),
                withEnv(Map.of("IDENTITY_REVIEW_LOGIN_PHONE", OTHER_PHONE)),
                withEnv(Map.of("IDENTITY_REVIEW_LOGIN_CODE_HASH", REVIEW_CODE_HASH)),
                withEnv(fullyConfigured()).withPropertyValues("identity.review-login.phone=" + OTHER_PHONE),
                withEnv(off).withPropertyValues("identity.review-login.enabled=true"),
                withEnv(off).withPropertyValues("identity.reviewLogin.code-hash=" + REVIEW_CODE_HASH),
                withEnv(off).withSystemProperties("identity.review-login.enabled=true"));
        for (ApplicationContextRunner candidate : foreign) {
            candidate.run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("reads only the GUA_REVIEW_LOGIN_ENABLED, GUA_REVIEW_LOGIN_PHONE and"
                                + " GUA_REVIEW_LOGIN_CODE_HASH environment variables")
                        .hasMessageContaining("Refusing to start");
                assertThat(stackText(context.getStartupFailure()))
                        .doesNotContain(REVIEW_CODE_HASH)
                        .doesNotContain(OTHER_PHONE);
            });
        }
    }

    @Configuration(proxyBeanMethods = false)
    @Import({ ReviewLogin.class, PhoneNumberNormalizer.class, PhoneNumberMasker.class })
    static class ReviewLoginOnly {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }

        @Bean
        DirectoryService directoryService() {
            return mock(DirectoryService.class);
        }

        @Bean
        PhoneNumberHasher phoneNumberHasher() {
            return mock(PhoneNumberHasher.class);
        }
    }

    // -------------------- helpers --------------------

    static double count(MeterRegistry metrics, ReviewLogin.Outcome outcome) {
        Counter counter = metrics.find("gua.identity.review.login").tag("outcome", outcome.tag()).counter();
        return counter == null ? 0.0 : counter.count();
    }

    private void assertNoSecretsLogged() {
        assertThat(logs.list).allSatisfy(event -> assertThat(event.getFormattedMessage())
                .doesNotContain(REVIEW_CODE)
                .doesNotContain(REVIEW_CODE_HASH)
                .doesNotContain(HTPASSWD_HASH)
                .doesNotContain(REVIEW_PHONE));
    }

    private static void assertWithinJitter(Duration actual, Duration base) {
        assertThat(actual).isBetween(base.multipliedBy(3).dividedBy(4), base.multipliedBy(5).dividedBy(4));
    }

    private static String stackText(Throwable failure) {
        StringBuilder text = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            text.append(t).append('\n');
        }
        return text.toString();
    }
}
