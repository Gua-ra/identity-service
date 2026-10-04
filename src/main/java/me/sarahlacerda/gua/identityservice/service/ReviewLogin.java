package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;

/**
 * The store review login. App store reviewers cannot receive our SMS, so exactly one
 * project-owned number may sign in with a fixed code instead of a texted one. Only the
 * interactive sign-in consults this (see {@link OtpService#sendLoginOtp} and
 * {@link OtpService#verifyLoginOtp}); every other OTP purpose never does, and every other
 * number is answered as before. The account's PIN is still required after the code. The
 * delayed account recovery, which would replace that PIN, is never offered to the review number,
 * and the review account ({@link #isReviewAccount}) is never offered, never registers and never
 * signs in with a passkey, so the code and the PIN are its only way in and rotating either cuts
 * off everyone who held the old one.
 *
 * <p>
 * Configured only by the {@code GUA_REVIEW_LOGIN_*} environment variables
 * ({@link ReviewLoginProperties}), off unless {@code GUA_REVIEW_LOGIN_ENABLED} is exactly
 * {@code true}. When on, a missing or malformed number or hash refuses startup, so a bad
 * configuration can neither enable the feature half way nor accept anything. The code itself is
 * never configured, only its bcrypt hash, the primitive PINs are hashed with; bcrypt's comparison
 * is constant time.
 *
 * <p>
 * The code never changes, so wrong guesses at it add up across sends: {@value #LOCKOUT_FAILURES}
 * of them within {@link #LOCKOUT_WINDOW} refuse every review code until that window ends
 * ({@link OtpService#verifyLoginOtp} keeps the count).
 *
 * <p>
 * A bcrypt check is slow, so while the feature is on every sign-in verify of every number
 * pays for exactly one ({@link #spendAReviewCodeCheck}); otherwise a wrong guess for the review
 * number would answer measurably later than one for any other number and name it.
 *
 * <p>
 * Every send and verify for the review number is logged at WARN with the number masked, and
 * counted as {@code gua_identity_review_login_total{outcome}}. The lockout is also logged once
 * at ERROR when it trips. Neither the code nor the hash is ever logged.
 */
@Component
public class ReviewLogin {

    private static final Logger log = LoggerFactory.getLogger(ReviewLogin.class);

    /** bcrypt as htpasswd and Spring write it: version, two-digit cost, 53 characters of salt and hash. */
    private static final Pattern BCRYPT = Pattern.compile("\\A\\$2[aby]\\$(\\d\\d)\\$[./0-9A-Za-z]{53}\\z");
    static final int MIN_COST = 10;
    static final int MAX_COST = 14;

    /** Wrong review codes within {@link #LOCKOUT_WINDOW} that lock the review code until the window ends. */
    public static final int LOCKOUT_FAILURES = 20;
    /** Fixed from the first wrong review code it counts. */
    public static final Duration LOCKOUT_WINDOW = Duration.ofHours(24);

    /** How long a review send waits before any real provider call has been timed on this instance. */
    static final Duration DEFAULT_PROVIDER_LATENCY = Duration.ofMillis(400);
    private static final long MAX_PROVIDER_LATENCY_NANOS = Duration.ofSeconds(3).toNanos();

    public enum Outcome {
        SENT("sent"),
        SEND_RATE_LIMITED("send_rate_limited"),
        ACCEPTED("accepted"),
        /** A wrong code, counted against the guess budget like any other. */
        REJECTED("rejected"),
        /** The guess budget is spent and the code is gone. */
        EXHAUSTED("exhausted"),
        /** No live code: never sent, expired, already used or burned. */
        NO_CODE("no_code"),
        /**
         * The lockout tripped, or refused a verify while it holds. A refused verify is never
         * compared with the review code, whatever was submitted.
         */
        LOCKED("locked");

        private final String tag;

        Outcome(String tag) {
            this.tag = tag;
        }

        public String tag() {
            return tag;
        }
    }

    @FunctionalInterface
    interface Sleeper {
        Sleeper THREAD = Thread::sleep;

        void sleep(Duration duration) throws InterruptedException;
    }

    private final boolean enabled;
    private final String phone;
    private final String codeHash;
    private final PasswordEncoder encoder;
    private final PhoneNumberMasker masker;
    private final MeterRegistry metrics;
    private final DirectoryService directory;
    private final PhoneNumberHasher hasher;
    private final Sleeper sleeper;
    /** Moving average of real provider calls, or -1 before the first one. */
    private final AtomicLong providerLatencyNanos = new AtomicLong(-1);

    @Autowired
    public ReviewLogin(ConfigurableEnvironment environment, PhoneNumberNormalizer normalizer,
            PhoneNumberMasker masker, MeterRegistry metrics, DirectoryService directory, PhoneNumberHasher hasher) {
        this(ReviewLoginProperties.fromEnvironment(environment), normalizer, masker, metrics, directory, hasher,
                Sleeper.THREAD, new BCryptPasswordEncoder());
    }

    /**
     * {@code sleeper} and {@code encoder} are seams for tests that time sends and count
     * comparisons; {@code encoder} must check bcrypt hashes.
     */
    ReviewLogin(ReviewLoginProperties properties, PhoneNumberNormalizer normalizer, PhoneNumberMasker masker,
            MeterRegistry metrics, DirectoryService directory, PhoneNumberHasher hasher, Sleeper sleeper,
            PasswordEncoder encoder) {
        this.masker = masker;
        this.metrics = metrics;
        this.directory = directory;
        this.hasher = hasher;
        this.sleeper = sleeper;
        this.encoder = encoder;
        this.enabled = properties.isEnabled();
        if (!enabled) {
            // The off switch works whatever else is set, so nothing else is read.
            this.phone = null;
            this.codeHash = null;
            return;
        }
        this.phone = requireCanonicalPhone(properties.getPhone(), normalizer);
        this.codeHash = requireCodeHash(properties.getCodeHash());
        log.warn("Store review login is ON for {}", masker.mask(phone));
    }

    /** Whether {@code e164} is the review number, compared exactly against its canonical form. */
    public boolean isReviewNumber(String e164) {
        return enabled && phone.equals(e164);
    }

    /**
     * Whether {@code userId} is the review account: the account the review number's directory row
     * names. Reads nothing while the feature is off.
     */
    public boolean isReviewAccount(String userId) {
        if (!enabled || !StringUtils.hasText(userId)) {
            return false;
        }
        return directory.findByDigest(hasher.digest(phone))
                .map(DirectoryEntry::getUserId)
                .filter(userId::equals)
                .isPresent();
    }

    /** Whether {@code submitted} is the review code. */
    public boolean matchesReviewCode(String submitted) {
        return enabled && submitted != null && encoder.matches(submitted, codeHash);
    }

    /**
     * Does the work of {@link #matchesReviewCode} and discards the answer. A sign-in verify that
     * does not compare against the review code calls this instead, so every sign-in verify costs
     * the same one bcrypt check while the feature is on, and none while it is off.
     */
    public void spendAReviewCodeCheck(String submitted) {
        if (enabled && submitted != null) {
            encoder.matches(submitted, codeHash);
        }
    }

    public void record(String e164, Outcome outcome) {
        log.warn("Store review login {} for {}", outcome.tag(), masker.mask(e164));
        count(outcome);
    }

    /** The one ERROR line a lockout writes, when it trips, counted as {@link Outcome#LOCKED}. */
    public void recordLockout(String e164) {
        log.error("Store review login locked for {}: {} wrong codes within {} hours. Every review code is refused"
                + " until the window ends.", masker.mask(e164), LOCKOUT_FAILURES, LOCKOUT_WINDOW.toHours());
        count(Outcome.LOCKED);
    }

    private void count(Outcome outcome) {
        metrics.counter("gua.identity.review.login", "outcome", outcome.tag()).increment();
    }

    /** Feeds the duration of one real SMS provider call, so a review send can take as long. */
    public void observeProviderLatency(Duration took) {
        if (!enabled) {
            return;
        }
        long sample = Math.min(took.toNanos(), MAX_PROVIDER_LATENCY_NANOS);
        providerLatencyNanos.accumulateAndGet(sample, (average, next) -> average < 0 ? next : average + (next - average) / 5);
    }

    /**
     * Takes about as long as a real provider call on this instance, so a review send cannot be
     * told apart from any other send by how long it took to answer.
     */
    public void waitLikeAProviderCall() {
        long average = providerLatencyNanos.get();
        long base = average < 0 ? DEFAULT_PROVIDER_LATENCY.toNanos() : average;
        long jittered = (long) (base * ThreadLocalRandom.current().nextDouble(0.75, 1.25));
        try {
            sleeper.sleep(Duration.ofNanos(jittered));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private static String requireCanonicalPhone(String configured, PhoneNumberNormalizer normalizer) {
        if (!StringUtils.hasText(configured)) {
            throw refuse("GUA_REVIEW_LOGIN_PHONE is not set");
        }
        String e164;
        try {
            e164 = normalizer.toE164(configured);
        } catch (InvalidPhoneNumberException ex) {
            throw refuse("GUA_REVIEW_LOGIN_PHONE is not a valid phone number");
        }
        if (!e164.equals(configured)) {
            throw refuse("GUA_REVIEW_LOGIN_PHONE must be written in E.164: a + then the country code and number,"
                    + " with no spaces or punctuation");
        }
        return e164;
    }

    private static String requireCodeHash(String configured) {
        if (!StringUtils.hasText(configured)) {
            throw refuse("GUA_REVIEW_LOGIN_CODE_HASH is not set");
        }
        Matcher bcrypt = BCRYPT.matcher(configured);
        if (!bcrypt.matches()) {
            throw refuse("GUA_REVIEW_LOGIN_CODE_HASH is not a bcrypt hash");
        }
        int cost = Integer.parseInt(bcrypt.group(1));
        if (cost < MIN_COST || cost > MAX_COST) {
            throw refuse("GUA_REVIEW_LOGIN_CODE_HASH uses bcrypt cost " + cost + "; use " + MIN_COST + " to "
                    + MAX_COST);
        }
        return configured;
    }

    /** Never carries the configured values: the message ends up in startup logs. */
    private static IllegalStateException refuse(String reason) {
        return new IllegalStateException("Store review login is enabled but " + reason
                + ". Refusing to start. Set GUA_REVIEW_LOGIN_ENABLED=false to turn it off.");
    }
}
