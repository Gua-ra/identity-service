package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.function.BiPredicate;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;
import me.sarahlacerda.gua.identityservice.metrics.OtpVerifyFlow;

@Service
public class OtpService {

    private static final String OTP_KEY_PREFIX = "otp:code:";
    private static final String ATTEMPTS_KEY_PREFIX = "otp:attempts:";
    private static final String PHONE_RATE_KEY_PREFIX = "otp:rate:phone:";
    private static final String IP_RATE_KEY_PREFIX = "otp:rate:ip:";
    /** Which live code a review sign-in issued; see {@link #sendLoginOtp}. */
    private static final String REVIEW_LOGIN_KEY_PREFIX = "otp:review-login:";
    private static final String EXHAUSTED_MESSAGE = "Too many incorrect verification codes; request a new code";

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final OtpCodeGenerator codeGenerator;
    private final SmsSender smsSender;
    private final RateLimiter rateLimiter;
    private final MeterRegistry metrics;
    private final ReviewLogin reviewLogin;
    private final String smsProvider;

    public OtpService(
        StringRedisTemplate redisTemplate,
        IdentityServiceProperties properties,
        OtpCodeGenerator codeGenerator,
        SmsSender smsSender,
        RateLimiter rateLimiter,
        MeterRegistry metrics,
        ReviewLogin reviewLogin
    ) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.codeGenerator = codeGenerator;
        this.smsSender = smsSender;
        this.rateLimiter = rateLimiter;
        this.metrics = metrics;
        this.reviewLogin = reviewLogin;
        // e.g. TwilioSmsSender -> "twilio", LoggingSmsSender -> "logging". Lets the SMS-usage metric
        // distinguish the real provider from the dev logger once real SMS is wired.
        this.smsProvider = SmsSender.providerTag(smsSender);
    }

    public void sendOtp(String e164PhoneNumber, String requesterIp, String language) {
        send(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), e164PhoneNumber, requesterIp, language);
    }

    /**
     * The interactive sign-in's send: {@link #sendOtp} for every number except the store review
     * number ({@link ReviewLogin}). That one gets the same rate limits, a fresh random code under
     * the same key with the same TTL and a fresh guess budget, takes about as long as a real send,
     * and texts nothing. The random code is what every other reader of the per-phone key sees, so
     * reauthentication and the REST sign-in still need a code nobody was sent.
     */
    public void sendLoginOtp(String e164PhoneNumber, String requesterIp, String language) {
        if (!reviewLogin.isReviewNumber(e164PhoneNumber)) {
            sendOtp(e164PhoneNumber, requesterIp, language);
            return;
        }
        try {
            enforceRateLimits(e164PhoneNumber, requesterIp);
        } catch (OtpRateLimitedException ex) {
            reviewLogin.record(e164PhoneNumber, ReviewLogin.Outcome.SEND_RATE_LIMITED);
            throw ex;
        }
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        storeFreshCode(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code);
        // Binds the review code to this code alone: any later send replaces the code and so ends it.
        redisTemplate.opsForValue().set(reviewLoginKey(e164PhoneNumber), code, properties.getOtp().getTtl());
        reviewLogin.waitLikeAProviderCall();
        reviewLogin.record(e164PhoneNumber, ReviewLogin.Outcome.SENT);
    }

    /**
     * The interactive sign-in's verify: {@link #verifyOtp} for every number except the store review
     * number, which, while its live code is the one {@link #sendLoginOtp} issued, is compared
     * against the review code instead. Same guess cap, expiry and burn as any other code.
     *
     * <p>
     * The review code is checked with bcrypt, which takes tens to hundreds of milliseconds, so
     * while the review login is on every comparison made here, for any number, pays for exactly
     * one bcrypt check. A wrong guess then answers in the same time whichever number it is for.
     */
    public void verifyLoginOtp(String e164PhoneNumber, String code) {
        if (!reviewLogin.isReviewNumber(e164PhoneNumber)) {
            verify(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code, OtpVerifyFlow.PHONE,
                    this::matchesAfterAReviewCodeCheck);
            return;
        }
        String bindingKey = reviewLoginKey(e164PhoneNumber);
        ReviewLoginCheck check = new ReviewLoginCheck(bindingKey);
        try {
            verify(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code, OtpVerifyFlow.PHONE, check);
        } catch (InvalidOtpException ex) {
            ReviewLogin.Outcome outcome = EXHAUSTED_MESSAGE.equals(ex.getMessage()) ? ReviewLogin.Outcome.EXHAUSTED
                    : check.compared ? ReviewLogin.Outcome.REJECTED : ReviewLogin.Outcome.NO_CODE;
            if (outcome == ReviewLogin.Outcome.EXHAUSTED) {
                redisTemplate.delete(bindingKey);
            }
            reviewLogin.record(e164PhoneNumber, outcome);
            throw ex;
        }
        redisTemplate.delete(bindingKey);
        reviewLogin.record(e164PhoneNumber, ReviewLogin.Outcome.ACCEPTED);
    }

    /**
     * Sends an OTP that belongs to one flow instead of to a phone number: the code is
     * written under {@code otp:code:{scope}:{scopeId}}, which the unauthenticated
     * {@code POST /otp/send} cannot write, so it can neither plant a code there ahead of
     * the flow nor have one of its own codes accepted by it. Everything else is the same
     * as {@link #sendOtp}: the same per-phone and per-IP send limits, the same code
     * length and TTL, the same SMS metrics, and the same fresh guess budget per code.
     */
    public void sendScopedOtp(OtpScope scope, String scopeId, String e164PhoneNumber, String requesterIp,
            String language) {
        send(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), e164PhoneNumber, requesterIp, language);
    }

    /** Redeems a scoped code under the same per-code guess cap as {@link #verifyOtp}. */
    public void verifyScopedOtp(OtpScope scope, String scopeId, String code) {
        verify(scopedCodeKey(scope, scopeId), scopedAttemptsKey(scope, scopeId), code, scope.verifyFlow(),
                OtpCodes::matches);
    }

    /**
     * Destroys a scoped code and its guess counter, for a flow that is abandoning the
     * challenge the code belonged to.
     */
    public void discardScopedOtp(OtpScope scope, String scopeId) {
        redisTemplate.delete(scopedCodeKey(scope, scopeId));
        redisTemplate.delete(scopedAttemptsKey(scope, scopeId));
    }

    private void send(String codeKey, String attemptsKey, String e164PhoneNumber, String requesterIp,
            String language) {
        enforceRateLimits(e164PhoneNumber, requesterIp);
        String code = codeGenerator.generateNumericCode(properties.getOtp().getCodeLength());
        String messageBody = SmsTemplates.forLanguage(properties.getOtp(), language).formatted(code);

        storeFreshCode(codeKey, attemptsKey, code);
        long started = System.nanoTime();
        try {
            smsSender.send(e164PhoneNumber, messageBody);
            reviewLogin.observeProviderLatency(Duration.ofNanos(System.nanoTime() - started));
            // gua_identity_sms_send_total{provider,result} — SMS usage + delivery failures.
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "sent").increment();
        } catch (RuntimeException ex) {
            metrics.counter("gua.identity.sms.send", "provider", smsProvider, "result", "failed").increment();
            throw ex;
        }
    }

    private void storeFreshCode(String codeKey, String attemptsKey, String code) {
        // A fresh code starts with a fresh guess budget.
        redisTemplate.delete(attemptsKey);
        redisTemplate.opsForValue().set(codeKey, code, properties.getOtp().getTtl());
    }

    /**
     * Redeems {@code code} for the phone's live OTP. Every guess is counted per code
     * in Redis before it is compared, so at most {@code identity.otp.max-verify-attempts}
     * guesses are ever compared against one code, however they are spread across
     * addresses and paths or fired in parallel: the count is an atomic INCR, the last
     * allowed guess deletes the code when it is wrong, and a guess whose count overtook
     * the cap is refused without being looked at. The spent counter is left to expire
     * with the code's TTL so a late guess cannot reopen the budget; only a new send,
     * which resets the counter, restores the code. The endpoint limiters bound how
     * fast one address can guess, this bounds how many guesses a code can absorb at all.
     */
    public void verifyOtp(String e164PhoneNumber, String code) {
        verify(codeKey(e164PhoneNumber), attemptsKey(e164PhoneNumber), code, OtpVerifyFlow.PHONE, OtpCodes::matches);
    }

    private void verify(String codeKey, String attemptsKey, String code, OtpVerifyFlow flow,
            BiPredicate<String, String> matches) {
        String storedCode = redisTemplate.opsForValue().get(codeKey);
        if (!StringUtils.hasText(storedCode)) {
            // gua_identity_otp_verify_total{result} — wrong/expired codes (auth friction / abuse signal).
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", flow.tagValue()).increment();
            throw new InvalidOtpException("Invalid or expired verification code");
        }
        long attempts = countGuess(codeKey, attemptsKey);
        int maxAttempts = properties.getOtp().getMaxVerifyAttempts();
        if (attempts > maxAttempts) {
            // A parallel guess spent the last slot between this one's GET and INCR.
            throw exhausted(codeKey, flow);
        }
        if (!matches.test(storedCode, code)) {
            metrics.counter("gua.identity.otp.verify", "result", "invalid", "flow", flow.tagValue()).increment();
            if (attempts < maxAttempts) {
                throw new InvalidOtpException("Invalid or expired verification code");
            }
            throw exhausted(codeKey, flow);
        }
        redisTemplate.delete(codeKey);
        redisTemplate.delete(attemptsKey);
        metrics.counter("gua.identity.otp.verify", "result", "valid", "flow", flow.tagValue()).increment();
    }

    private long countGuess(String codeKey, String attemptsKey) {
        Long counted = redisTemplate.opsForValue().increment(attemptsKey);
        // The counter never outlives the code it guards.
        redisTemplate.expire(attemptsKey, remainingTtl(codeKey));
        return counted == null ? 1L : counted;
    }

    private InvalidOtpException exhausted(String codeKey, OtpVerifyFlow flow) {
        // Only the code goes. Deleting the counter too would hand a guess that fetched the
        // code before the cap tripped a fresh budget starting at 1.
        redisTemplate.delete(codeKey);
        // gua_identity_otp_verify_total{result="exhausted"}: guesses refused by the cap (brute-force signal).
        metrics.counter("gua.identity.otp.verify", "result", "exhausted", "flow", flow.tagValue()).increment();
        return new InvalidOtpException(EXHAUSTED_MESSAGE);
    }

    private Duration remainingTtl(String codeKey) {
        Long seconds = redisTemplate.getExpire(codeKey);
        return seconds != null && seconds > 0 ? Duration.ofSeconds(seconds) : properties.getOtp().getTtl();
    }

    private static String codeKey(String e164PhoneNumber) {
        return OTP_KEY_PREFIX + e164PhoneNumber;
    }

    private static String attemptsKey(String e164PhoneNumber) {
        return ATTEMPTS_KEY_PREFIX + e164PhoneNumber;
    }

    private static String reviewLoginKey(String e164PhoneNumber) {
        return REVIEW_LOGIN_KEY_PREFIX + e164PhoneNumber;
    }

    private static String scopedCodeKey(OtpScope scope, String scopeId) {
        return OTP_KEY_PREFIX + scope.keySegment() + ":" + scopeId;
    }

    private static String scopedAttemptsKey(OtpScope scope, String scopeId) {
        return ATTEMPTS_KEY_PREFIX + scope.keySegment() + ":" + scopeId;
    }

    private void enforceRateLimits(String e164PhoneNumber, String requesterIp) {
        Duration window = Duration.ofHours(1);
        try {
            rateLimiter.checkRate(PHONE_RATE_KEY_PREFIX + e164PhoneNumber, properties.getOtp().getMaxRequestsPerPhonePerHour(), window);
            if (StringUtils.hasText(requesterIp)) {
                rateLimiter.checkRate(IP_RATE_KEY_PREFIX + requesterIp, properties.getOtp().getMaxRequestsPerIpPerHour(), window);
            }
        } catch (RateLimiterException ex) {
            throw new OtpRateLimitedException("Too many OTP requests", ex);
        }
    }

    /**
     * A sign-in comparison against a live code: the plain one, after the bcrypt check the review
     * code's comparison costs, so it takes as long. No bcrypt while the review login is off.
     */
    private boolean matchesAfterAReviewCodeCheck(String storedCode, String submitted) {
        reviewLogin.spendAReviewCodeCheck(submitted);
        return OtpCodes.matches(storedCode, submitted);
    }

    /**
     * The review number's comparison: the review code while the live code is the one a review
     * sign-in issued, the live code itself otherwise (a code another flow texted to the number).
     * Either way one bcrypt check, like every other sign-in comparison.
     */
    private final class ReviewLoginCheck implements BiPredicate<String, String> {

        private final String bindingKey;
        private boolean compared;

        ReviewLoginCheck(String bindingKey) {
            this.bindingKey = bindingKey;
        }

        @Override
        public boolean test(String storedCode, String submitted) {
            compared = true;
            String issuedForReview = redisTemplate.opsForValue().get(bindingKey);
            if (issuedForReview != null && OtpCodes.matches(issuedForReview, storedCode)) {
                return reviewLogin.matchesReviewCode(submitted);
            }
            return matchesAfterAReviewCodeCheck(storedCode, submitted);
        }
    }
}
