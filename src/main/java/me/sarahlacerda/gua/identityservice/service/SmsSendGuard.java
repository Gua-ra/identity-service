package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.PhoneNumberUtil.PhoneNumberFormat;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;

import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.OtpProperties;
import me.sarahlacerda.gua.identityservice.exception.InvalidPhoneNumberException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.exception.UnsupportedPhoneCountryException;

/**
 * Decides whether one SMS may be sent. Every path that texts a code calls one of the admit methods
 * before the provider: the destination must be a valid number, in an allowed region when an
 * allowlist is configured, and the per-address and per-number counters, and the hourly and daily
 * ceilings that are configured, must all have room. A daily per-number limit, when configured,
 * also bounds how many codes one phone can be sent once each hourly window reopens. A daily
 * per-region limit, when configured for the destination's region, bounds the spend on regions
 * whose SMS cost much more than the rest.
 *
 * <p>
 * Sends to numbers without an account count against separate sign-up ceilings, so a sign-up
 * flood cannot use up the account ceilings. Unauthenticated sends to numbers that have an
 * account, such as repeated sign-in requests, still count against the account ceilings.
 *
 * <p>
 * A send the provider refuses texted nothing, so {@link #refund} gives back every counter its
 * {@link Admission} charged.
 *
 * <p>
 * Every admitted send that texts a code is counted by the region of its destination in
 * {@code gua_identity_sms_admitted_total{country,budget}}. A send the provider accepts and later
 * reports as undelivered is still counted there, so the count shows where codes were requested.
 *
 * <p>
 * Every admitted or refused send is also logged in logfmt with its region, dialling code, last four
 * digits and requesting address.
 */
@Component
public class SmsSendGuard {

    private static final Logger log = LoggerFactory.getLogger(SmsSendGuard.class);

    static final String IP_KEY_PREFIX = "otp:rate:ip:";
    static final String PHONE_KEY_PREFIX = "otp:rate:phone:";
    static final String PHONE_DAILY_KEY_PREFIX = "otp:rate:phone-day:";
    static final String SIGN_UP_HOURLY_KEY = "otp:rate:sign-up:hour";
    static final String SIGN_UP_DAILY_KEY = "otp:rate:sign-up:day";
    static final String ACCOUNT_HOURLY_KEY = "otp:rate:account:hour";
    static final String ACCOUNT_DAILY_KEY = "otp:rate:account:day";
    static final String COUNTRY_DAILY_KEY_PREFIX = "otp:rate:country-day:";

    private static final Duration HOUR = Duration.ofHours(1);
    private static final Duration DAY = Duration.ofDays(1);
    private static final PhoneNumberUtil PHONE_NUMBERS = PhoneNumberUtil.getInstance();

    /**
     * KEYS are counters and ARGV holds each one's limit and window in milliseconds. Every counter
     * is read before any is incremented, so a refused send spends no budget. Returns 0 when the
     * send is admitted, otherwise a bitmask of the counters that are full.
     */
    private static final RedisScript<Long> ADMIT = new DefaultRedisScript<>("""
            local full = 0
            local bit = 1
            for i = 1, #KEYS do
              if tonumber(redis.call('GET', KEYS[i]) or '0') >= tonumber(ARGV[2 * i - 1]) then
                full = full + bit
              end
              bit = bit * 2
            end
            if full > 0 then
              return full
            end
            for i = 1, #KEYS do
              if redis.call('INCR', KEYS[i]) == 1 or redis.call('PTTL', KEYS[i]) == -1 then
                redis.call('PEXPIRE', KEYS[i], ARGV[2 * i])
              end
            end
            return 0
            """, Long.class);

    /** Tag values of {@code gua_identity_sms_refused_total{reason}}. */
    public enum Refusal {
        COUNTRY("country"),
        IP("ip"),
        PHONE("phone"),
        PHONE_DAILY("phone_daily"),
        SIGN_UP_HOURLY_CEILING("sign_up_hourly_ceiling"),
        SIGN_UP_DAILY_CEILING("sign_up_daily_ceiling"),
        ACCOUNT_HOURLY_CEILING("account_hourly_ceiling"),
        ACCOUNT_DAILY_CEILING("account_daily_ceiling"),
        COUNTRY_DAILY_CEILING("country_daily_ceiling");

        private final String tagValue;

        Refusal(String tagValue) {
            this.tagValue = tagValue;
        }

        public String tagValue() {
            return tagValue;
        }

        boolean isCeiling() {
            return this != COUNTRY && this != IP && this != PHONE && this != PHONE_DAILY;
        }
    }

    /** The counters one admitted send charged, for {@link #refund}. */
    public record Admission(List<String> keys) {

        public Admission {
            keys = List.copyOf(keys);
        }
    }

    private enum Budget {
        SIGN_UP("sign_up"), ACCOUNT("account"), NONE("none");

        private final String tagValue;

        Budget(String tagValue) {
            this.tagValue = tagValue;
        }
    }

    private record Counter(String key, int limit, Duration window, Refusal refusal) {
    }

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final MeterRegistry metrics;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final RateLimiter rateLimiter;
    private final PhoneNumberMasker masker;
    private final Set<String> allowedCountries;
    private final Map<String, Integer> countryDailyLimits;

    public SmsSendGuard(StringRedisTemplate redisTemplate, IdentityServiceProperties properties,
            MeterRegistry metrics, DirectoryService directoryService, PhoneNumberHasher phoneNumberHasher,
            RateLimiter rateLimiter, PhoneNumberMasker masker) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.metrics = metrics;
        this.directoryService = directoryService;
        this.phoneNumberHasher = phoneNumberHasher;
        this.rateLimiter = rateLimiter;
        this.masker = masker;
        this.allowedCountries = allowedCountries(properties.getOtp().getAllowedCountries());
        this.countryDailyLimits = countryDailyLimits(properties.getOtp().getCountryDailyLimits());
    }

    /**
     * Admits one send to a number that may or may not have an account, and counts it. A number
     * with an account counts against the account ceilings, any other against the sign-up
     * ceilings.
     *
     * @return the counters the send charged
     * @throws InvalidPhoneNumberException      when the number is not a valid phone number
     * @throws UnsupportedPhoneCountryException when its region is not allowed
     * @throws OtpRateLimitedException          when a counter is full, with the wait until the
     *                                          last full one reopens
     */
    public Admission admit(String phoneNumber, String requesterIp) {
        PhoneNumber parsed = parse(phoneNumber);
        String e164 = PHONE_NUMBERS.format(parsed, PhoneNumberFormat.E164);
        requireAllowedCountry(parsed, e164, requesterIp);
        boolean hasAccount = directoryService.findByDigest(phoneNumberHasher.digest(e164)).isPresent();
        return count(e164, region(parsed), requesterIp, hasAccount ? Budget.ACCOUNT : Budget.SIGN_UP);
    }

    /**
     * {@link #admit} for a send a signed-in account asked for, to its own number or to the new
     * number of its phone change. Counted against the account ceilings.
     */
    public Admission admitForAccount(String phoneNumber, String requesterIp) {
        PhoneNumber parsed = parse(phoneNumber);
        String e164 = PHONE_NUMBERS.format(parsed, PhoneNumberFormat.E164);
        requireAllowedCountry(parsed, e164, requesterIp);
        return count(e164, region(parsed), requesterIp, Budget.ACCOUNT);
    }

    /**
     * Admits a sign-in that texts nothing, the store review number's. It counts against the hourly
     * per-number and per-address limits only, and needs no allowed region.
     */
    public void admitWithoutSms(String phoneNumber, String requesterIp) {
        PhoneNumber parsed = parse(phoneNumber);
        count(PHONE_NUMBERS.format(parsed, PhoneNumberFormat.E164), region(parsed), requesterIp, Budget.NONE);
    }

    /**
     * Gives back every counter {@code admission} charged, for a send the provider refused. Each
     * counter keeps its window. Best effort, like {@link RateLimiter#refund}.
     */
    public void refund(Admission admission) {
        admission.keys().forEach(rateLimiter::refund);
    }

    private Admission count(String e164, String region, String requesterIp, Budget budget) {
        OtpProperties otp = properties.getOtp();
        List<Counter> counters = new ArrayList<>();
        if (budget == Budget.SIGN_UP) {
            addCeiling(counters, SIGN_UP_DAILY_KEY, otp.getMaxSignUpSendsPerDay(), DAY,
                    Refusal.SIGN_UP_DAILY_CEILING);
            addCeiling(counters, SIGN_UP_HOURLY_KEY, otp.getMaxSignUpSendsPerHour(), HOUR,
                    Refusal.SIGN_UP_HOURLY_CEILING);
        } else if (budget == Budget.ACCOUNT) {
            addCeiling(counters, ACCOUNT_DAILY_KEY, otp.getMaxAccountSendsPerDay(), DAY,
                    Refusal.ACCOUNT_DAILY_CEILING);
            addCeiling(counters, ACCOUNT_HOURLY_KEY, otp.getMaxAccountSendsPerHour(), HOUR,
                    Refusal.ACCOUNT_HOURLY_CEILING);
        }
        Integer countryDailyLimit = countryDailyLimits.get(region);
        if (budget != Budget.NONE && countryDailyLimit != null) {
            counters.add(new Counter(COUNTRY_DAILY_KEY_PREFIX + region, countryDailyLimit, DAY,
                    Refusal.COUNTRY_DAILY_CEILING));
        }
        if (StringUtils.hasText(requesterIp)) {
            counters.add(new Counter(IP_KEY_PREFIX + requesterIp, otp.getMaxRequestsPerIpPerHour(), HOUR, Refusal.IP));
        }
        counters.add(new Counter(PHONE_KEY_PREFIX + e164, otp.getMaxRequestsPerPhonePerHour(), HOUR,
                Refusal.PHONE));
        if (budget != Budget.NONE) {
            addCeiling(counters, PHONE_DAILY_KEY_PREFIX + e164, otp.getMaxRequestsPerPhonePerDay(), DAY,
                    Refusal.PHONE_DAILY);
        }

        List<String> keys = counters.stream().map(Counter::key).toList();
        Object[] limitsAndWindows = counters.stream()
                .flatMap(counter -> Stream.of(String.valueOf(counter.limit()),
                        String.valueOf(counter.window().toMillis())))
                .toArray();
        long full = Objects.requireNonNull(redisTemplate.execute(ADMIT, keys, limitsAndWindows),
                "SMS send limiter returned no reply");
        if (full == 0L) {
            if (budget != Budget.NONE) {
                metrics.counter("gua.identity.sms.admitted", "country", region, "budget", budget.tagValue)
                        .increment();
                log.info("sms_admit outcome=admitted country={} budget={} phone={} ip={}", region,
                        budget.tagValue, masker.maskWithDialCode(e164), requesterIp);
            }
            return new Admission(keys);
        }

        Refusal refusal = null;
        Duration retryAfter = Duration.ZERO;
        for (int i = 0; i < counters.size(); i++) {
            if ((full & (1L << i)) == 0) {
                continue;
            }
            Counter counter = counters.get(i);
            if (refusal == null) {
                refusal = counter.refusal();
            }
            Duration remaining = remaining(counter);
            if (remaining.compareTo(retryAfter) > 0) {
                retryAfter = remaining;
            }
        }
        refused(refusal, region, e164, requesterIp);
        throw new OtpRateLimitedException(
                refusal.isCeiling() ? "Verification codes are temporarily unavailable" : "Too many OTP requests",
                retryAfter);
    }

    /** A limit of 0 is not configured: it is neither counted nor checked. */
    private static void addCeiling(List<Counter> counters, String key, int limit, Duration window, Refusal refusal) {
        if (limit > 0) {
            counters.add(new Counter(key, limit, window, refusal));
        }
    }

    private void requireAllowedCountry(PhoneNumber parsed, String e164, String requesterIp) {
        if (allowedCountries.isEmpty()) {
            return;
        }
        String region = PHONE_NUMBERS.getRegionCodeForNumber(parsed);
        if (region == null || !allowedCountries.contains(region)) {
            refused(Refusal.COUNTRY, region(parsed), e164, requesterIp);
            throw new UnsupportedPhoneCountryException("Verification codes cannot be sent to this country");
        }
    }

    private Duration remaining(Counter counter) {
        Long millis = redisTemplate.getExpire(counter.key(), TimeUnit.MILLISECONDS);
        return millis != null && millis > 0 ? Duration.ofMillis(millis) : counter.window();
    }

    /** The number's own region, or {@code "unknown"} for a number that maps to none. */
    private static String region(PhoneNumber parsed) {
        String region = PHONE_NUMBERS.getRegionCodeForNumber(parsed);
        return region != null ? region : "unknown";
    }

    private void refused(Refusal refusal, String region, String e164, String requesterIp) {
        metrics.counter("gua.identity.sms.refused", "reason", refusal.tagValue()).increment();
        log.info("sms_admit outcome=refused reason={} country={} phone={} ip={}", refusal.tagValue(), region,
                masker.maskWithDialCode(e164), requesterIp);
    }

    private static PhoneNumber parse(String phoneNumber) {
        PhoneNumber parsed;
        try {
            parsed = PHONE_NUMBERS.parse(phoneNumber, null);
        } catch (NumberParseException ex) {
            throw new InvalidPhoneNumberException("Phone number is not valid");
        }
        if (!PHONE_NUMBERS.isValidNumber(parsed)) {
            throw new InvalidPhoneNumberException("Phone number is not valid");
        }
        return parsed;
    }

    /** The configured regions, upper-cased; empty means every region. */
    private static Set<String> allowedCountries(List<String> configured) {
        if (configured == null) {
            return Set.of();
        }
        Set<String> regions = configured.stream()
                .filter(StringUtils::hasText)
                .map(region -> region.trim().toUpperCase(Locale.ROOT))
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> unknown = new TreeSet<>(regions);
        unknown.removeAll(PHONE_NUMBERS.getSupportedRegions());
        if (!unknown.isEmpty()) {
            throw new IllegalStateException("identity.otp.allowed-countries must list ISO 3166-1 alpha-2 regions"
                    + "; not recognised: " + String.join(",", unknown));
        }
        return Set.copyOf(regions);
    }

    /** The configured {@code REGION:LIMIT} entries, by upper-cased region; empty means no region is limited. */
    private static Map<String, Integer> countryDailyLimits(List<String> configured) {
        if (configured == null) {
            return Map.of();
        }
        Map<String, Integer> limits = new TreeMap<>();
        Set<String> unrecognised = new TreeSet<>();
        for (String entry : configured) {
            if (!StringUtils.hasText(entry)) {
                continue;
            }
            String[] parts = entry.split(":", -1);
            String region = parts[0].trim().toUpperCase(Locale.ROOT);
            Integer limit = parts.length == 2 ? positiveInt(parts[1].trim()) : null;
            if (limit == null || !PHONE_NUMBERS.getSupportedRegions().contains(region)
                    || limits.putIfAbsent(region, limit) != null) {
                unrecognised.add(entry.trim());
            }
        }
        if (!unrecognised.isEmpty()) {
            throw new IllegalStateException("identity.otp.country-daily-limits must list REGION:LIMIT entries"
                    + " with an ISO 3166-1 alpha-2 region, once each, and a limit of at least 1; not recognised: "
                    + String.join(",", unrecognised));
        }
        return Map.copyOf(limits);
    }

    private static Integer positiveInt(String value) {
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
