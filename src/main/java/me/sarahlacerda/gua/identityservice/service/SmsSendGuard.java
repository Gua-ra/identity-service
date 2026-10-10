package me.sarahlacerda.gua.identityservice.service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
 * before the provider: the destination must be a valid number in an allowed region, and the
 * per-address, per-number, hourly and daily counters must all have room.
 *
 * <p>
 * Sends to numbers without an account count against separate sign-up ceilings, so a sign-up
 * flood cannot use up the account ceilings. Unauthenticated sends to numbers that have an
 * account, such as repeated sign-in requests, still count against the account ceilings.
 */
@Component
public class SmsSendGuard {

    static final String IP_KEY_PREFIX = "otp:rate:ip:";
    static final String PHONE_KEY_PREFIX = "otp:rate:phone:";
    static final String SIGN_UP_HOURLY_KEY = "otp:rate:sign-up:hour";
    static final String SIGN_UP_DAILY_KEY = "otp:rate:sign-up:day";
    static final String ACCOUNT_HOURLY_KEY = "otp:rate:account:hour";
    static final String ACCOUNT_DAILY_KEY = "otp:rate:account:day";

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
        SIGN_UP_HOURLY_CEILING("sign_up_hourly_ceiling"),
        SIGN_UP_DAILY_CEILING("sign_up_daily_ceiling"),
        ACCOUNT_HOURLY_CEILING("account_hourly_ceiling"),
        ACCOUNT_DAILY_CEILING("account_daily_ceiling");

        private final String tagValue;

        Refusal(String tagValue) {
            this.tagValue = tagValue;
        }

        public String tagValue() {
            return tagValue;
        }

        boolean isCeiling() {
            return this != COUNTRY && this != IP && this != PHONE;
        }
    }

    private enum Budget {
        SIGN_UP, ACCOUNT, NONE
    }

    private record Counter(String key, int limit, Duration window, Refusal refusal) {
    }

    private final StringRedisTemplate redisTemplate;
    private final IdentityServiceProperties properties;
    private final MeterRegistry metrics;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final Set<String> allowedCountries;

    public SmsSendGuard(StringRedisTemplate redisTemplate, IdentityServiceProperties properties,
            MeterRegistry metrics, DirectoryService directoryService, PhoneNumberHasher phoneNumberHasher) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
        this.metrics = metrics;
        this.directoryService = directoryService;
        this.phoneNumberHasher = phoneNumberHasher;
        this.allowedCountries = allowedCountries(properties.getOtp().getAllowedCountries());
    }

    /**
     * Admits one send to a number that may or may not have an account, and counts it. A number
     * with an account counts against the account ceilings, any other against the sign-up
     * ceilings.
     *
     * @throws InvalidPhoneNumberException      when the number is not a valid phone number
     * @throws UnsupportedPhoneCountryException when its region is not allowed
     * @throws OtpRateLimitedException          when a counter is full, with the wait until the
     *                                          last full one reopens
     */
    public void admit(String phoneNumber, String requesterIp) {
        PhoneNumber parsed = parse(phoneNumber);
        requireAllowedCountry(parsed);
        String e164 = PHONE_NUMBERS.format(parsed, PhoneNumberFormat.E164);
        boolean hasAccount = directoryService.findByDigest(phoneNumberHasher.digest(e164)).isPresent();
        count(e164, requesterIp, hasAccount ? Budget.ACCOUNT : Budget.SIGN_UP);
    }

    /**
     * {@link #admit} for a send a signed-in account asked for, to its own number or to the new
     * number of its phone change. Counted against the account ceilings.
     */
    public void admitForAccount(String phoneNumber, String requesterIp) {
        PhoneNumber parsed = parse(phoneNumber);
        requireAllowedCountry(parsed);
        count(PHONE_NUMBERS.format(parsed, PhoneNumberFormat.E164), requesterIp, Budget.ACCOUNT);
    }

    /**
     * Admits a sign-in that texts nothing, the store review number's. It counts against the
     * per-number and per-address limits only, and needs no allowed region.
     */
    public void admitWithoutSms(String phoneNumber, String requesterIp) {
        count(PHONE_NUMBERS.format(parse(phoneNumber), PhoneNumberFormat.E164), requesterIp, Budget.NONE);
    }

    private void count(String e164, String requesterIp, Budget budget) {
        OtpProperties otp = properties.getOtp();
        List<Counter> counters = new ArrayList<>();
        if (budget == Budget.SIGN_UP) {
            counters.add(new Counter(SIGN_UP_DAILY_KEY, otp.getMaxSignUpSendsPerDay(), DAY,
                    Refusal.SIGN_UP_DAILY_CEILING));
            counters.add(new Counter(SIGN_UP_HOURLY_KEY, otp.getMaxSignUpSendsPerHour(), HOUR,
                    Refusal.SIGN_UP_HOURLY_CEILING));
        } else if (budget == Budget.ACCOUNT) {
            counters.add(new Counter(ACCOUNT_DAILY_KEY, otp.getMaxAccountSendsPerDay(), DAY,
                    Refusal.ACCOUNT_DAILY_CEILING));
            counters.add(new Counter(ACCOUNT_HOURLY_KEY, otp.getMaxAccountSendsPerHour(), HOUR,
                    Refusal.ACCOUNT_HOURLY_CEILING));
        }
        if (StringUtils.hasText(requesterIp)) {
            counters.add(new Counter(IP_KEY_PREFIX + requesterIp, otp.getMaxRequestsPerIpPerHour(), HOUR, Refusal.IP));
        }
        counters.add(new Counter(PHONE_KEY_PREFIX + e164, otp.getMaxRequestsPerPhonePerHour(), HOUR,
                Refusal.PHONE));

        List<String> keys = counters.stream().map(Counter::key).toList();
        Object[] limitsAndWindows = counters.stream()
                .flatMap(counter -> Stream.of(String.valueOf(counter.limit()),
                        String.valueOf(counter.window().toMillis())))
                .toArray();
        long full = Objects.requireNonNull(redisTemplate.execute(ADMIT, keys, limitsAndWindows),
                "SMS send limiter returned no reply");
        if (full == 0L) {
            return;
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
        refused(refusal);
        throw new OtpRateLimitedException(
                refusal.isCeiling() ? "Verification codes are temporarily unavailable" : "Too many OTP requests",
                retryAfter);
    }

    private void requireAllowedCountry(PhoneNumber parsed) {
        String region = PHONE_NUMBERS.getRegionCodeForNumber(parsed);
        if (region == null || !allowedCountries.contains(region)) {
            refused(Refusal.COUNTRY);
            throw new UnsupportedPhoneCountryException("Verification codes cannot be sent to this country");
        }
    }

    private Duration remaining(Counter counter) {
        Long millis = redisTemplate.getExpire(counter.key(), TimeUnit.MILLISECONDS);
        return millis != null && millis > 0 ? Duration.ofMillis(millis) : counter.window();
    }

    private void refused(Refusal refusal) {
        metrics.counter("gua.identity.sms.refused", "reason", refusal.tagValue()).increment();
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

    private static Set<String> allowedCountries(List<String> configured) {
        Set<String> regions = configured.stream()
                .map(region -> region.trim().toUpperCase(Locale.ROOT))
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(TreeSet::new));
        Set<String> unknown = new TreeSet<>(regions);
        unknown.removeAll(PHONE_NUMBERS.getSupportedRegions());
        if (regions.isEmpty() || !unknown.isEmpty()) {
            throw new IllegalStateException("identity.otp.allowed-countries must list ISO 3166-1 alpha-2 regions"
                    + (unknown.isEmpty() ? "" : "; not recognised: " + String.join(",", unknown)));
        }
        return Set.copyOf(regions);
    }
}
