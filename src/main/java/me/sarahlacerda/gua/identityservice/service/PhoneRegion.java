package me.sarahlacerda.gua.identityservice.service;

import org.springframework.util.StringUtils;

import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;

/** ISO 3166-1 alpha-2 region of an E.164 phone, the only phone-derived value a metric tag may carry. */
public final class PhoneRegion {

    private PhoneRegion() {
    }

    /** The region, or {@code "unknown"} when the number does not parse or maps to no single region. */
    public static String of(String e164PhoneNumber) {
        if (!StringUtils.hasText(e164PhoneNumber)) {
            return "unknown";
        }
        try {
            PhoneNumberUtil util = PhoneNumberUtil.getInstance();
            String region = util.getRegionCodeForNumber(util.parse(e164PhoneNumber, null));
            return region != null ? region : "unknown";
        } catch (NumberParseException ex) {
            return "unknown";
        }
    }
}
