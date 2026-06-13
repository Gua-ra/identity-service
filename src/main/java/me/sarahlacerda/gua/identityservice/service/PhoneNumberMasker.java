package me.sarahlacerda.gua.identityservice.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Produces a privacy-preserving, display-only mask of an E.164 phone number
 * that
 * reveals only the last four digits (e.g. {@code +15551234567 -> ••••4567}).
 *
 * <p>
 * The mask is intentionally NOT reversible to the full number; it exists so
 * users can recognise which phone is linked to their account without the
 * service
 * having to store the raw value.
 */
@Component
public class PhoneNumberMasker {

    private static final String BULLETS = "\u2022\u2022\u2022\u2022";
    private static final int VISIBLE_DIGITS = 4;

    /**
     * Returns a masked representation revealing the last {@value #VISIBLE_DIGITS}
     * characters, or {@code null} when the input is blank or too short to mask
     * safely.
     */
    public String mask(String phone) {
        if (!StringUtils.hasText(phone) || phone.length() < VISIBLE_DIGITS) {
            return null;
        }
        return BULLETS + phone.substring(phone.length() - VISIBLE_DIGITS);
    }
}
