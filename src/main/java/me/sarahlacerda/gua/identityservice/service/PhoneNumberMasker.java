package me.sarahlacerda.gua.identityservice.service;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Produces a display-only mask of an E.164 phone number that reveals only the last four digits
 * (e.g. {@code +15551234567 -> ••••4567}). The mask is not reversible; it lets users recognise which
 * phone is linked without the service storing the raw value.
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
