package me.sarahlacerda.gua.identityservice.service.security;

import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.WeakPinException;

/**
 * Single source of truth for account-PIN (two-step verification) strength rules.
 *
 * <p>A PIN must be exactly six digits and must not be trivially guessable. The
 * rules follow NIST SP 800-63B guidance, which requires rejecting values that
 * are sequential, repetitive, or known to be commonly chosen. The same checks
 * are mirrored (best-effort, for instant feedback) in the clients, but this
 * server-side policy is authoritative.
 */
@Component
public class PinPolicy {

    /** Exactly six digits. Keep in sync with the client-side checks. */
    public static final int PIN_LENGTH = 6;

    private static final Pattern SIX_DIGITS = Pattern.compile("\\d{" + PIN_LENGTH + "}");

    /**
     * Curated denylist of the most commonly chosen 6-digit PINs that are NOT
     * already caught by the structural (sequential / repeated) checks below.
     * Derived from published breach analyses of numeric PIN frequency.
     */
    private static final Set<String> COMMON_PINS = Set.of(
            "123123", "121212", "123321", "112233", "123654", "159753",
            "147258", "159357", "753951", "357159", "142536", "789456",
            "456789", "696969", "777777", "131313", "101010", "102030",
            "201020", "232323", "456123", "987654", "654321", "212121",
            "120120", "110110", "100100", "808080", "520520", "999999",
            "888888");

    /**
     * Validates a candidate PIN's format and strength.
     *
     * @throws InvalidPinException when the PIN is missing, not six digits, or too weak
     */
    public void validate(String pin) {
        if (!StringUtils.hasText(pin) || !SIX_DIGITS.matcher(pin).matches()) {
            throw new InvalidPinException("PIN must be a 6-digit numeric value");
        }
        if (isRepeated(pin)) {
            throw new WeakPinException("PIN is too weak: avoid repeating the same digit");
        }
        if (isSequential(pin)) {
            throw new WeakPinException("PIN is too weak: avoid sequential digits");
        }
        if (COMMON_PINS.contains(pin)) {
            throw new WeakPinException("PIN is too common: please choose a less predictable PIN");
        }
    }

    /** True when every digit is identical (e.g. 000000, 111111). */
    private boolean isRepeated(String pin) {
        char first = pin.charAt(0);
        for (int i = 1; i < pin.length(); i++) {
            if (pin.charAt(i) != first) {
                return false;
            }
        }
        return true;
    }

    /**
     * True when the digits form a strictly ascending or descending run with a
     * constant step of 1 (e.g. 123456, 654321).
     */
    private boolean isSequential(String pin) {
        boolean ascending = true;
        boolean descending = true;
        for (int i = 1; i < pin.length(); i++) {
            int delta = pin.charAt(i) - pin.charAt(i - 1);
            if (delta != 1) {
                ascending = false;
            }
            if (delta != -1) {
                descending = false;
            }
        }
        return ascending || descending;
    }
}
