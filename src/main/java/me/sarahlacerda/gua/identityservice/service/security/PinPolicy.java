package me.sarahlacerda.gua.identityservice.service.security;

import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.WeakPinException;

@Component
public class PinPolicy {

    /** Keep in sync with the client-side checks. */
    public static final int PIN_LENGTH = 6;

    private static final Pattern SIX_DIGITS = Pattern.compile("\\d{" + PIN_LENGTH + "}");

    /** Common PINs not already caught by the sequential and repeated checks. */
    private static final Set<String> COMMON_PINS = Set.of(
            "123123", "121212", "123321", "112233", "123654", "159753",
            "147258", "159357", "753951", "357159", "142536", "789456",
            "456789", "696969", "777777", "131313", "101010", "102030",
            "201020", "232323", "456123", "987654", "654321", "212121",
            "120120", "110110", "100100", "808080", "520520", "999999",
            "888888");

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

    private boolean isRepeated(String pin) {
        char first = pin.charAt(0);
        for (int i = 1; i < pin.length(); i++) {
            if (pin.charAt(i) != first) {
                return false;
            }
        }
        return true;
    }

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
