package me.sarahlacerda.gua.identityservice.controller.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * normalizeLoginHint turns an OIDC login_hint into an E.164 phone (or null). The key case is
 * Bug 1: the '+' of an E.164 hint is routinely lost in transit — '+15551234567' form-decodes to a
 * leading space (then trimmed) or is dropped — so a real number arrives as a bare digit run and
 * must still resolve to "+15551234567" rather than being discarded.
 */
class OidcLoginHintNormalizeTest {

    @ParameterizedTest
    @CsvSource({
        // already a clean E.164 — passed through
        "+15551234567, +15551234567",
        // '+' lost entirely (bare digit run) — restored
        "15551234567, +15551234567",
        // '+' form-decoded to a leading space — restored
        "' 15551234567', +15551234567",
        // phone-style prefixes are unwrapped, then the same restoration applies
        "tel:+15551234567, +15551234567",
        "tel:15551234567, +15551234567",
        "phone:+5511999990000, +5511999990000",
        "msisdn:5511999990000, +5511999990000",
    })
    void normalizesPhoneHints(String input, String expected) {
        assertThat(OidcAuthorizationController.normalizeLoginHint(input)).isEqualTo(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
        "   ",                       // blank
        "@alice:gua.global",         // mxid, not a phone
        "alice@example.com",         // email
        "12345",                     // too short to be a bare E.164 digit run
        "555-123-4567",              // punctuation, not bare digits and no '+'
    })
    void rejectsNonPhoneHints(String input) {
        assertThat(OidcAuthorizationController.normalizeLoginHint(input)).isNull();
    }
}
