package me.sarahlacerda.gua.identityservice.config;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

class DirectoryPepperPinValidatorTest {

    private IdentityServiceProperties propertiesWith(String pepper, String pinnedFingerprint) {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getDirectory().setPepper(pepper);
        properties.getDirectory().setPepperFingerprint(pinnedFingerprint);
        return properties;
    }

    private String fingerprintOf(String pepper) throws Exception {
        // Use the validator itself (unpinned) to surface the canonical fingerprint by
        // reflection so the test never hardcodes a derived value.
        Method m = DirectoryPepperPinValidator.class.getDeclaredMethod("fingerprint", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, pepper);
    }

    @Test
    void startsWhenNoFingerprintIsPinned() {
        DirectoryPepperPinValidator validator =
                new DirectoryPepperPinValidator(propertiesWith("dev-pepper", ""));

        assertThatCode(validator::verifyPepperPin).doesNotThrowAnyException();
    }

    @Test
    void startsWhenPinnedFingerprintMatches() throws Exception {
        String pepper = "live-pepper-value";
        DirectoryPepperPinValidator validator =
                new DirectoryPepperPinValidator(propertiesWith(pepper, fingerprintOf(pepper)));

        assertThatCode(validator::verifyPepperPin).doesNotThrowAnyException();
    }

    @Test
    void failsFastWhenPepperRotatedAwayFromPinnedFingerprint() throws Exception {
        String pinnedFor = fingerprintOf("the-original-pepper");
        // Service is now configured with a DIFFERENT (rotated/drifted) pepper.
        DirectoryPepperPinValidator validator =
                new DirectoryPepperPinValidator(propertiesWith("a-rotated-pepper", pinnedFor));

        assertThatThrownBy(validator::verifyPepperPin)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("IDENTITY_DIRECTORY_PEPPER");
    }
}
