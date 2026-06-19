package me.sarahlacerda.gua.identityservice.config;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * Pins {@code IDENTITY_DIRECTORY_PEPPER} against silent rotation / environment
 * drift.
 *
 * <p>
 * The directory pepper is the HMAC key for every phone digest in
 * {@code PhoneNumberHasher}. It is an <em>immutable, backed-up</em> secret:
 * changing it re-keys every digest, so the existing directory rows can no longer
 * be found and returning users are wrongly routed into signup (the
 * duplicate-account half of the identity-reset loop). A rotation is therefore a
 * data-corruption event, not a credential refresh.
 *
 * <p>
 * To catch an accidental rotation loudly, an operator records the live pepper's
 * <em>fingerprint</em> in {@code identity.directory.pepper-fingerprint}. On
 * startup this validator recomputes the fingerprint of the configured pepper and
 * {@linkplain IllegalStateException fails fast} if it differs from the pinned
 * value. The fingerprint is a one-way HMAC over a fixed, non-secret label keyed
 * by the pepper, so it never reveals the pepper and is safe to store in config.
 *
 * <p>
 * When no fingerprint is pinned (e.g. local dev) the validator only logs the
 * computed fingerprint at WARN so an operator can copy it into the deployment
 * config. It never hardcodes or logs the pepper itself.
 */
@Component
public class DirectoryPepperPinValidator {

    private static final Logger log = LoggerFactory.getLogger(DirectoryPepperPinValidator.class);

    /**
     * Fixed, non-secret label HMAC'd with the pepper to derive a stable,
     * non-reversible fingerprint. Changing this string changes every fingerprint,
     * so it must remain constant across releases.
     */
    private static final String FINGERPRINT_LABEL = "gua.identity.directory.pepper.fingerprint.v1";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final IdentityServiceProperties properties;

    public DirectoryPepperPinValidator(IdentityServiceProperties properties) {
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void verifyPepperPin() {
        String pepper = properties.getDirectory().getPepper();
        String expected = properties.getDirectory().getPepperFingerprint();
        String actual = fingerprint(pepper);

        if (expected == null || expected.isBlank()) {
            log.warn("identity.directory.pepper-fingerprint is not pinned. The directory pepper is an immutable, "
                    + "backed-up secret: rotating it orphans every existing account. Pin this fingerprint in the "
                    + "deployment config to fail fast on accidental rotation: identity.directory.pepper-fingerprint={}",
                    actual);
            return;
        }

        if (!constantTimeEquals(expected.trim().toLowerCase(), actual)) {
            throw new IllegalStateException(
                    "IDENTITY_DIRECTORY_PEPPER does not match the pinned identity.directory.pepper-fingerprint. "
                            + "The directory pepper appears to have been rotated or drifted, which orphans every "
                            + "existing directory row and would mint duplicate accounts for returning users. Refusing "
                            + "to start. Restore the original pepper, or — only if this rotation is intentional and "
                            + "the directory has been re-keyed — update the pinned fingerprint to: " + actual);
        }

        log.info("Directory pepper fingerprint matches the pinned value; pepper integrity verified.");
    }

    private static String fingerprint(String pepper) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] digest = mac.doFinal(FINGERPRINT_LABEL.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to compute directory pepper fingerprint", ex);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
