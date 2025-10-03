package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Computes a deterministic, secret-keyed digest (HMAC-SHA256) of E.164-formatted phone numbers.
 * <p>
 * The digest is produced using a server-side pepper from {@link IdentityServiceProperties.DirectoryProperties}
 * so that the same phone number always yields the same digest for a given pepper, while the raw number
 * never needs to be stored or compared directly.
 * <p>
 * This component is thread-safe and efficient: it caches a per-thread {@link Mac} instance using {@link ThreadLocal},
 * since {@link Mac} is not thread-safe and relatively expensive to initialize.
 */
@Component
public class PhoneNumberHasher {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final IdentityServiceProperties properties;
    private final ThreadLocal<Mac> macSupplier;

    /**
     * Constructs a hasher using application properties to retrieve the secret pepper.
     *
     * @param properties configuration properties; the pepper is read from identity.directory.pepper
     */
    public PhoneNumberHasher(IdentityServiceProperties properties) {
        this.properties = properties;
        this.macSupplier = ThreadLocal.withInitial(this::createMac);
    }

    /**
     * Computes the HMAC-SHA256 digest of the provided E.164 phone number and returns it as a lowercase hex string.
     * <p>
     * The output is 64 hex characters (32 bytes).
     *
     * @param e164PhoneNumber phone number in E.164 format (e.g., +15551234567); must not be null
     * @return lowercase hexadecimal HMAC digest
     * @throws IllegalStateException if the MAC cannot be (re)initialized
     */
    public String digest(String e164PhoneNumber) {
        Mac mac = macSupplier.get();
        mac.reset();
        mac.update(e164PhoneNumber.getBytes(StandardCharsets.UTF_8));
        byte[] result = mac.doFinal();
        return bytesToHex(result);
    }

    /**
     * Creates and initializes a {@link Mac} instance for HMAC-SHA256 using the configured pepper.
     *
     * @return initialized Mac instance
     */
    private Mac createMac() {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKey = new SecretKeySpec(properties.getDirectory().getPepper().getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(secretKey);
            return mac;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to initialize phone hasher", ex);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
