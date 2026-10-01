package me.sarahlacerda.gua.identityservice.service;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Component
public class PhoneNumberHasher {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final IdentityServiceProperties properties;
    private final ThreadLocal<Mac> macSupplier;

    public PhoneNumberHasher(IdentityServiceProperties properties) {
        this.properties = properties;
        this.macSupplier = ThreadLocal.withInitial(this::createMac);
    }

    public String digest(String e164PhoneNumber) {
        Mac mac = macSupplier.get();
        mac.reset();
        mac.update(e164PhoneNumber.getBytes(StandardCharsets.UTF_8));
        byte[] result = mac.doFinal();
        return bytesToHex(result);
    }

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
