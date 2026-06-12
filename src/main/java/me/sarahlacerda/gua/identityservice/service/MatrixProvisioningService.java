package me.sarahlacerda.gua.identityservice.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;
import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MatrixProvisioningService {

    private final IdentityServiceProperties properties;
    private final MatrixAdminClient matrixAdminClient;
    private final HomeserverRegistry homeserverRegistry;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates an opaque, prefixed localpart for a brand-new account on the given
     * homeserver. The localpart is intentionally NOT the user's chosen handle:
     * under Gua's routing model the human-readable username lives in the directory
     * (as a global alias), decoupled from the MXID.
     */
    public String generateOpaqueUserId(Homeserver homeserver) {
        return homeserver.userId(generateOpaqueLocalpart());
    }

    /** Back-compatible overload: places on the default homeserver. */
    public String generateOpaqueUserId() {
        return generateOpaqueUserId(homeserverRegistry.getDefault());
    }

    private String generateOpaqueLocalpart() {
        String prefix = properties.getMatrix().getUserLocalpartPrefix();
        if (prefix == null) {
            prefix = "";
        }
        prefix = prefix.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._=/-]", "");
        if (prefix.isBlank() || prefix.contains(".") || prefix.contains(":")) {
            prefix = "u";
        }
        String random = UUID.randomUUID().toString().replace("-", "");
        return prefix + random;
    }

    /** Builds the full MXID for a localpart on a specific homeserver. */
    public String buildUserId(String localpart, Homeserver homeserver) {
        return homeserver.userId(localpart);
    }

    /** Back-compatible overload: builds the MXID on the default homeserver. */
    public String buildUserId(String localpart) {
        return buildUserId(localpart, homeserverRegistry.getDefault());
    }

    public MatrixSession ensureSessionForUser(String userId, String phone, String displayName,
            boolean ensurePhoneLinked) {
        String password = generatePassword();
        matrixAdminClient.upsertUser(userId, password, ensurePhoneLinked ? phone : null, displayName);
        MatrixLoginResponse loginResponse = matrixAdminClient.login(userId, password);
        return new MatrixSession(loginResponse.accessToken(), loginResponse.userId(), loginResponse.deviceId(),
                properties.getMatrix().getClientApiBaseUrl());
    }

    public void ensureExclusivePhoneBinding(String userId, String phone) {
        List<String> currentPhones = matrixAdminClient.getLinkedPhones(userId);
        if (!currentPhones.contains(phone)) {
            matrixAdminClient.linkPhone(userId, phone);
        }
        currentPhones.stream()
                .filter(existing -> !existing.equals(phone))
                .forEach(existing -> matrixAdminClient.unlinkPhone(userId, existing));
    }

    private String generatePassword() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
