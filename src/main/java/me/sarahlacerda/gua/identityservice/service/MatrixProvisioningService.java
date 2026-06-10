package me.sarahlacerda.gua.identityservice.service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MatrixProvisioningService {

    private final IdentityServiceProperties properties;
    private final MatrixAdminClient matrixAdminClient;
    private final SecureRandom secureRandom = new SecureRandom();

    public String generateOpaqueUserId() {
        String prefix = properties.getMatrix().getUserLocalpartPrefix();
        if (prefix == null) {
            prefix = "";
        }
        prefix = prefix.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._=/-]", "");
        if (prefix.isBlank() || prefix.contains(".") || prefix.contains(":")) {
            prefix = "u";
        }
        String random = UUID.randomUUID().toString().replace("-", "");
        String localPart = prefix + random;
        return buildUserId(localPart);
    }

    public String buildUserId(String localpart) {
        return "@" + localpart + ":" + properties.getMatrix().getHomeserverDomain();
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
