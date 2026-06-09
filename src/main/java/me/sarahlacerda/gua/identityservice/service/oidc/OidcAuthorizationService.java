package me.sarahlacerda.gua.identityservice.service.oidc;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.MatrixProvisioningService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

@Service
@RequiredArgsConstructor
public class OidcAuthorizationService {

    private static final String CODE_KEY_PREFIX = "oidc:code:";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OtpService otpService;
    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final MatrixProvisioningService matrixProvisioningService;
    private final UserSecurityService userSecurityService;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    private final OidcProperties properties;

    public OidcAuthorizationCode issueAuthorizationCode(OidcAuthorizationRequest request) {
        otpService.verifyOtp(request.phoneNumber(), request.otpCode());

        String digest = phoneNumberHasher.digest(request.phoneNumber());
        Optional<DirectoryEntry> existingEntry = directoryService.findByDigest(digest);

        String userId = existingEntry
            .map(DirectoryEntry::getUserId)
            .orElseGet(matrixProvisioningService::generateOpaqueUserId);

        String resolvedDisplayName = resolveDisplayName(request.displayName(), existingEntry);

        directoryService.upsertByDigest(digest, userId, resolvedDisplayName);
        userSecurityService.recordSuccessfulLogin(userId);

        OidcAuthorization authorization = new OidcAuthorization(
            userId,
            request.phoneNumber(),
            resolvedDisplayName,
            request.scope(),
            request.clientId()
        );

        String code = generateCode();
        persist(code, authorization, request.redirectUri(), request.codeChallenge());
        return new OidcAuthorizationCode(code, authorization, request.redirectUri(),
            Optional.ofNullable(request.codeChallenge()));
    }

    public Optional<OidcAuthorizationCode> consumeAuthorizationCode(String code) {
        String key = keyFor(code);
        String payload = redisTemplate.opsForValue().get(key);
        if (payload == null) {
            return Optional.empty();
        }
        redisTemplate.delete(key);
        try {
            AuthorizationCodePayload stored = objectMapper.readValue(payload, AuthorizationCodePayload.class);
            OidcAuthorization authorization = new OidcAuthorization(
                stored.userId(),
                stored.phoneNumber(),
                stored.displayName(),
                Set.copyOf(stored.scope()),
                stored.clientId()
            );
            return Optional.of(new OidcAuthorizationCode(code, authorization, stored.redirectUri(),
                Optional.ofNullable(stored.codeChallenge())));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to deserialize authorization code", ex);
        }
    }

    private void persist(String code, OidcAuthorization authorization, String redirectUri, String codeChallenge) {
        AuthorizationCodePayload payload = new AuthorizationCodePayload(
            authorization.userId(),
            authorization.phoneNumber(),
            authorization.displayName(),
            authorization.scope(),
            authorization.clientId(),
            redirectUri,
            codeChallenge
        );
        try {
            redisTemplate.opsForValue().set(
                keyFor(code),
                objectMapper.writeValueAsString(payload),
                properties.getAuthorizationCodeTtl()
            );
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize authorization code", ex);
        }
    }

    private String keyFor(String code) {
        return CODE_KEY_PREFIX + code;
    }

    private String generateCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String resolveDisplayName(String requested, Optional<DirectoryEntry> existingEntry) {
        if (requested != null && !requested.isBlank()) {
            return requested;
        }
        return existingEntry.map(DirectoryEntry::getDisplayName).orElse(null);
    }

    private record AuthorizationCodePayload(
        String userId,
        String phoneNumber,
        String displayName,
        Set<String> scope,
        String clientId,
        String redirectUri,
        String codeChallenge
    ) {}
}
