package me.sarahlacerda.gua.identityservice.service.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

@Service
@RequiredArgsConstructor
public class PasskeyService implements CredentialRepository {

    private static final String REGISTRATION_KEY_PREFIX = "passkey:registration:";
    private static final String ASSERTION_KEY_PREFIX = "passkey:assertion:";

    private final PasskeyCredentialRepository repository;
    private final LoginFlowProperties loginProperties;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public boolean isEnabled() {
        return loginProperties.getPasskeys().isEnabled();
    }

    public JsonNode startRegistration(String sessionId, LoginSession session) {
        ensureEnabled();
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "Passkey setup requires a verified account");
        }

        UserIdentity user = UserIdentity.builder()
                .name(session.getUserId())
                .displayName(displayNameFor(session))
                .id(userHandleFor(session.getUserId()))
                .build();

        PublicKeyCredentialCreationOptions options = relyingParty().startRegistration(
                StartRegistrationOptions.builder()
                        .user(user)
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .residentKey(ResidentKeyRequirement.REQUIRED)
                                .userVerification(UserVerificationRequirement.PREFERRED)
                                .build())
                        .timeout(loginProperties.getPasskeys().getTimeoutMillis())
                        .build());

        try {
            redisTemplate.opsForValue().set(
                    registrationKey(sessionId),
                    options.toJson(),
                    loginProperties.getPasskeys().getChallengeTtl());
            return browserPublicKey(options.toCredentialsCreateJson(), "publicKey");
        } catch (Exception ex) {
            throw new LoginFlowException(HttpStatus.INTERNAL_SERVER_ERROR, "passkey_options_failed",
                    "Could not create passkey setup options");
        }
    }

    @Transactional
    public void finishRegistration(String sessionId, LoginSession session, JsonNode credential) {
        ensureEnabled();
        String stored = redisTemplate.opsForValue().get(registrationKey(sessionId));
        if (!StringUtils.hasText(stored)) {
            throw new LoginFlowException(HttpStatus.GONE, "passkey_challenge_expired",
                    "Passkey setup expired. Please try again.");
        }
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "Passkey setup requires a verified account");
        }

        try {
            RegistrationResult result = relyingParty().finishRegistration(FinishRegistrationOptions.builder()
                    .request(PublicKeyCredentialCreationOptions.fromJson(stored))
                    .response(PublicKeyCredential.parseRegistrationResponseJson(objectMapper.writeValueAsString(credential)))
                    .build());

            repository.save(PasskeyCredential.builder()
                    .userId(session.getUserId())
                    .userHandle(userHandleFor(session.getUserId()).getBase64Url())
                    .credentialId(result.getKeyId().getId().getBase64Url())
                    .publicKeyCose(result.getPublicKeyCose().getBase64Url())
                    .signatureCount(result.getSignatureCount())
                    .backupEligible(result.isBackupEligible())
                    .backupState(result.isBackedUp())
                    .build());
            redisTemplate.delete(registrationKey(sessionId));
        } catch (RegistrationFailedException ex) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "passkey_registration_failed",
                    "Passkey setup was not accepted. Please try again.");
        } catch (IOException ex) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "passkey_response_invalid",
                    "Passkey setup response was invalid.");
        }
    }

    public JsonNode startAuthentication(String sessionId) {
        ensureEnabled();
        AssertionRequest request = relyingParty().startAssertion(StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .timeout(loginProperties.getPasskeys().getTimeoutMillis())
                .build());

        try {
            redisTemplate.opsForValue().set(
                    assertionKey(sessionId),
                    request.toJson(),
                    loginProperties.getPasskeys().getChallengeTtl());
            return browserPublicKey(request.getPublicKeyCredentialRequestOptions().toCredentialsGetJson(), "publicKey");
        } catch (Exception ex) {
            throw new LoginFlowException(HttpStatus.INTERNAL_SERVER_ERROR, "passkey_options_failed",
                    "Could not create passkey sign-in options");
        }
    }

    @Transactional
    public PasskeyAuthentication finishAuthentication(String sessionId, JsonNode credential) {
        ensureEnabled();
        String stored = redisTemplate.opsForValue().get(assertionKey(sessionId));
        if (!StringUtils.hasText(stored)) {
            throw new LoginFlowException(HttpStatus.GONE, "passkey_challenge_expired",
                    "Passkey sign-in expired. Please try again.");
        }

        try {
            AssertionResult result = relyingParty().finishAssertion(FinishAssertionOptions.builder()
                    .request(AssertionRequest.fromJson(stored))
                    .response(PublicKeyCredential.parseAssertionResponseJson(objectMapper.writeValueAsString(credential)))
                    .build());

            if (!result.isSuccess()) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                        "Passkey sign-in was not accepted.");
            }

            PasskeyCredential saved = repository.findByCredentialId(result.getCredentialId().getBase64Url())
                    .orElseThrow(() -> new LoginFlowException(HttpStatus.UNAUTHORIZED,
                            "passkey_authentication_failed", "Unknown passkey."));
            saved.setSignatureCount(result.getSignatureCount());
            saved.setBackupEligible(result.isBackupEligible());
            saved.setBackupState(result.isBackedUp());
            saved.setLastUsedAt(Instant.now());
            redisTemplate.delete(assertionKey(sessionId));

            return new PasskeyAuthentication(saved.getUserId());
        } catch (AssertionFailedException ex) {
            throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                    "Passkey sign-in was not accepted.");
        } catch (IOException ex) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "passkey_response_invalid",
                    "Passkey sign-in response was invalid.");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return repository.findByUserId(username).stream()
                .map(this::descriptorFor)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.of(userHandleFor(username));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return repository.findByUserHandle(userHandle.getBase64Url()).stream()
                .findFirst()
                .map(PasskeyCredential::getUserId);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return repository.findByCredentialId(credentialId.getBase64Url())
                .filter(credential -> credential.getUserHandle().equals(userHandle.getBase64Url()))
                .map(this::registeredCredentialFor);
    }

    @Override
    @Transactional(readOnly = true)
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return repository.findByCredentialId(credentialId.getBase64Url())
                .map(this::registeredCredentialFor)
                .map(Set::of)
                .orElseGet(Set::of);
    }

    private RelyingParty relyingParty() {
        LoginFlowProperties.Passkeys passkeys = loginProperties.getPasskeys();
        Set<String> origins = passkeys.getOrigins().stream()
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        return RelyingParty.builder()
                .identity(RelyingPartyIdentity.builder()
                        .id(passkeys.getRpId())
                        .name(passkeys.getRpName())
                        .build())
                .credentialRepository(this)
                .origins(origins)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(false)
                .build();
    }

    private JsonNode browserPublicKey(String json, String nestedKey) throws IOException {
        JsonNode node = objectMapper.readTree(json);
        JsonNode nested = node.get(nestedKey);
        return nested == null ? node : nested;
    }

    private PublicKeyCredentialDescriptor descriptorFor(PasskeyCredential credential) {
        return PublicKeyCredentialDescriptor.builder()
                .id(base64Url(credential.getCredentialId()))
                .type(PublicKeyCredentialType.PUBLIC_KEY)
                .build();
    }

    private RegisteredCredential registeredCredentialFor(PasskeyCredential credential) {
        return RegisteredCredential.builder()
                .credentialId(base64Url(credential.getCredentialId()))
                .userHandle(base64Url(credential.getUserHandle()))
                .publicKeyCose(base64Url(credential.getPublicKeyCose()))
                .signatureCount(credential.getSignatureCount())
                .backupEligible(credential.isBackupEligible())
                .backupState(credential.isBackupState())
                .build();
    }

    private ByteArray base64Url(String value) {
        try {
            return ByteArray.fromBase64Url(value);
        } catch (Base64UrlException ex) {
            throw new IllegalStateException("Stored passkey credential bytes are invalid", ex);
        }
    }

    private ByteArray userHandleFor(String userId) {
        return new ByteArray(userId.getBytes(StandardCharsets.UTF_8));
    }

    private String displayNameFor(LoginSession session) {
        if (StringUtils.hasText(session.getDisplayName())) {
            return session.getDisplayName();
        }
        if (StringUtils.hasText(session.getPreferredUsername())) {
            return session.getPreferredUsername();
        }
        return session.getUserId();
    }

    private void ensureEnabled() {
        if (!isEnabled()) {
            throw new LoginFlowException(HttpStatus.NOT_FOUND, "passkey_unavailable", "Passkeys are unavailable");
        }
    }

    private String registrationKey(String sessionId) {
        return REGISTRATION_KEY_PREFIX + sessionId;
    }

    private String assertionKey(String sessionId) {
        return ASSERTION_KEY_PREFIX + sessionId;
    }

    public record PasskeyAuthentication(String userId) {
    }
}
