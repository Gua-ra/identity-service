package me.sarahlacerda.gua.identityservice.service.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;

import org.springframework.dao.DataIntegrityViolationException;
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
    private static final String STEP_UP_KEY_PREFIX = "passkey:stepup:";

    private final PasskeyCredentialRepository repository;
    private final LoginFlowProperties loginProperties;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public boolean isEnabled() {
        return loginProperties.getPasskeys().isEnabled();
    }

    /** Whether the given account already has at least one registered passkey. */
    public boolean hasPasskey(String userId) {
        return StringUtils.hasText(userId) && repository.existsByUserId(userId);
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
                        // RelyingParty.startRegistration auto-populates excludeCredentials from the
                        // CredentialRepository (getCredentialIdsForUsername), so a device that already
                        // has a Gua passkey for this user is excluded and won't silently re-register.
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
        } catch (DataIntegrityViolationException ex) {
            // The credential id is unique; a duplicate means this passkey is already registered.
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_already_registered",
                    "This passkey is already set up for your account.");
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
        // Login. User verification stays advisory here, matching the PREFERRED requirement the
        // login ceremony asks for: raising the bar on login would refuse an authenticator that
        // legitimately cannot do UV and silently push that account onto another factor. Login
        // is not a place where an assertion outranks a knowledge factor with lockout accounting.
        return redeemAssertion(assertionKey(sessionId), credential, false);
    }

    /**
     * Starts an assertion that may be spent as a <b>step-up</b> factor on a privileged
     * operation, instead of as a login.
     *
     * <p>
     * Two things separate it from the login ceremony:
     * <ul>
     * <li>{@link UserVerificationRequirement#REQUIRED}, so the authenticator must actually
     * verify the human in front of it (biometric or authenticator PIN). A bare possession
     * assertion is a weaker proof than the account PIN it would stand in for, and the account
     * PIN carries failure counting and lockout while a possession-only assertion carries
     * neither.</li>
     * <li>Its own Redis namespace and its own id, so a challenge minted for a step-up can
     * never be redeemed as a login and a login challenge can never be redeemed as a step-up.
     * The ceremony is pinned to {@code userId}, so the assertion can only resolve to the
     * account that asked for it.</li>
     * </ul>
     *
     * @return the browser {@code publicKey} request options; the caller sends back the
     *         {@code stepUpId} it was handed together with the assertion response
     */
    public JsonNode startStepUpAssertion(String stepUpId, String userId) {
        ensureEnabled();
        if (!StringUtils.hasText(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "A passkey step-up requires a verified account");
        }
        // Feasibility, NOT policy: an account with no registered credential has nothing to
        // assert, so the ceremony would hand the authenticator an empty allow list and fail
        // with a confusing browser error. This decides nothing about which factor the
        // operation requires; the caller keeps every fallback it had.
        if (!hasPasskey(userId)) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_not_registered",
                    "This account has no passkey to verify with.");
        }

        AssertionRequest request = relyingParty().startAssertion(StartAssertionOptions.builder()
                .username(userId)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(loginProperties.getPasskeys().getTimeoutMillis())
                .build());

        try {
            redisTemplate.opsForValue().set(
                    stepUpKey(stepUpId),
                    request.toJson(),
                    loginProperties.getPasskeys().getChallengeTtl());
            return browserPublicKey(request.getPublicKeyCredentialRequestOptions().toCredentialsGetJson(), "publicKey");
        } catch (Exception ex) {
            throw new LoginFlowException(HttpStatus.INTERNAL_SERVER_ERROR, "passkey_options_failed",
                    "Could not create passkey verification options");
        }
    }

    /**
     * Redeems a step-up assertion started by {@link #startStepUpAssertion(String, String)}.
     * Refuses an assertion that did not verify the user.
     *
     * <p>
     * Single use in the strict sense: the challenge is burned on refusal as well as on
     * acceptance, so an attempt that fails costs the caller a round trip to
     * {@code POST /security/passkey/stepup/options} rather than nothing. The caller must
     * still check that the returned user id is the account it is acting for; this method
     * resolves whose credential answered, not whether that is the right account.
     */
    @Transactional
    public PasskeyAuthentication finishStepUpAssertion(String stepUpId, JsonNode credential) {
        return redeemAssertion(stepUpKey(stepUpId), credential, true);
    }

    private PasskeyAuthentication redeemAssertion(String challengeKey, JsonNode credential,
            boolean requireUserVerification) {
        ensureEnabled();
        String stored = redisTemplate.opsForValue().get(challengeKey);
        if (!StringUtils.hasText(stored)) {
            throw new LoginFlowException(HttpStatus.GONE, "passkey_challenge_expired",
                    "Passkey verification expired. Please try again.");
        }

        try {
            AssertionResult result = runAssertion(stored, credential);

            if (!result.isSuccess()) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                        "Passkey sign-in was not accepted.");
            }

            // Read from the authenticator data of THIS assertion, not from what the stored
            // request asked for: the check holds even if the ceremony was started with a
            // weaker requirement than a step-up needs.
            if (requireUserVerification && !result.isUserVerified()) {
                throw new LoginFlowException(HttpStatus.FORBIDDEN, "passkey_user_verification_required",
                        "This action needs a passkey that verifies you, not only your device.");
            }

            PasskeyCredential saved = repository.findByCredentialId(result.getCredentialId().getBase64Url())
                    .orElseThrow(() -> new LoginFlowException(HttpStatus.UNAUTHORIZED,
                            "passkey_authentication_failed", "Unknown passkey."));
            saved.setSignatureCount(result.getSignatureCount());
            saved.setBackupEligible(result.isBackupEligible());
            saved.setBackupState(result.isBackedUp());
            saved.setLastUsedAt(Instant.now());

            return new PasskeyAuthentication(saved.getUserId(), saved.getCreatedAt());
        } catch (AssertionFailedException ex) {
            throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                    "Passkey sign-in was not accepted.");
        } catch (IOException ex) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "passkey_response_invalid",
                    "Passkey sign-in response was invalid.");
        } finally {
            // One challenge, one attempt, whatever the outcome. A challenge that survived a
            // refusal could be presented again until its TTL ran out, which turns a short
            // single-use window into a retry window: a wrong credential, a response that
            // failed verification, or a malformed body would each cost the attacker nothing.
            // Burning it here rather than on each exit path means no future branch can
            // return or throw past it.
            redisTemplate.delete(challengeKey);
        }
    }

    /**
     * The WebAuthn ceremony on its own, separated from the checks applied to its result.
     * Behaviour is unchanged: this is the same call that used to sit inline in
     * {@link #redeemAssertion}.
     *
     * <p>
     * It is a seam, and it exists because the user-verification bar had none. That bar is
     * the whole of what separates a step-up from a sign-in, and nothing in the suite could
     * build an assertion that failed it, so switching it off was an edit no test objected
     * to. Overriding this one method lets a test hand {@link #redeemAssertion} a result whose
     * {@code isUserVerified()} is false and watch what the bar does with it.
     */
    AssertionResult runAssertion(String storedRequest, JsonNode credential)
            throws AssertionFailedException, IOException {
        return relyingParty().finishAssertion(FinishAssertionOptions.builder()
                .request(AssertionRequest.fromJson(storedRequest))
                .response(PublicKeyCredential.parseAssertionResponseJson(objectMapper.writeValueAsString(credential)))
                .build());
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
                // Deliberate non-change: an authenticator that legitimately never increments its
                // signature counter (every passkey stored in a synced credential manager) would be
                // locked out of its own account by counter validation, and the counter is not what
                // the step-up bar rests on. The bar rests on user verification, checked per
                // assertion in redeemAssertion.
                .validateSignatureCounter(false)
                // Deliberate non-change: no attestation metadata service is configured, so
                // requiring trusted attestation would refuse every registration rather than
                // filter authenticators. Attestation says which authenticator model registered,
                // not whether this assertion verified the human, so it is not the step-up bar.
                .allowUntrustedAttestation(true)
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

    private String stepUpKey(String stepUpId) {
        return STEP_UP_KEY_PREFIX + stepUpId;
    }

    /**
     * Who answered, and when the credential that answered was registered.
     *
     * @param userId                 the account the asserted credential belongs to. Resolving
     *                               it is not accepting it: the caller must still check that
     *                               this is the account it is acting for
     * @param credentialRegisteredAt when that credential was stored. A phone change reads it
     *                               to refuse a credential minted minutes ago by whoever
     *                               holds the session, exactly as it refuses a PIN of that
     *                               age. Never null for a stored credential: {@code
     *                               passkey_credentials.created_at} has been NOT NULL since
     *                               the table was created
     */
    public record PasskeyAuthentication(String userId, Instant credentialRegisteredAt) {
    }
}
