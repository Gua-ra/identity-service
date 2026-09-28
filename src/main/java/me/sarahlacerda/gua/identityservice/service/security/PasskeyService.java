package me.sarahlacerda.gua.identityservice.service.security;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
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
    private final PasskeyPrincipals principals;
    private final LoginFlowProperties loginProperties;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public boolean isEnabled() {
        return loginProperties.getPasskeys().isEnabled();
    }

    /**
     * Whether the given account already has at least one registered passkey.
     *
     * <p>Resolved through the stable principal, not the MXID. Keyed on the MXID this answered "no" for an
     * account whose Matrix identity had changed, which is the wrong answer to a policy question: it is what
     * decides whether a passkey-only account must assert, whether a step-up can be offered, and whether
     * registration is a duplicate.
     *
     * <p>An account with no attached genesis row has no principal and therefore no passkey by construction,
     * because a credential can no longer be written without one.
     */
    public boolean hasPasskey(String userId) {
        return principals.forUserId(userId)
                .map(p -> repository.existsByAccountPrincipal(p.text()))
                .orElse(false);
    }

    /**
     * Removes every passkey stored for the account and returns how many there were.
     *
     * <p>
     * Only a completed account recovery calls it, inside its own transaction and under the
     * account's row lock. Recovery's premise is that these credentials cannot be used by the
     * account holder, so leaving them in place would leave a lost or stolen device able to sign
     * straight back in with passkey-first sign-in, which asks for no OTP.
     */
    @Transactional
    public int removeAllForUser(String userId) {
        // By principal. Keyed on the row's user_id this silently deletes nothing for an account whose Matrix
        // identity has changed, and recovery still reports success.
        List<PasskeyCredential> credentials = principals.forUserId(userId)
                .map(p -> repository.findByAccountPrincipal(p.text()))
                .orElseGet(List::of);
        repository.deleteAll(credentials);
        return credentials.size();
    }

    public JsonNode startRegistration(String sessionId, LoginSession session) {
        ensureEnabled();
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "Passkey setup requires a verified account");
        }

        // Both fields that leave this server carry the stable principal, never the MXID: `id` is the handle the
        // authenticator stores and replays, and `name` is what a credential manager shows. An MXID here would
        // put the account's localpart and homeserver into every synced credential and break it on a placement
        // change.
        PasskeyPrincipals.Principal principal = requirePrincipal(session.getUserId());
        UserIdentity user = UserIdentity.builder()
                .name(principal.text())
                .displayName(displayNameFor(session))
                .id(new ByteArray(principal.bytes()))
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

            PasskeyPrincipals.Principal principal = requirePrincipal(session.getUserId());
            repository.save(PasskeyCredential.builder()
                    // Ownership key. userId is kept for audit and is never read to decide ownership.
                    .accountPrincipal(principal.text())
                    .userId(session.getUserId())
                    .userHandle(new ByteArray(principal.bytes()).getBase64Url())
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

        // Yubico looks credentials up by "username", so the username it is given has to be the ownership key.
        // Passing the MXID made every username-pinned ceremony fail inside the library for a stable-handle
        // credential, before any of this service's own checks were reached.
        AssertionRequest request = relyingParty().startAssertion(StartAssertionOptions.builder()
                .username(requirePrincipal(userId).text())
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
            // A credential predating the stable model replays its Matrix id as the user handle, which can never
            // name a principal. Judging the submitted bytes reads nothing, so a distinct code here reveals
            // nothing about which accounts or credentials exist, and it still answers once the row is deleted.
            //
            // Two placement constraints: before the ceremony, which requires the handle to resolve to a
            // username before any signature is checked, and inside the try, whose finally spends the
            // single-use challenge.
            Optional<byte[]> replayedHandle = replayedHandleBytes(credential);
            if (replayedHandle.isPresent() && principals.fromHandleBytes(replayedHandle.get()).isEmpty()) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_credential_retired",
                        "This passkey cannot be used any more. Sign in another way and add it again.");
            }

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

            // A row with no principal names no account.
            String principalText = saved.getAccountPrincipal();
            if (!StringUtils.hasText(principalText)) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                        "Passkey sign-in was not accepted.");
            }

            // The handle is an ownership claim, so both the row's own handle and any handle the authenticator
            // replayed must name this principal. The replayed value comes from the response body:
            // AssertionResult.getUserHandle() returns the handle this service handed the library out of this
            // same row, so it cannot disagree with it.
            if (!namesPrincipal(storedHandleBytes(saved), principalText)) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                        "Passkey sign-in was not accepted.");
            }
            if (replayedHandle.isPresent() && !namesPrincipal(replayedHandle.get(), principalText)) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_authentication_failed",
                        "Passkey sign-in was not accepted.");
            }

            // After the checks, so a refused assertion leaves no counter or timestamp behind.
            saved.setSignatureCount(result.getSignatureCount());
            saved.setBackupEligible(result.isBackupEligible());
            saved.setBackupState(result.isBackedUp());
            saved.setLastUsedAt(Instant.now());

            // The credential names a principal; the principal names the account's current Matrix identity. The
            // row's own user_id is audit only and must never answer this.
            String currentUserId = principals.currentUserId(principalText)
                    .orElseThrow(() -> new LoginFlowException(HttpStatus.UNAUTHORIZED,
                            "passkey_authentication_failed", "Unknown passkey."));
            return new PasskeyAuthentication(currentUserId, saved.getCreatedAt());
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
     *
     * <p>
     * A seam for tests. The user-verification bar is the whole of what separates a step-up
     * from a sign-in, and no test can build a real assertion that fails it, so without an
     * override here that bar could be removed with nothing objecting
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
        // Ownership again: this feeds excludeCredentials at registration and the allow list at assertion. Keyed
        // on the MXID it returned an empty set for an account whose identity had changed, which silently turned
        // "you already have this passkey" into a duplicate registration and handed an assertion an empty allow
        // list.
        return repository.findByAccountPrincipal(username).stream()
                .map(this::descriptorFor)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        // The username Yubico passes here is the principal text this service supplied. Derive the handle from
        // it. This used to recompute the MXID's bytes and never consult the stored column at all, so for a
        // stable-handle credential the library compared the wrong handle and failed the ceremony before any
        // check in this class ran.
        return principals.fromText(username).map(p -> new ByteArray(p.bytes()));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        // A decode, not a lookup: the handle is the principal's own canonical bytes, so the mapping the library
        // wants is already in the value it handed us, and reading a row to answer it would substitute a
        // different fact for the one submitted. Several credentials of one account share a handle by design,
        // which is why no row-keyed answer can be correct here.
        //
        // The library does not treat this as proof the account exists; lookup establishes the credential, and
        // the same validation step asserts both.
        return principals.fromHandleBytes(userHandle.getBytes())
                .map(PasskeyPrincipals.Principal::text);
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return repository.findByCredentialId(credentialId.getBase64Url())
                .filter(credential -> credential.getUserHandle().equals(userHandle.getBase64Url()))
                // The handle must also name the principal the row says owns the credential. Without this the
                // comparison above is self-confirming, since both sides come from the same column.
                .filter(credential -> namesPrincipal(userHandle.getBytes(), credential.getAccountPrincipal()))
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

    /**
     * The stable principal of the account, or a refusal.
     *
     * <p>Deliberately a refusal and never a fallback to the MXID. A credential written under an MXID is the
     * thing this model removes, so writing one because a genesis row was missing would quietly recreate the
     * defect for that account. An account reaching here without an attached genesis row means the bootstrap
     * backfill has not run, which is a deployment state to fix rather than to paper over.
     */
    private PasskeyPrincipals.Principal requirePrincipal(String userId) {
        return principals.forUserId(userId)
                .orElseThrow(() -> new LoginFlowException(HttpStatus.CONFLICT, "passkey_account_not_ready",
                        "This account is not ready for passkeys yet. Please try again shortly."));
    }

    /**
     * Whether these handle bytes name the given principal.
     *
     * <p>Bytes that parse to nothing name nothing, and a row with no principal is named by nothing, so the
     * answer is always "these bytes prove this principal" and never "these bytes disprove it". The comparison
     * runs from the decoded side so a null principal is false rather than an error.
     */
    private boolean namesPrincipal(byte[] handleBytes, String principalText) {
        return principals.fromHandleBytes(handleBytes)
                .map(PasskeyPrincipals.Principal::text)
                .filter(decoded -> decoded.equals(principalText))
                .isPresent();
    }

    /**
     * The handle the row stores, or no bytes when the column is not base64url.
     *
     * <p>Does not use the throwing {@code base64Url} helper: an unreadable column must become a refusal
     * rather than a 500.
     */
    private byte[] storedHandleBytes(PasskeyCredential saved) {
        String stored = saved.getUserHandle();
        if (!StringUtils.hasText(stored)) {
            return new byte[0];
        }
        try {
            return ByteArray.fromBase64Url(stored).getBytes();
        } catch (Base64UrlException ex) {
            return new byte[0];
        }
    }

    /**
     * The handle the authenticator replayed, when it replayed one.
     *
     * <p>Absent is legitimate and must not be a refusal: a ceremony built from an allow list, which is every
     * step-up, need not carry one. A handle that is present but unreadable is a malformed body.
     */
    private Optional<byte[]> replayedHandleBytes(JsonNode credential) {
        JsonNode handle = credential.path("response").path("userHandle");
        if (!handle.isTextual() || !StringUtils.hasText(handle.asText())) {
            return Optional.empty();
        }
        try {
            return Optional.of(ByteArray.fromBase64Url(handle.asText()).getBytes());
        } catch (Base64UrlException ex) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "passkey_response_invalid",
                    "Passkey sign-in response was invalid.");
        }
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
