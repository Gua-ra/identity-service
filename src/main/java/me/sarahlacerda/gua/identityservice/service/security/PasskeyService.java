package me.sarahlacerda.gua.identityservice.service.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
        // By principal, and this one is a security property rather than a tidy-up. Recovery's premise is that
        // the account holder cannot use these credentials, so any left behind leave a lost or stolen device
        // able to sign straight back in through passkey-first sign-in, which asks for no OTP. Keyed on the
        // MXID this deleted NOTHING for an account whose Matrix identity had changed since registration, and
        // it would have failed silently: the count would simply be zero and recovery would report success.
        List<PasskeyCredential> credentials = principals.forUserId(userId)
                .map(p -> repository.findByAccountPrincipal(p.text()))
                .orElseGet(List::of);
        repository.deleteAll(credentials);
        return credentials.size();
    }

    /**
     * Removes one credential of the account, and reports whether it was there.
     *
     * <p>ADM-009 gate 5 calls this a prerequisite rather than a nice-to-have, and the reason is the fresh-factor
     * hold. Until now the only way to remove a credential was {@link #removeAllForUser(String)}, so an owner
     * locking a thief out of a stolen device had to wipe every credential and then register a new one, which put
     * their own remaining factor inside the hold and cost them a week on anything the hold gates. Removing the
     * one credential that is gone leaves the others established.
     *
     * <p>The last remaining factor is refused. An account that holds nothing has to set a factor up before a
     * sign-in completes, so wiping the last one here would turn a tidy-up into a state the account holder did
     * not ask for; the way to be rid of every credential is still the recovery that assumes they are lost.
     *
     * @return whether a credential of this account with that id existed
     * @throws LoginFlowException 409 {@code factor_required} when it is the account's last factor
     */
    @Transactional
    public boolean removeCredential(String userId, String credentialId, boolean accountHoldsAnotherFactor) {
        Optional<PasskeyCredential> credential = repository.findByCredentialId(credentialId)
                .filter(row -> row.getUserId().equals(userId));
        if (credential.isEmpty()) {
            // Same answer for another account's credential and for one that does not exist, so this cannot be
            // used to ask whose a credential is.
            return false;
        }
        if (!accountHoldsAnotherFactor && repository.findByUserId(userId).size() <= 1) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "factor_required",
                    "Set up another way to confirm it is you before removing this one.");
        }
        repository.delete(credential.get());
        return true;
    }

    public JsonNode startRegistration(String sessionId, LoginSession session) {
        ensureEnabled();
        if (!StringUtils.hasText(session.getUserId())) {
            throw new LoginFlowException(HttpStatus.CONFLICT, "passkey_user_unknown",
                    "Passkey setup requires a verified account");
        }

        // The WebAuthn user is the STABLE principal, in both fields that leave this server. `id` is the user
        // handle the authenticator stores and replays; `name` is what a credential manager shows and what
        // Yubico keys its own username lookups on. Both used to be the MXID, which put the account's
        // localpart and its homeserver domain inside every credential synced to the holder's password
        // manager, and made the credential unusable the moment either changed.
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

            // The credential names a principal; the principal names whatever Matrix identity the account has
            // NOW. Reading saved.getUserId() here is what tied a credential to the identity it happened to be
            // registered under. A row with no principal predates the stable model: its handle is an MXID's own
            // bytes, which no principal can match, so it is refused and its holder re-enrols rather than being
            // resolved by a guess.
            String principalText = saved.getAccountPrincipal();
            if (principalText == null || principalText.isBlank()) {
                throw new LoginFlowException(HttpStatus.UNAUTHORIZED, "passkey_credential_retired",
                        "This passkey was set up under an older format. Please sign in another way and add it again.");
            }
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
        // Returns the principal, because that is the username this service deals in. Returning the MXID here
        // made the library's own view of identity disagree with the column it had just read.
        return repository.findByUserHandle(userHandle.getBase64Url()).stream()
                .findFirst()
                .map(PasskeyCredential::getAccountPrincipal);
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

    @Deprecated(forRemoval = true)
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
