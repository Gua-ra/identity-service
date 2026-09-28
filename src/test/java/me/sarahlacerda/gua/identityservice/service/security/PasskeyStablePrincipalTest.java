package me.sarahlacerda.gua.identityservice.service.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;

import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The passkey ownership invariant: a credential belongs to the stable Gua account, and the account's current
 * Matrix identity is resolved afterwards and never stored as the owner.
 *
 * <p>Each case here fails silently if ownership is re-keyed on the Matrix identity: the call succeeds and
 * answers for the wrong account.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyStablePrincipalTest {

    private static final AccountId ACCOUNT = AccountId.derive(
            AccountId.CLASS_BOOTSTRAP, "stable-principal-fixture".getBytes(StandardCharsets.UTF_8));
    private static final String PRINCIPAL = ACCOUNT.value();

    /** The Matrix identity the account had when the credential was registered. */
    private static final String OLD_MXID = "@alice:dev.gua.sarahlacerda.me";
    /** The Matrix identity it has now, after a placement change. */
    private static final String NEW_MXID = "@alice:dev2.gua.sarahlacerda.me";

    @Mock
    private PasskeyCredentialRepository repository;
    @Mock
    private PasskeyPrincipals principals;
    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private PasskeyService service() {
        return new PasskeyService(repository, principals, new LoginFlowProperties(), redisTemplate,
                new ObjectMapper());
    }

    private static PasskeyCredential credentialOwnedByThePrincipal() {
        return PasskeyCredential.builder()
                .accountPrincipal(PRINCIPAL)
                // Stale on purpose: the identity at registration time, which nothing may read.
                .userId(OLD_MXID)
                // What registration writes: the principal's own canonical bytes, which the assertion path
                // compares against the row.
                .userHandle(new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes()).getBase64Url())
                .credentialId("Y3JlZC0x")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
    }

    // --- the regression test the recovery hole demands -----------------------------------------------

    /**
     * A completed account recovery must revoke the credentials even though the account's Matrix identity has
     * changed since they were registered.
     *
     * <p>This is the test that fails the moment anyone re-keys recovery cleanup on the MXID. Under MXID keying
     * the lookup returns nothing, `deleteAll` deletes nothing, and `removeAllForUser` returns 0 — and recovery
     * reports success. The account holder is told their passkeys are gone while a lost or stolen device can
     * still sign straight back in through passkey-first sign-in, which asks for no OTP.
     */
    @Test
    void recoveryRevokesCredentialsAfterTheMatrixIdentityChanged() {
        PasskeyCredential credential = credentialOwnedByThePrincipal();
        when(principals.forUserId(NEW_MXID))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
        when(repository.findByAccountPrincipal(PRINCIPAL)).thenReturn(List.of(credential));

        int removed = service().removeAllForUser(NEW_MXID);

        assertThat(removed)
                .as("recovery must revoke by stable principal, not by the Matrix id of the moment")
                .isEqualTo(1);
        verify(repository).deleteAll(List.of(credential));
        // The stale column must not be the lookup key, ever.
        verify(repository, never()).findByUserId(anyString());
    }

    /** And the same guarantee stated as the negative: nothing is looked up by the Matrix id. */
    @Test
    void recoveryNeverQueriesCredentialsByMatrixId() {
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        int removed = service().removeAllForUser(NEW_MXID);

        assertThat(removed).isZero();
        // The key is what matters, not the call: nothing is looked up by the Matrix id. deleteAll may still
        // be handed the empty list, which deletes nothing.
        verify(repository, never()).findByUserId(anyString());
        verify(repository, never()).findByAccountPrincipal(anyString());
    }

    // --- ownership questions -------------------------------------------------------------------------

    @Test
    void hasPasskeyAnswersForTheAccountNotForTheMatrixIdOfTheMoment() {
        when(principals.forUserId(NEW_MXID))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
        when(repository.existsByAccountPrincipal(PRINCIPAL)).thenReturn(true);

        assertThat(service().hasPasskey(NEW_MXID)).isTrue();
        verify(repository, never()).existsByUserId(anyString());
    }

    /**
     * An account with no attached genesis row has no principal, so it has no passkey and cannot register one.
     * The answer is a refusal rather than a fallback: writing a credential under the MXID "just this once"
     * would recreate the defect for that account.
     */
    @Test
    void anAccountWithNoStableIdentityHasNoPasskeyAndIsNotGuessedAt() {
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        assertThat(service().hasPasskey(NEW_MXID)).isFalse();
        verify(repository, never()).existsByUserId(anyString());
        verify(repository, never()).existsByAccountPrincipal(anyString());
    }

    @Test
    void credentialEnumerationIsKeyedOnThePrincipalSoExclusionAndAllowListsStayCorrect() {
        when(repository.findByAccountPrincipal(PRINCIPAL)).thenReturn(List.of(credentialOwnedByThePrincipal()));

        // Yubico passes the username this service gave it, which is the principal.
        assertThat(service().getCredentialIdsForUsername(PRINCIPAL)).hasSize(1);
        verify(repository, never()).findByUserId(anyString());
    }

    @Test
    void theUserHandleIsTheCanonicalPrincipalBytesAndCarriesNoMatrixIdentity() {
        when(principals.fromText(PRINCIPAL))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));

        var handle = service().getUserHandleForUsername(PRINCIPAL).orElseThrow();

        assertThat(handle.getBytes()).isEqualTo(ACCOUNT.rawBytes());
        assertThat(handle.getBytes()).hasSize(AccountId.RAW_LENGTH);
        // No localpart and no homeserver domain travel to the authenticator.
        assertThat(new String(handle.getBytes(), StandardCharsets.UTF_8)).doesNotContain("dev.gua");
        assertThat(new String(handle.getBytes(), StandardCharsets.UTF_8)).doesNotContain("@alice");
    }

    @Test
    void aLegacyMxidHandleCanNeverBeMistakenForAPrincipal() {
        // The real discriminator, and the reason this model needs no version column: a principal's first byte
        // is the format version 0x01, while any MXID-derived handle begins with '@' (0x40) and is not 34 bytes.
        byte[] legacy = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        assertThat(legacy[0]).isEqualTo((byte) '@');
        assertThat(ACCOUNT.rawBytes()[0]).isEqualTo(AccountId.FORMAT_VERSION);
        assertThat(legacy.length).isNotEqualTo(AccountId.RAW_LENGTH);
    }

    // --- the canonical representation ----------------------------------------------------------------

    @Test
    void theCanonicalPrincipalRoundTripsByteForByte() {
        byte[] raw = ACCOUNT.rawBytes();

        AccountId back = AccountId.fromRawBytes(raw);

        assertThat(back.value()).isEqualTo(PRINCIPAL);
        assertThat(back.rawBytes()).isEqualTo(raw);
        assertThat(AccountId.fromRawBytes(back.rawBytes()).value()).isEqualTo(PRINCIPAL);
        assertThat(raw).hasSize(34);
        assertThat(raw.length).isLessThanOrEqualTo(64);
    }

    @Test
    void theCanonicalPrincipalIsDeterministicAndIndependentOfPhoneAndPlacement() {
        byte[] genesis = "stable-principal-fixture".getBytes(StandardCharsets.UTF_8);

        AccountId again = AccountId.derive(AccountId.CLASS_BOOTSTRAP, genesis);

        assertThat(again.value()).isEqualTo(PRINCIPAL);
        // Nothing about a phone number, a localpart or a homeserver is an input, so none can change it.
        assertThat(PRINCIPAL).doesNotContain("gua.sarahlacerda.me").doesNotContain("alice");
    }

    @Test
    void bytesThatAreNotAPrincipalAreRefusedRatherThanCoerced() {
        assertThat(catchThrowable(() -> AccountId.fromRawBytes(OLD_MXID.getBytes(StandardCharsets.UTF_8))))
                .isNotNull();
        assertThat(catchThrowable(() -> AccountId.fromRawBytes(new byte[34]))).isNotNull();
        assertThat(catchThrowable(() -> AccountId.fromRawBytes(null))).isNotNull();
    }

    private static Throwable catchThrowable(Runnable work) {
        try {
            work.run();
            return null;
        } catch (Throwable t) {
            return t;
        }
    }
    // --- the handle is an ownership claim, so it is checked --------------------------------------------

    /**
     * A handle naming no principal belongs to a credential the account can no longer use, and its holder is
     * told to add the passkey again.
     *
     * <p>The refusal must precede the WebAuthn ceremony: the library requires the handle to resolve to a
     * username before any signature is checked, so a check placed after the ceremony never sees these rows.
     * This test pins the ordering as well as the code.
     */
    @Test
    void aHandleThatNamesNoPrincipalIsRefusedBeforeTheCeremonyEverRuns() {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenReturn("{\"stored\":\"ceremony\"}");
        byte[] mxidBytes = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        when(principals.fromHandleBytes(mxidBytes)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.finishAuthentication("session-1", assertionReplaying(mxidBytes)))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    LoginFlowException flow = (LoginFlowException) ex;
                    assertThat(flow.getCode()).isEqualTo("passkey_credential_retired");
                    assertThat(flow.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                });

        // Never reached the database, which is what makes the distinct code safe on an unauthenticated path:
        // it answers a property of the caller's own submission and cannot say whether anything exists.
        verify(repository, never()).findByCredentialId(anyString());
    }

    /**
     * And the single-use challenge is still burned by that refusal. A guard placed before the try block would
     * skip the finally that deletes it, turning one attempt into a retry window until the TTL ran out.
     */
    @Test
    void thatRefusalStillSpendsTheChallenge() {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenReturn("{\"stored\":\"ceremony\"}");
        byte[] mxidBytes = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        when(principals.fromHandleBytes(mxidBytes)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.finishAuthentication("session-1", assertionReplaying(mxidBytes)))
                .isInstanceOf(LoginFlowException.class);

        verify(redisTemplate).delete("passkey:assertion:session-1");
    }

    /**
     * An absent handle is not a refusal. Every step-up ceremony is built from an allow list, and an
     * authenticator answering one need not replay a handle at all, so treating absence as a refusal would
     * break step-up rather than tighten it.
     */
    @Test
    void anAbsentHandleIsNoOpinionRatherThanARefusal() {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenReturn("{\"stored\":\"ceremony\"}");

        // No userHandle at all. It must get past the guard and fail later, in the ceremony, which with a
        // stored value that is not a real ceremony means a refusal that is NOT the retired code.
        assertThatThrownBy(() -> service.finishAuthentication("session-1", assertionWithNoHandle()))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> assertThat(((LoginFlowException) ex).getCode())
                        .isNotEqualTo("passkey_credential_retired"));
    }

    /**
     * A handle that is present but not even base64url is a malformed body, not a retired credential.
     */
    @Test
    void anUnreadableHandleIsAMalformedResponse() {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenReturn("{\"stored\":\"ceremony\"}");

        assertThatThrownBy(() -> service.finishAuthentication("session-1",
                new ObjectMapper().readTree("{\"response\":{\"userHandle\":\"!!!not base64url!!!\"}}")))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    LoginFlowException flow = (LoginFlowException) ex;
                    assertThat(flow.getCode()).isEqualTo("passkey_response_invalid");
                    assertThat(flow.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                });
    }

    private static com.fasterxml.jackson.databind.JsonNode assertionReplaying(byte[] handle) throws Exception {
        String b64url = new com.yubico.webauthn.data.ByteArray(handle).getBase64Url();
        return new ObjectMapper().readTree("{\"response\":{\"userHandle\":\"" + b64url + "\"}}");
    }

    private static com.fasterxml.jackson.databind.JsonNode assertionWithNoHandle() throws Exception {
        return new ObjectMapper().readTree("{\"response\":{}}");
    }

    // --- the handle-to-user mapping the WebAuthn library asks for ---------------------------------------

    /**
     * Several credentials of one account share a user handle, by design, so no row-keyed answer to "which
     * user is this handle" can be correct. It is decoded from the handle instead, and no row is read.
     */
    @Test
    void theHandleToUserMappingIsDecodedAndNeverReadFromARow() {
        byte[] handle = ACCOUNT.rawBytes();
        when(principals.fromHandleBytes(handle))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, handle)));

        assertThat(service().getUsernameForUserHandle(new com.yubico.webauthn.data.ByteArray(handle)))
                .contains(PRINCIPAL);

        verify(repository, never()).findByUserHandle(anyString());
        verify(repository, never()).findByUserId(anyString());
    }

    /** Bytes that name no account map to no user, so the ceremony fails rather than resolving to a guess. */
    @Test
    void aHandleNamingNoAccountMapsToNoUser() {
        byte[] notAPrincipal = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        when(principals.fromHandleBytes(notAPrincipal)).thenReturn(Optional.empty());

        assertThat(service().getUsernameForUserHandle(new com.yubico.webauthn.data.ByteArray(notAPrincipal)))
                .isEmpty();
    }

    /**
     * A credential is only resolved when the handle names the principal its own row says owns it. Comparing
     * the handle against the row's handle alone is self-confirming, because both sides are the same column,
     * so a row whose handle belonged to another account would authenticate as this one.
     */
    @Test
    void aCredentialWhoseHandleNamesAnotherAccountIsNotResolved() {
        AccountId other = AccountId.derive(
                AccountId.CLASS_BOOTSTRAP, "a-different-account".getBytes(StandardCharsets.UTF_8));
        PasskeyCredential row = PasskeyCredential.builder()
                .accountPrincipal(PRINCIPAL)
                .userId(OLD_MXID)
                // The handle of a different account, which the row nonetheless claims to own.
                .userHandle(new com.yubico.webauthn.data.ByteArray(other.rawBytes()).getBase64Url())
                .credentialId("cred-1")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
        // lookup() addresses the row by the base64url of the credential id it is handed.
        when(repository.findByCredentialId("Y3JlZC0x")).thenReturn(Optional.of(row));
        when(principals.fromHandleBytes(other.rawBytes()))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(other.value(), other.rawBytes())));

        assertThat(service().lookup(
                new com.yubico.webauthn.data.ByteArray("cred-1".getBytes(StandardCharsets.UTF_8)),
                new com.yubico.webauthn.data.ByteArray(other.rawBytes())))
                .isEmpty();
    }

    /** A row with no principal is named by no handle, and asking must not fail with an error. */
    @Test
    void aRowWithNoPrincipalIsNotResolvedAndDoesNotThrow() {
        PasskeyCredential row = PasskeyCredential.builder()
                .userId(OLD_MXID)
                .userHandle(new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes()).getBase64Url())
                .credentialId("Y3JlZC0y")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
        // lookup() addresses the row by the base64url of the credential id it is handed.
        when(repository.findByCredentialId("Y3JlZC0y")).thenReturn(Optional.of(row));
        when(principals.fromHandleBytes(ACCOUNT.rawBytes()))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));

        assertThat(service().lookup(
                new com.yubico.webauthn.data.ByteArray("cred-2".getBytes(StandardCharsets.UTF_8)),
                new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes())))
                .isEmpty();
    }

}
