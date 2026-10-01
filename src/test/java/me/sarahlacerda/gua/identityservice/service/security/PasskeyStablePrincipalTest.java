package me.sarahlacerda.gua.identityservice.service.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;

import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasskeyStablePrincipalTest {

    private static final AccountId ACCOUNT = AccountId.derive(
            AccountId.CLASS_BOOTSTRAP, "stable-principal-fixture".getBytes(StandardCharsets.UTF_8));
    private static final String PRINCIPAL = ACCOUNT.value();

    private static final String OLD_MXID = "@alice:dev.gua.sarahlacerda.me";
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
                .userId(OLD_MXID)
                .userHandle(new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes()).getBase64Url())
                .credentialId("Y3JlZC0x")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
    }

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
        verify(repository, never()).findByUserId(anyString());
    }

    @Test
    void recoveryNeverQueriesCredentialsByMatrixId() {
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        int removed = service().removeAllForUser(NEW_MXID);

        assertThat(removed).isZero();
        verify(repository, never()).findByUserId(anyString());
        verify(repository, never()).findByAccountPrincipal(anyString());
    }

    @Test
    void hasPasskeyAnswersForTheAccountNotForTheMatrixIdOfTheMoment() {
        when(principals.forUserId(NEW_MXID))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
        when(repository.existsByAccountPrincipal(PRINCIPAL)).thenReturn(true);

        assertThat(service().hasPasskey(NEW_MXID)).isTrue();
        verify(repository, never()).existsByUserId(anyString());
    }

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
        assertThat(new String(handle.getBytes(), StandardCharsets.UTF_8)).doesNotContain("dev.gua");
        assertThat(new String(handle.getBytes(), StandardCharsets.UTF_8)).doesNotContain("@alice");
    }

    @Test
    void aLegacyMxidHandleCanNeverBeMistakenForAPrincipal() {
        byte[] legacy = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        assertThat(legacy[0]).isEqualTo((byte) '@');
        assertThat(ACCOUNT.rawBytes()[0]).isEqualTo(AccountId.FORMAT_VERSION);
        assertThat(legacy.length).isNotEqualTo(AccountId.RAW_LENGTH);
    }

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

        verify(repository, never()).findByCredentialId(anyString());
    }

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

    @Test
    void anAbsentHandleIsNoOpinionRatherThanARefusal() {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get(anyString())).thenReturn("{\"stored\":\"ceremony\"}");

        // The stored value is not a real ceremony, so the call still fails, with another code.
        assertThatThrownBy(() -> service.finishAuthentication("session-1", assertionWithNoHandle()))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> assertThat(((LoginFlowException) ex).getCode())
                        .isNotEqualTo("passkey_credential_retired"));
    }

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

    @Test
    void aHandleNamingNoAccountMapsToNoUser() {
        byte[] notAPrincipal = OLD_MXID.getBytes(StandardCharsets.UTF_8);
        when(principals.fromHandleBytes(notAPrincipal)).thenReturn(Optional.empty());

        assertThat(service().getUsernameForUserHandle(new com.yubico.webauthn.data.ByteArray(notAPrincipal)))
                .isEmpty();
    }

    @Test
    void aCredentialWhoseHandleNamesAnotherAccountIsNotResolved() {
        AccountId other = AccountId.derive(
                AccountId.CLASS_BOOTSTRAP, "a-different-account".getBytes(StandardCharsets.UTF_8));
        PasskeyCredential row = PasskeyCredential.builder()
                .accountPrincipal(PRINCIPAL)
                .userId(OLD_MXID)
                .userHandle(new com.yubico.webauthn.data.ByteArray(other.rawBytes()).getBase64Url())
                .credentialId("cred-1")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
        // lookup() queries by the base64url of the credential id it is handed.
        when(repository.findByCredentialId("Y3JlZC0x")).thenReturn(Optional.of(row));
        when(principals.fromHandleBytes(other.rawBytes()))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(other.value(), other.rawBytes())));

        assertThat(service().lookup(
                new com.yubico.webauthn.data.ByteArray("cred-1".getBytes(StandardCharsets.UTF_8)),
                new com.yubico.webauthn.data.ByteArray(other.rawBytes())))
                .isEmpty();
    }

    @Test
    void aRowWithNoPrincipalIsNotResolvedAndDoesNotThrow() {
        PasskeyCredential row = PasskeyCredential.builder()
                .userId(OLD_MXID)
                .userHandle(new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes()).getBase64Url())
                .credentialId("Y3JlZC0y")
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
        when(repository.findByCredentialId("Y3JlZC0y")).thenReturn(Optional.of(row));
        when(principals.fromHandleBytes(ACCOUNT.rawBytes()))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));

        assertThat(service().lookup(
                new com.yubico.webauthn.data.ByteArray("cred-2".getBytes(StandardCharsets.UTF_8)),
                new com.yubico.webauthn.data.ByteArray(ACCOUNT.rawBytes())))
                .isEmpty();
    }

    private static LoginSession sessionFor(String userId) {
        LoginSession session = new LoginSession();
        session.setUserId(userId);
        session.setPreferredUsername("alice");
        return session;
    }

    @Test
    void registrationForAnAccountWithNoPrincipalIsRefusedAndStoresNothing() {
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service().startRegistration("session-1", sessionFor(NEW_MXID)))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    LoginFlowException flow = (LoginFlowException) ex;
                    assertThat(flow.getCode()).isEqualTo("passkey_account_not_ready");
                    assertThat(flow.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                });

        verifyNoInteractions(redisTemplate);
        verify(repository, never()).save(any());
    }

    @Test
    void finishingRegistrationForAnAccountWithNoPrincipalIsRefusedBeforeTheCeremonyAndSavesNothing()
            throws Exception {
        PasskeyService service = service();
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("passkey:registration:session-1")).thenReturn("{\"stored\":\"ceremony\"}");
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.finishRegistration("session-1", sessionFor(NEW_MXID),
                new ObjectMapper().readTree("{\"response\":{}}")))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    LoginFlowException flow = (LoginFlowException) ex;
                    assertThat(flow.getCode()).isEqualTo("passkey_account_not_ready");
                    assertThat(flow.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                });

        verify(repository, never()).save(any());
    }

    @Test
    void theStepUpOptionsNameNoMatrixIdentity() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(principals.forUserId(NEW_MXID))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
        lenient().when(principals.fromText(PRINCIPAL))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
        when(repository.existsByAccountPrincipal(PRINCIPAL)).thenReturn(true);
        when(repository.findByAccountPrincipal(PRINCIPAL)).thenReturn(List.of(credentialOwnedByThePrincipal()));

        JsonNode options = service().startStepUpAssertion("step-1", NEW_MXID);

        assertThat(options.path("allowCredentials")).hasSize(1);
        assertThat(options.toString())
                .doesNotContain(NEW_MXID)
                .doesNotContain(OLD_MXID)
                .doesNotContain("@alice");
    }

}
