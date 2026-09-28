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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The passkey ownership invariant: a credential belongs to the stable Gua account, and the account's current
 * Matrix identity is resolved afterwards and never stored as the owner.
 *
 * <p>These are the cases that were wrong when ownership was keyed on the MXID, and each one failed in a way
 * that looked like success rather than like an error.
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

    private PasskeyService service() {
        return new PasskeyService(repository, principals, new LoginFlowProperties(), redisTemplate,
                new ObjectMapper());
    }

    private static PasskeyCredential credentialOwnedByThePrincipal() {
        return PasskeyCredential.builder()
                .accountPrincipal(PRINCIPAL)
                // Stale on purpose: this is the identity at registration time, and nothing may read it.
                .userId(OLD_MXID)
                .userHandle("handle")
                .credentialId("cred-1")
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
        // The point is the KEY, not the call: nothing is ever looked up by the Matrix id. deleteAll may still
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
}
