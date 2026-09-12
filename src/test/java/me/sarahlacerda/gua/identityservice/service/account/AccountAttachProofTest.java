package me.sarahlacerda.gua.identityservice.service.account;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.GenesisProofs;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.State;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The attack cases the attach proof exists to stop (ADM-008 decision 6).
 *
 * <p>The premise throughout: anyone can compose an authorize URL, so an attach handle is
 * attacker-controlled in both directions. The dangerous shape is an attacker's own genesis carried in a
 * URL that prefills the victim's number, which the victim's OTP then passes. What stops it is that the
 * attach also needs a signature over bytes the server chose for this session, under the key committed
 * inside the registered genesis.
 */
class AccountAttachProofTest {

    private static final String USER_ID = "@alice:example.org";

    private AccountGenesisRepository repository;
    private AccountGenesisService service;

    private TestEd25519.Pair authority;
    private AccountGenesis genesis;
    private AccountId accountId;
    private String handle;
    private AccountGenesisRecord row;

    @BeforeEach
    void setUp() {
        repository = mock(AccountGenesisRepository.class);
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getGenesis().setEnabled(true);
        properties.getGenesis().setProductionIssuance(true);
        service = new AccountGenesisService(repository, properties);

        authority = TestEd25519.generate();
        TestEd25519.Pair recovery = TestEd25519.generate();
        byte[] canonical = AccountGenesisCodec.encode(authority.rawPublicKey(),
                AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY, recovery.rawPublicKey(), new byte[16]);
        genesis = AccountGenesisCodec.decode(canonical);
        accountId = genesis.accountId();

        handle = "handle-from-the-login-hint";
        row = AccountGenesisRecord.pendingGenesis(accountId.value(), (short) 1, (short) 1,
                base64Url(canonical), base64Url(authority.rawPublicKey()),
                AccountGenesisService.sha256Hex(handle), Instant.now().plusSeconds(600));

        when(repository.findByAttachHandleHash(AccountGenesisService.sha256Hex(handle)))
                .thenReturn(Optional.of(row));
        when(repository.attach(anyString(), anyString(), anyString(), any(), any(), any())).thenReturn(1);
    }

    private static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /** A challenge the server issued for one session. */
    private String challenge() {
        return service.issueAttachChallenge();
    }

    private String proofOver(String challengeB64, AccountId signedAccountId, PrivateKey key) {
        byte[] preimage = GenesisProofs.attachProofPreimage(
                Base64.getUrlDecoder().decode(challengeB64), signedAccountId);
        return base64Url(TestEd25519.sign(key, preimage));
    }

    @Test
    void aProofOverThisSessionsChallengeAttaches() {
        String challenge = challenge();

        AccountId attached = service.attach(handle, challenge, proofOver(challenge, accountId,
                authority.privateKey()), USER_ID);

        assertThat(attached.value()).isEqualTo(accountId.value());
        verify(repository).attach(eq(accountId.value()), eq(AccountGenesisService.sha256Hex(handle)),
                eq(USER_ID), any(), eq(State.PENDING), eq(State.ATTACHED));
    }

    @Test
    void aChallengeRelayedFromAnotherSessionDoesNotAttach() {
        // The attacker completes a profile step of their own, captures the challenge issued there, and
        // relays it into the victim's session. The victim's session holds different bytes, and the
        // server signs nothing it was handed: it reads the challenge from its own session state.
        String attackersChallenge = challenge();
        String victimsChallenge = challenge();
        String proof = proofOver(attackersChallenge, accountId, authority.privateKey());

        assertThatThrownBy(() -> service.attach(handle, victimsChallenge, proof, USER_ID))
                .isInstanceOf(LoginFlowException.class)
                .extracting(e -> ((LoginFlowException) e).getCode())
                .isEqualTo("genesis_attach_failed");
        verify(repository, never()).attach(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void aProofIsNotReplayableOnceItHasAttached() {
        String challenge = challenge();
        String proof = proofOver(challenge, accountId, authority.privateKey());
        service.attach(handle, challenge, proof, USER_ID);

        // The successful attach cleared the handle, so the same proof finds no pending registration.
        when(repository.findByAttachHandleHash(AccountGenesisService.sha256Hex(handle)))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.attach(handle, challenge, proof, "@mallory:example.org"))
                .isInstanceOf(LoginFlowException.class);
    }

    @Test
    void aProofIsNotReplayableAgainstARowThatIsNoLongerPending() {
        String challenge = challenge();
        String proof = proofOver(challenge, accountId, authority.privateKey());
        // The row this handle names has already been attached: the shape the compare-and-set leaves
        // behind, built here rather than mutated, since the state is not settable from outside.
        when(repository.findByAttachHandleHash(AccountGenesisService.sha256Hex(handle)))
                .thenReturn(Optional.of(AccountGenesisRecord.attachedGenesis(accountId.value(), USER_ID,
                        (short) 1, (short) 1, row.getGenesisB64(), row.getAuthorityKeyB64(), Instant.now())));

        assertThatThrownBy(() -> service.attach(handle, challenge, proof, USER_ID))
                .isInstanceOf(LoginFlowException.class);
        verify(repository, never()).attach(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void aChallengeReusedAcrossTwoSessionsDoesNotAttachTwice() {
        // One challenge, two sessions. Even if a client reuses the value, the compare-and-set means only
        // the first attach wins; the second updates no row.
        String challenge = challenge();
        String proof = proofOver(challenge, accountId, authority.privateKey());
        when(repository.attach(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(1).thenReturn(0);

        service.attach(handle, challenge, proof, USER_ID);

        assertThatThrownBy(() -> service.attach(handle, challenge, proof, "@bob:example.org"))
                .isInstanceOf(LoginFlowException.class);
    }

    @Test
    void aProofSignedOverAnotherAccountIdDoesNotAttach() {
        // The client signs a well-formed proof, but over a different accountId than the one the stored
        // genesis derives. The server reads no accountId from the request, so the preimages differ.
        String challenge = challenge();
        AccountId someoneElse = AccountId.derive(AccountId.CLASS_GENESIS, "another account".getBytes());
        String proof = proofOver(challenge, someoneElse, authority.privateKey());

        assertThatThrownBy(() -> service.attach(handle, challenge, proof, USER_ID))
                .isInstanceOf(LoginFlowException.class);
        verify(repository, never()).attach(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void aProofUnderAnyOtherKeyDoesNotAttach() {
        // The planted-handle case: the attacker holds the handle but not the key committed inside the
        // genesis it names.
        String challenge = challenge();
        String proof = proofOver(challenge, accountId, TestEd25519.generate().privateKey());

        assertThatThrownBy(() -> service.attach(handle, challenge, proof, USER_ID))
                .isInstanceOf(LoginFlowException.class);
    }

    @Test
    void twoSessionsRacingOnOneHandleResolveToASingleAttach() {
        String first = challenge();
        String second = challenge();
        // Both hold a valid proof for their own session; the database decides which one lands.
        when(repository.attach(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(1).thenReturn(0);

        service.attach(handle, first, proofOver(first, accountId, authority.privateKey()), USER_ID);

        assertThatThrownBy(() -> service.attach(handle, second,
                proofOver(second, accountId, authority.privateKey()), "@bob:example.org"))
                .isInstanceOf(LoginFlowException.class);
    }

    @Test
    void anExpiredRegistrationDoesNotAttach() {
        row.setExpiresAt(Instant.now().minusSeconds(1));
        String challenge = challenge();

        assertThatThrownBy(() -> service.attach(handle, challenge,
                proofOver(challenge, accountId, authority.privateKey()), USER_ID))
                .isInstanceOf(LoginFlowException.class);
        verify(repository, never()).attach(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void aMissingProofOrChallengeFailsTheSignupRatherThanAttaching() {
        String challenge = challenge();

        assertThatThrownBy(() -> service.attach(handle, challenge, null, USER_ID))
                .isInstanceOf(LoginFlowException.class);
        assertThatThrownBy(() -> service.attach(handle, null,
                proofOver(challenge, accountId, authority.privateKey()), USER_ID))
                .isInstanceOf(LoginFlowException.class);
        assertThatThrownBy(() -> service.attach(handle, challenge, "not base64url!!", USER_ID))
                .isInstanceOf(LoginFlowException.class);
        verify(repository, never()).attach(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void anUnknownHandleFailsTheSignup() {
        when(repository.findByAttachHandleHash(anyString())).thenReturn(Optional.empty());
        String challenge = challenge();

        assertThatThrownBy(() -> service.attach("a handle nobody registered", challenge,
                proofOver(challenge, accountId, authority.privateKey()), USER_ID))
                .isInstanceOf(LoginFlowException.class);
    }

    @Test
    void theChallengeIs32CsprngBytesAndNeverRepeats() {
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            String challenge = service.issueAttachChallenge();
            assertThat(Base64.getUrlDecoder().decode(challenge))
                    .hasSize(GenesisProofs.ATTACH_CHALLENGE_LENGTH);
            seen.add(challenge);
        }

        assertThat(seen).hasSize(100);
    }
}
