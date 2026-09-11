package me.sarahlacerda.gua.identityservice.service.account;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.GenesisProofs;
import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.controller.dto.AccountGenesisRegisterResponse;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.State;
import me.sarahlacerda.gua.identityservice.exception.GenesisRegistrationException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Registration at {@code POST /account/genesis}, and the bootstrap branch (ADM-008 decisions 3 and 4). */
class AccountGenesisServiceTest {

    private AccountGenesisRepository repository;
    private IdentityServiceProperties properties;
    private AccountGenesisService service;

    private TestEd25519.Pair authority;
    private byte[] canonicalBytes;
    private AccountId accountId;

    @BeforeEach
    void setUp() {
        repository = mock(AccountGenesisRepository.class);
        properties = new IdentityServiceProperties();
        properties.getGenesis().setEnabled(true);
        properties.getGenesis().setProductionIssuance(true);
        service = new AccountGenesisService(repository, properties);

        authority = TestEd25519.generate();
        canonicalBytes = AccountGenesisCodec.encode(authority.rawPublicKey(),
                AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY,
                TestEd25519.generate().rawPublicKey(), new byte[16]);
        accountId = AccountGenesisCodec.decode(canonicalBytes).accountId();

        when(repository.findById(anyString())).thenReturn(Optional.empty());
        when(repository.save(any())).thenAnswer(call -> call.getArgument(0));
    }

    private static String b64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String validProof() {
        return b64(TestEd25519.sign(authority.privateKey(),
                GenesisProofs.genesisProofPreimage(canonicalBytes)));
    }

    @Test
    void aValidRegistrationStoresThePendingRowAndReturnsTheAccountId() {
        AccountGenesisRegisterResponse response = service.register(b64(canonicalBytes), validProof());

        assertThat(response.accountId()).isEqualTo(accountId.value());
        assertThat(response.attachHandle()).isNotBlank();
        assertThat(response.expiresAt()).isAfter(Instant.now());

        ArgumentCaptor<AccountGenesisRecord> saved = ArgumentCaptor.forClass(AccountGenesisRecord.class);
        verify(repository).save(saved.capture());
        AccountGenesisRecord row = saved.getValue();
        assertThat(row.getAccountId()).isEqualTo(accountId.value());
        assertThat(row.getOrigin()).isEqualTo(Origin.GENESIS);
        assertThat(row.getState()).isEqualTo(State.PENDING);
        assertThat(row.getUserId()).isNull();
        assertThat(row.getGenesisB64()).isEqualTo(b64(canonicalBytes));
        assertThat(row.getAuthorityKeyB64()).isEqualTo(b64(authority.rawPublicKey()));
    }

    @Test
    void onlyTheHashOfTheAttachHandleIsStored() {
        AccountGenesisRegisterResponse response = service.register(b64(canonicalBytes), validProof());

        ArgumentCaptor<AccountGenesisRecord> saved = ArgumentCaptor.forClass(AccountGenesisRecord.class);
        verify(repository).save(saved.capture());

        assertThat(saved.getValue().getAttachHandleHash())
                .isNotEqualTo(response.attachHandle())
                .isEqualTo(AccountGenesisService.sha256Hex(response.attachHandle()))
                .hasSize(64);
    }

    @Test
    void theStoredBytesAreTheBytesReceived() {
        service.register(b64(canonicalBytes), validProof());

        ArgumentCaptor<AccountGenesisRecord> saved = ArgumentCaptor.forClass(AccountGenesisRecord.class);
        verify(repository).save(saved.capture());
        byte[] stored = Base64.getUrlDecoder().decode(saved.getValue().getGenesisB64());

        assertThat(stored).isEqualTo(canonicalBytes);
        assertThat(AccountId.derive(AccountId.CLASS_GENESIS, stored).value())
                .isEqualTo(saved.getValue().getAccountId());
    }

    @Test
    void aSuccessfulRegistrationSweepsExpiredPendingRows() {
        // There is no scheduler in this application, so the sweep rides along on the write path.
        service.register(b64(canonicalBytes), validProof());

        verify(repository).deleteExpiredPending(any(), any());
    }

    @Test
    void aRefusedRegistrationWritesNothingAtAll() {
        properties.getGenesis().setEnabled(false);

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), validProof()))
                .isInstanceOf(GenesisRegistrationException.class);

        verify(repository, never()).save(any());
        verify(repository, never()).deleteExpiredPending(any(), any());
    }

    @Test
    void theEndpointIsUnavailableWhileTheFeatureIsOff() {
        properties.getGenesis().setEnabled(false);

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), validProof()))
                .isInstanceOf(GenesisRegistrationException.class)
                .extracting(e -> ((GenesisRegistrationException) e).getCode())
                .isEqualTo("genesis_disabled");
        verify(repository, never()).save(any());
    }

    @Test
    void aProofThatDoesNotVerifyIsRefused() {
        String wrongKeysProof = b64(TestEd25519.sign(TestEd25519.generate().privateKey(),
                GenesisProofs.genesisProofPreimage(canonicalBytes)));

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), wrongKeysProof))
                .isInstanceOf(GenesisRegistrationException.class)
                .extracting(e -> ((GenesisRegistrationException) e).getCode())
                .isEqualTo("invalid_genesis_proof");
        verify(repository, never()).save(any());
    }

    @Test
    void aProofOverOtherBytesIsRefused() {
        byte[] otherBytes = AccountGenesisCodec.encode(authority.rawPublicKey(),
                AccountGenesis.RECOVERY_FRAMEWORK_COMMITTED_KEY,
                TestEd25519.generate().rawPublicKey(), new byte[] { 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 });
        String proofOverOther = b64(TestEd25519.sign(authority.privateKey(),
                GenesisProofs.genesisProofPreimage(otherBytes)));

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), proofOverOther))
                .isInstanceOf(GenesisRegistrationException.class);
    }

    @Test
    void framework0x01IsRefusedWhileProductionIssuanceIsOff() {
        properties.getGenesis().setProductionIssuance(false);

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), validProof()))
                .isInstanceOf(GenesisRegistrationException.class)
                .extracting(e -> ((GenesisRegistrationException) e).getCode())
                .isEqualTo("genesis_issuance_not_permitted");
        verify(repository, never()).save(any());
    }

    @Test
    void productionIssuanceIsOffByDefault() {
        assertThat(new IdentityServiceProperties().getGenesis().isProductionIssuance()).isFalse();
        assertThat(new IdentityServiceProperties().getGenesis().isEnabled()).isFalse();
    }

    @Test
    void aMalformedGenesisIsRefusedByTheCodec() {
        assertThatThrownBy(() -> service.register(b64(new byte[10]), validProof()))
                .isInstanceOf(InvalidGenesisException.class);
        assertThatThrownBy(() -> service.register("this is not base64url!!", validProof()))
                .isInstanceOf(InvalidGenesisException.class);
    }

    @Test
    void reRegisteringTheSameBytesWhilePendingRotatesTheHandle() {
        AccountGenesisRecord pending = AccountGenesisRecord.pendingGenesis(accountId.value(), (short) 1, (short) 1,
                b64(canonicalBytes), b64(authority.rawPublicKey()), "an-old-hash", Instant.now().plusSeconds(60));
        when(repository.findById(accountId.value())).thenReturn(Optional.of(pending));

        AccountGenesisRegisterResponse response = service.register(b64(canonicalBytes), validProof());

        assertThat(response.accountId()).isEqualTo(accountId.value());
        assertThat(pending.getAttachHandleHash())
                .isEqualTo(AccountGenesisService.sha256Hex(response.attachHandle()))
                .isNotEqualTo("an-old-hash");
    }

    @Test
    void reRegisteringAnAlreadyAttachedGenesisIsAConflict() {
        AccountGenesisRecord attached = AccountGenesisRecord.attachedBootstrap(accountId.value(),
                "@alice:example.org", (short) 1, (short) 1, b64(canonicalBytes), Instant.now());
        when(repository.findById(accountId.value())).thenReturn(Optional.of(attached));

        assertThatThrownBy(() -> service.register(b64(canonicalBytes), validProof()))
                .isInstanceOf(GenesisRegistrationException.class)
                .extracting(e -> ((GenesisRegistrationException) e).getCode())
                .isEqualTo("genesis_already_attached");
    }

    @Test
    void bootstrapMintsABootstrapClassAccountIdMarkedForAnAuditor() {
        when(repository.findByUserId("@alice:example.org")).thenReturn(Optional.empty());

        AccountId minted = service.bootstrap("@alice:example.org");

        ArgumentCaptor<AccountGenesisRecord> saved = ArgumentCaptor.forClass(AccountGenesisRecord.class);
        verify(repository).save(saved.capture());
        AccountGenesisRecord row = saved.getValue();

        assertThat(minted.isGenesisRooted()).isFalse();
        assertThat(minted.rootClass()).isEqualTo(AccountId.CLASS_BOOTSTRAP);
        assertThat(row.getOrigin()).isEqualTo(Origin.BOOTSTRAP);
        assertThat(row.getState()).isEqualTo(State.ATTACHED);
        assertThat(row.getAuthorityKeyB64()).isNull();
        assertThat(row.getUserId()).isEqualTo("@alice:example.org");
    }

    @Test
    void theBootstrapEntropyIsNotDerivedFromTheAccount() {
        // Two accounts whose ids differ only by localpart must not produce related genesis bytes: the
        // entropy is random, never the MXID or the phone (ADM-001 L4, L15).
        when(repository.findByUserId(anyString())).thenReturn(Optional.empty());

        AccountId first = service.bootstrap("@alice:example.org");
        AccountId second = service.bootstrap("@alice:example.org");

        assertThat(first.value()).isNotEqualTo(second.value());
    }

    @Test
    void bootstrapIsIdempotentForAnAccountThatAlreadyHasAnId() {
        String existingId = BootstrapGenesisCodec.mint().accountId().value();
        AccountGenesisRecord existing = AccountGenesisRecord.attachedBootstrap(existingId, "@alice:example.org",
                (short) 1, (short) 0, b64(new byte[22]), Instant.now());
        when(repository.findByUserId("@alice:example.org")).thenReturn(Optional.of(existing));

        assertThat(service.bootstrap("@alice:example.org").value()).isEqualTo(existingId);
        verify(repository, never()).save(any());
    }
}
