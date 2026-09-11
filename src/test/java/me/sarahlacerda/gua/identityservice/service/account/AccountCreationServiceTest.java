package me.sarahlacerda.gua.identityservice.service.account;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.account.AccountCreationService.GenesisAttachment;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Which branch a new account takes: attach, bootstrap, or refuse (ADM-008 decision 6).
 *
 * <p>The rule being pinned down is that a handle that was presented and fails to attach fails the whole
 * signup, while a signup presenting no handle at all takes the bootstrap branch and is not a failure.
 */
class AccountCreationServiceTest {

    private static final String DIGEST = "digest";
    private static final String MASKED = "••••4567";
    private static final String USER_ID = "@alice:example.org";

    private DirectoryService directoryService;
    private AccountGenesisService accountGenesisService;
    private AccountCreationService service;

    @BeforeEach
    void setUp() {
        directoryService = mock(DirectoryService.class);
        accountGenesisService = mock(AccountGenesisService.class);
        service = new AccountCreationService(directoryService, accountGenesisService);
        when(accountGenesisService.isEnabled()).thenReturn(true);
    }

    private void create(GenesisAttachment attachment) {
        service.createAccount(DIGEST, MASKED, USER_ID, "Alice", "default", "alice", attachment);
    }

    private void assertTheAccountWasWritten() {
        verify(directoryService).upsertByDigest(DIGEST, MASKED, USER_ID, "Alice");
        verify(directoryService).assignRouting(DIGEST, "default", "alice");
    }

    @Test
    void aSessionCarryingAHandleAttachesTheGenesis() {
        when(accountGenesisService.attach("handle", "challenge", "proof", USER_ID))
                .thenReturn(AccountId.derive(AccountId.CLASS_GENESIS, new byte[] { 1 }));

        create(new GenesisAttachment("handle", "challenge", "proof", true));

        assertTheAccountWasWritten();
        verify(accountGenesisService).attach("handle", "challenge", "proof", USER_ID);
        verify(accountGenesisService, never()).bootstrap(anyString());
    }

    @Test
    void aSignupPresentingNoHandleTakesTheBootstrapBranch() {
        create(GenesisAttachment.none(false));

        assertTheAccountWasWritten();
        verify(accountGenesisService).bootstrap(USER_ID);
        verify(accountGenesisService, never()).attach(any(), any(), any(), any());
    }

    @Test
    void aHandleThatFailsToAttachFailsTheWholeSignup() {
        // No silent downgrade to a bootstrap id: the exception propagates out of the transactional
        // method, so the directory write made a moment ago rolls back with it.
        when(accountGenesisService.attach(anyString(), any(), any(), anyString()))
                .thenThrow(new LoginFlowException(org.springframework.http.HttpStatus.BAD_REQUEST,
                        "genesis_attach_failed", "nope"));

        assertThatThrownBy(() -> create(new GenesisAttachment("handle", "challenge", "bad proof", true)))
                .isInstanceOf(LoginFlowException.class)
                .extracting(e -> ((LoginFlowException) e).getCode())
                .isEqualTo("genesis_attach_failed");

        verify(accountGenesisService, never()).bootstrap(anyString());
    }

    @Test
    void aNativeSignupWithoutAHandleIsRefusedOnceGenesisIsRequired() {
        when(accountGenesisService.isRequiredForNative()).thenReturn(true);

        assertThatThrownBy(() -> create(GenesisAttachment.none(true)))
                .isInstanceOf(LoginFlowException.class)
                .extracting(e -> ((LoginFlowException) e).getCode())
                .isEqualTo("genesis_required");

        verify(accountGenesisService, never()).bootstrap(anyString());
    }

    @Test
    void aWebSignupIsUnaffectedByTheNativeRequirement() {
        when(accountGenesisService.isRequiredForNative()).thenReturn(true);

        create(GenesisAttachment.none(false));

        assertTheAccountWasWritten();
        verify(accountGenesisService).bootstrap(USER_ID);
    }

    @Test
    void withTheFeatureOffTheAccountIsWrittenAndNoGenesisRowIsTouched() {
        when(accountGenesisService.isEnabled()).thenReturn(false);

        create(new GenesisAttachment("handle", "challenge", "proof", true));

        assertTheAccountWasWritten();
        verify(accountGenesisService, never()).attach(any(), any(), any(), any());
        verify(accountGenesisService, never()).bootstrap(anyString());
    }

    @Test
    void withNoAttachmentAtAllTheAccountIsWrittenExactlyAsBefore() {
        // What the login flow passes when the feature is off: the creation path is then byte for byte
        // the two directory writes it has always made.
        service.createAccount(DIGEST, MASKED, USER_ID, "Alice", "default", "alice", null);

        assertTheAccountWasWritten();
        verify(accountGenesisService, never()).attach(any(), any(), any(), any());
        verify(accountGenesisService, never()).bootstrap(anyString());
    }

    @Test
    void theDirectoryIsWrittenBeforeTheGenesisSoBothShareOneTransaction() {
        when(accountGenesisService.attach(anyString(), any(), any(), anyString()))
                .thenReturn(AccountId.derive(AccountId.CLASS_GENESIS, new byte[] { 1 }));

        create(new GenesisAttachment("handle", "challenge", "proof", true));

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(directoryService, accountGenesisService);
        order.verify(directoryService).upsertByDigest(eq(DIGEST), any(), eq(USER_ID), any());
        order.verify(directoryService).assignRouting(eq(DIGEST), eq("default"), eq("alice"));
        order.verify(accountGenesisService).attach(anyString(), any(), any(), anyString());
    }

    @Test
    void aBootstrapAttachmentNeverConsultsTheDirectoryTwice() {
        create(GenesisAttachment.none(false));

        verify(directoryService).upsertByDigest(anyString(), any(), anyString(), any());
        verify(directoryService).assignRouting(anyString(), anyString(), anyString());
        org.mockito.Mockito.verifyNoMoreInteractions(directoryService);
    }

    @Test
    void anAttachmentWithABlankHandleIsTreatedAsNone() {
        create(new GenesisAttachment("   ", null, null, false));

        verify(accountGenesisService).bootstrap(USER_ID);
        verify(accountGenesisService, never()).attach(any(), any(), any(), any());
    }
}
