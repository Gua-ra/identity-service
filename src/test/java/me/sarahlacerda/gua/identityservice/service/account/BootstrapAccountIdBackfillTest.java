package me.sarahlacerda.gua.identityservice.service.account;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** The backfill that gives every pre-existing account an accountId: idempotent, resumable, batched. */
class BootstrapAccountIdBackfillTest {

    private IdentityServiceProperties properties;
    private AccountScanner scanner;
    private AccountGenesisRepository repository;
    private AccountGenesisService genesisService;
    private BootstrapAccountIdBackfill backfill;

    private final List<String> minted = new ArrayList<>();

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        properties.getGenesis().getBootstrapBackfill().setBatchSize(2);
        scanner = mock(AccountScanner.class);
        repository = mock(AccountGenesisRepository.class);
        genesisService = mock(AccountGenesisService.class);
        backfill = new BootstrapAccountIdBackfill(properties, scanner, repository, genesisService);

        when(repository.findExistingUserIds(org.mockito.ArgumentMatchers.anyCollection()))
                .thenReturn(List.of());
        when(genesisService.bootstrap(anyString())).thenAnswer(call -> {
            minted.add(call.getArgument(0));
            return BootstrapGenesisCodec.mint().accountId();
        });
    }

    /** Pages the given accounts through the scanner in batches of the configured size. */
    private void accountsAre(String... userIds) {
        List<String> all = List.of(userIds);
        when(scanner.nextBatch(anyString(), anyInt())).thenAnswer(call -> {
            String cursor = call.getArgument(0);
            int limit = call.getArgument(1);
            return all.stream().filter(id -> id.compareTo(cursor) > 0).sorted().limit(limit).toList();
        });
    }

    @Test
    void itDoesNotRunOnStartupWhileTheFlagIsOff() {
        accountsAre("@a:example.org");

        backfill.backfillOnStartup();

        verifyNoInteractions(scanner);
        verifyNoInteractions(genesisService);
    }

    @Test
    void itRunsOnStartupWhenTheFlagIsOn() {
        properties.getGenesis().getBootstrapBackfill().setEnabled(true);
        accountsAre("@a:example.org", "@b:example.org");

        backfill.backfillOnStartup();

        assertThat(minted).containsExactly("@a:example.org", "@b:example.org");
    }

    @Test
    void everyAccountAcrossSeveralBatchesGetsAnAccountId() {
        accountsAre("@a:example.org", "@b:example.org", "@c:example.org", "@d:example.org", "@e:example.org");

        int count = backfill.run();

        assertThat(count).isEqualTo(5);
        assertThat(minted).containsExactly("@a:example.org", "@b:example.org", "@c:example.org",
                "@d:example.org", "@e:example.org");
    }

    @Test
    void accountsThatAlreadyHoldARowAreSkipped() {
        accountsAre("@a:example.org", "@b:example.org");
        when(repository.findExistingUserIds(org.mockito.ArgumentMatchers.anyCollection()))
                .thenReturn(List.of("@a:example.org"));

        int count = backfill.run();

        assertThat(count).isEqualTo(1);
        assertThat(minted).containsExactly("@b:example.org");
        verify(genesisService, never()).bootstrap("@a:example.org");
    }

    @Test
    void asecondRunOverAFullyBackfilledDeploymentWritesNothing() {
        accountsAre("@a:example.org", "@b:example.org", "@c:example.org");
        backfill.run();
        minted.clear();
        // Now every account holds a row, which is what the second run sees.
        when(repository.findExistingUserIds(org.mockito.ArgumentMatchers.anyCollection()))
                .thenAnswer(call -> new ArrayList<>(call.getArgument(0, java.util.Collection.class)));

        int count = backfill.run();

        assertThat(count).isZero();
        assertThat(minted).isEmpty();
    }

    @Test
    void oneFailingAccountDoesNotStopTheSweep() {
        accountsAre("@a:example.org", "@b:example.org", "@c:example.org");
        // doThrow, not when(...): when(mock.call(arg)) would invoke the mock to build the matcher, and
        // the Answer registered in setUp would record "@b" as minted before this stub replaced it.
        org.mockito.Mockito.doThrow(new IllegalStateException("transient"))
                .when(genesisService).bootstrap("@b:example.org");

        int count = backfill.run();

        assertThat(count).isEqualTo(2);
        assertThat(minted).containsExactly("@a:example.org", "@c:example.org");
    }

    @Test
    void itResumesFromTheLastAccountItSawRatherThanRestarting() {
        accountsAre("@a:example.org", "@b:example.org", "@c:example.org");

        backfill.run();

        // Keyset pagination: each page asks for accounts after the last id of the previous one, so a
        // rerun interrupted halfway never reprocesses the whole table.
        verify(scanner).nextBatch(eq(""), eq(2));
        verify(scanner).nextBatch(eq("@b:example.org"), eq(2));
        verify(scanner).nextBatch(eq("@c:example.org"), eq(2));
    }

    @Test
    void anEmptyDeploymentIsANoOp() {
        when(scanner.nextBatch(anyString(), anyInt())).thenReturn(List.of());

        assertThat(backfill.run()).isZero();
        verifyNoInteractions(genesisService);
    }

    @Test
    void theMintedIdsAreBootstrapClass() {
        accountsAre("@a:example.org");
        org.mockito.Mockito.doAnswer(call -> {
            AccountId id = BootstrapGenesisCodec.mint().accountId();
            assertThat(id.rootClass()).isEqualTo(AccountId.CLASS_BOOTSTRAP);
            return id;
        }).when(genesisService).bootstrap(anyString());

        assertThat(backfill.run()).isEqualTo(1);
    }
}
