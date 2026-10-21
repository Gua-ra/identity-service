package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;

class UsernameAvailabilityTest {

    private static final Homeserver HOME = new Homeserver("home", "home.example", null, null, null, null, 1, true);
    private static final Homeserver OTHER = new Homeserver("other", "other.example", null, null, null, null, 1, false);

    private DirectoryService directoryService;
    private AccountGenesisService accountGenesisService;
    private MatrixAdminClient matrixAdminClient;
    private UsernameAvailability availability;

    @BeforeEach
    void setUp() {
        directoryService = mock(DirectoryService.class);
        accountGenesisService = mock(AccountGenesisService.class);
        matrixAdminClient = mock(MatrixAdminClient.class);
        HomeserverRegistry registry = mock(HomeserverRegistry.class);
        when(registry.all()).thenReturn(List.of(HOME, OTHER));
        availability = new UsernameAvailability(directoryService, accountGenesisService, registry, matrixAdminClient);
    }

    @Test
    void aUsernameNobodyHoldsIsFree() {
        assertThat(availability.isTaken("alice", "@alice:home.example")).isFalse();
    }

    @Test
    void aUsernameInTheDirectoryIsTakenWithoutAskingTheHomeserver() {
        when(directoryService.isUsernameTaken("alice")).thenReturn(true);

        assertThat(availability.isTaken("alice", "@alice:home.example")).isTrue();
        verify(matrixAdminClient, never()).userExists(any());
    }

    /**
     * The deleted account lived on another configured homeserver, including one closed to new accounts,
     * and the homeserver this signup would use reports the name free.
     */
    @Test
    void aUsernameADeletedAccountHeldOnAnyConfiguredHomeserverIsTaken() {
        when(accountGenesisService.isAnyDeleted(anyCollection())).thenAnswer(call -> {
            Collection<String> userIds = call.getArgument(0);
            return userIds.contains("@alice:other.example");
        });

        assertThat(availability.isTaken("alice", "@alice:home.example")).isTrue();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<String>> checked = ArgumentCaptor.forClass(Collection.class);
        verify(accountGenesisService).isAnyDeleted(checked.capture());
        assertThat(checked.getValue()).containsExactlyInAnyOrder("@alice:home.example", "@alice:other.example");
        verify(matrixAdminClient, never()).userExists(any());
    }

    @Test
    void aUsernameTheTargetHomeserverAlreadyHasIsTaken() {
        when(matrixAdminClient.userExists("@alice:home.example")).thenReturn(true);

        assertThat(availability.isTaken("alice", "@alice:home.example")).isTrue();
    }
}
