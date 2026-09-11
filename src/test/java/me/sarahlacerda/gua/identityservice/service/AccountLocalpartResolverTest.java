package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;

@ExtendWith(MockitoExtension.class)
class AccountLocalpartResolverTest {

    @Mock
    private DirectoryService directoryService;

    private AccountLocalpartResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new AccountLocalpartResolver(directoryService);
    }

    private static DirectoryEntry row(String userId, String username) {
        return DirectoryEntry.builder().phoneDigest("digest").userId(userId).username(username).build();
    }

    private static void assertRefused(ThrowingCallable call) {
        assertThatThrownBy(call).isInstanceOfSatisfying(LoginFlowException.class, ex -> {
            assertThat(ex.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(ex.getCode()).isEqualTo(AccountLocalpartResolver.INCONSISTENT_CODE);
        });
    }

    @Test
    void emitsTheStoredUsername() {
        assertThat(resolver.forExistingAccount("@alice:dev.local", List.of(row("@alice:dev.local", "alice"))))
                .isEqualTo("alice");
    }

    @Test
    void storedUsernameWinsOverADifferentMxidLocalpart() {
        assertThat(resolver.forExistingAccount("@alice:dev.local", List.of(row("@alice:dev.local", "alice.s"))))
                .isEqualTo("alice.s");
    }

    /** The S6 trap: re-keying user_id to a colon-bearing value must not change the localpart. */
    @Test
    void storedUsernameDoesNotDependOnTheUserId() {
        assertThat(resolver.forExistingAccount("ga1abc:x", List.of(row("ga1abc:x", "alice")))).isEqualTo("alice");
    }

    @Test
    void fallsBackToTheMxidLocalpartWhenNoUsernameIsStored() {
        assertThat(resolver.forExistingAccount("@alice:dev.local", List.of(row("@alice:dev.local", null))))
                .isEqualTo("alice");
        assertThat(resolver.forExistingAccount("@alice:dev.local", List.of())).isEqualTo("alice");
    }

    /** The old derivation gave both of these accounts the localpart {@code ga1abc}. */
    @Test
    void colonBearingIdsSharingAPrefixNeverShareALocalpart() {
        assertRefused(() -> resolver.forExistingAccount("ga1abc:x", List.of(row("ga1abc:x", null))));
        assertRefused(() -> resolver.forExistingAccount("ga1abc:y", List.of()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "u1", "alice", "alice:dev.local", "@alice" })
    void refusesAUserIdThatIsNotAMatrixUserIdWhenNoUsernameIsStored(String userId) {
        assertRefused(() -> resolver.forExistingAccount(userId, List.of()));
    }

    @ParameterizedTest
    @ValueSource(strings = { "@Alice:dev.local", "@al:dev.local", "@alice+x:dev.local",
            "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:dev.local" })
    void refusesAFallbackOutsideTheUsernameFormat(String userId) {
        assertRefused(() -> resolver.forExistingAccount(userId, List.of()));
    }

    @Test
    void refusesAStoredUsernameOutsideTheUsernameFormat() {
        assertRefused(() -> resolver.forExistingAccount("@alice:dev.local", List.of(row("@alice:dev.local", "Alice"))));
    }

    @Test
    void refusesAFallbackThatIsAnotherAccountsStoredUsername() {
        when(directoryService.resolveByUsername("alice"))
                .thenReturn(Optional.of(row("@alice:other.local", "alice")));

        assertRefused(() -> resolver.forExistingAccount("@alice:dev.local", List.of()));
    }

    @Test
    void acceptsAStoredUsernameHeldByTheSameAccount() {
        when(directoryService.resolveByUsername("alice")).thenReturn(Optional.of(row("@alice:dev.local", "alice")));

        assertThat(resolver.forExistingAccount("@alice:dev.local", List.of(row("@alice:dev.local", "alice"))))
                .isEqualTo("alice");
    }

    @Test
    void refusesTwoDifferentStoredUsernames() {
        assertRefused(() -> resolver.forExistingAccount("@alice:dev.local",
                List.of(row("@alice:dev.local", "alice"), row("@alice:dev.local", "alice.s"))));
    }

    @Test
    void refusesARowThatBelongsToAnotherAccount() {
        assertRefused(() -> resolver.forExistingAccount("@alice:dev.local", List.of(row("@bob:dev.local", "bob"))));
    }
}
