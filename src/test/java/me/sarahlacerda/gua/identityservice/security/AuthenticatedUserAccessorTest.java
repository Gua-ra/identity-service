package me.sarahlacerda.gua.identityservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

class AuthenticatedUserAccessorTest {

    private AuthenticatedUserAccessor accessor;

    @BeforeEach
    void setUp() {
        accessor = new AuthenticatedUserAccessor();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void currentUserIdReturnsEmptyWhenUnauthenticated() {
        Optional<String> result = accessor.currentUserId();
        assertThat(result).isEmpty();
    }

    @Test
    void currentUserIdReturnsPrincipalWhenPresent() {
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("@user:gua.global", "token", null)
        );

        assertThat(accessor.currentUserId()).contains("@user:gua.global");
    }

    @Test
    void requireCurrentUserIdThrowsWhenMissing() {
        assertThatThrownBy(accessor::requireCurrentUserId)
            .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void requireUserIdMatchesValidatesEquality() {
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("@user:gua.global", "token", null)
        );

        accessor.requireUserIdMatches("@user:gua.global");

        assertThatThrownBy(() -> accessor.requireUserIdMatches("@other:gua.global"))
            .isInstanceOf(AccessDeniedException.class)
            .hasMessageContaining("Token user does not match");
    }
}
