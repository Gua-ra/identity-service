package me.sarahlacerda.gua.identityservice.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;

class OidcAccessTokenAuthenticationFilterTest {

    private OidcAccessTokenValidator tokenValidator;
    private OidcAccessTokenAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        tokenValidator = mock(OidcAccessTokenValidator.class);
        RequestMatcher sendMatcher = request -> "POST".equals(request.getMethod()) && "/otp/send".equals(request.getRequestURI());
        RequestMatcher verifyMatcher = request -> "POST".equals(request.getMethod()) && "/otp/verify".equals(request.getRequestURI());
        filter = new OidcAccessTokenAuthenticationFilter(tokenValidator, List.of(sendMatcher, verifyMatcher));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void openEndpointsBypassAuthentication() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/otp/send");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        verify(tokenValidator, never()).validate(any());
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void authenticatesValidBearerToken() throws ServletException, IOException {
        String token = "token-123";
        OidcAuthenticatedPrincipal principal = new OidcAuthenticatedPrincipal("@user:domain", "+15555551212", "User", Set.of("openid"));
        when(tokenValidator.validate(token)).thenReturn(Optional.of(principal));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secure");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        AtomicReference<Object> principalOnChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> principalOnChain.set(SecurityContextHolder.getContext().getAuthentication().getPrincipal());

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat(principalOnChain.get()).isInstanceOf(OidcAuthenticatedPrincipal.class);
        OidcAuthenticatedPrincipal authenticatedPrincipal = (OidcAuthenticatedPrincipal) principalOnChain.get();
        assertThat(authenticatedPrincipal.userId()).isEqualTo("@user:domain");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void rejectsMissingToken() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(tokenValidator, never()).validate(any());
    }

    @Test
    void rejectsInvalidToken() throws ServletException, IOException {
        String token = "invalid";
        when(tokenValidator.validate(token)).thenReturn(Optional.empty());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/secure");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
