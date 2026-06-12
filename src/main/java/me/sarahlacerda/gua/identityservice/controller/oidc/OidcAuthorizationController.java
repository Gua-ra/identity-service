package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSessionService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationRequest;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcClientService.RegisteredClient;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@RestController
@RequiredArgsConstructor
@Tag(name = "OIDC Authorization", description = "OAuth 2.0 authorization code endpoints backing the Matrix Authentication Service")
public class OidcAuthorizationController {

    private final OidcAuthorizationService authorizationService;
    private final OidcTokenService tokenService;
    private final OidcClientService clientService;
    private final LoginSessionService loginSessionService;
    private final LoginFlowProperties loginProperties;

    @GetMapping("/oauth2/authorize")
    @Operation(summary = "Initiate the OAuth 2.0 authorization code flow", description = "Entry point used by Matrix Authentication Service. Validates the OIDC request, starts a "
            + "browser login session, and redirects to the interactive login UI (phone -> OTP -> PIN/profile) "
            + "which issues the authorization code once the user is authenticated. Supports PKCE (RFC 7636) via "
            + "code_challenge / code_challenge_method=S256.")
    @ApiResponses({
            @ApiResponse(responseCode = "302", description = "Redirecting to the login UI, or back to the client with an authorization code"),
            @ApiResponse(responseCode = "400", description = "Unsupported response type, unknown client, or invalid request", content = @Content)
    })
    public ResponseEntity<Void> authorize(
            @Parameter(description = "Must be set to `code` for the authorization code flow.", required = true) @RequestParam("response_type") String responseType,
            @Parameter(description = "Identifier registered with this provider.", required = true) @RequestParam("client_id") String clientId,
            @Parameter(description = "Redirect URI; must exactly match one registered for the client.", required = true) @RequestParam("redirect_uri") String redirectUri,
            @Parameter(description = "Requested scopes separated by spaces. Defaults to `openid` if omitted.") @RequestParam(value = "scope", required = false, defaultValue = "openid") String scope,
            @Parameter(description = "Opaque state returned to the client on success for CSRF mitigation.") @RequestParam(value = "state", required = false) String state,
            @Parameter(description = "String value used to associate the client session with the ID token (OIDC nonce).") @RequestParam(value = "nonce", required = false) String nonce,
            @Parameter(description = "PKCE code challenge (base64url, 43-128 chars). Required for public clients.") @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @Parameter(description = "PKCE code_challenge_method. Only S256 is supported.") @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @Parameter(description = "Optional login hint (E.164 phone) forwarded by MAS to pre-fill the login UI.") @RequestParam(value = "login_hint", required = false) String loginHint,
            @Parameter(description = "Deprecated: direct phone number for the non-interactive flow. Omit to use the interactive login UI.") @RequestParam(value = "phone_number", required = false) String phoneNumber,
            @Parameter(description = "Deprecated: OTP for the non-interactive flow. Omit to use the interactive login UI.") @RequestParam(value = "otp_code", required = false) String otpCode,
            @Parameter(description = "Optional display name (non-interactive flow only).") @RequestParam(value = "display_name", required = false) String displayName) {
        if (!"code".equals(responseType)) {
            throw new OidcInvalidRequestException("unsupported_response_type", "Only response_type=code is supported");
        }

        RegisteredClient client = clientService.requireClient(clientId);
        clientService.validateRedirectUri(client, redirectUri);
        Set<String> scopes = parseScopes(scope);
        clientService.validateScope(client, scopes);
        clientService.validateChallenge(client, codeChallenge, codeChallengeMethod);

        // Legacy non-interactive flow: credentials supplied directly as query params.
        // Retained for backward compatibility; new clients omit them and use the
        // interactive login UI below.
        if (phoneNumber != null && otpCode != null) {
            OidcAuthorizationRequest request = new OidcAuthorizationRequest(
                    clientId, redirectUri, scopes, phoneNumber, otpCode, displayName, codeChallenge,
                    codeChallengeMethod);
            OidcAuthorizationCode authorizationCode = authorizationService.issueAuthorizationCode(request);
            UriComponentsBuilder redirect = UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam("code", authorizationCode.code());
            if (state != null) {
                redirect.queryParam("state", state);
            }
            return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirect.toUriString())).build();
        }

        // Interactive flow: park the validated request in a login session and hand off
        // to the browser UI, which walks phone -> OTP -> PIN/profile before the
        // authorization code is issued at /login/**.
        LoginSession session = new LoginSession();
        session.setClientId(clientId);
        session.setRedirectUri(redirectUri);
        session.setScope(new ArrayList<>(scopes));
        session.setState(state);
        session.setNonce(nonce);
        session.setCodeChallenge(codeChallenge);
        session.setCodeChallengeMethod(codeChallengeMethod);
        session.setPhase(LoginSession.Phase.PHONE);
        session.setPhoneHint(normalizeLoginHint(loginHint));
        session.setCsrfToken(loginSessionService.newToken());
        String sessionId = loginSessionService.create(session);

        ResponseCookie cookie = ResponseCookie.from(loginProperties.getCookieName(), sessionId)
                .httpOnly(true)
                .secure(loginProperties.isCookieSecure())
                .sameSite("Lax")
                .path("/")
                .maxAge(loginProperties.getSessionTtl())
                .build();

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .location(URI.create(loginProperties.getUiUrl()))
                .build();
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Exchange an authorization code for tokens", description = "Validates the authorization code, client authentication, and PKCE verifier, then returns RS256-signed access and ID tokens.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token exchange succeeded", content = @Content(schema = @Schema(implementation = OidcTokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid grant request", content = @Content),
            @ApiResponse(responseCode = "401", description = "Client authentication failed", content = @Content)
    })
    public ResponseEntity<OidcTokenResponse> token(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @Parameter(description = "Must be set to `authorization_code`.", required = true) @RequestParam("grant_type") String grantType,
            @Parameter(description = "Authorization code received from /oauth2/authorize.", required = true) @RequestParam("code") String code,
            @Parameter(description = "Redirect URI that was used when requesting the authorization code.", required = true) @RequestParam("redirect_uri") String redirectUri,
            @Parameter(description = "Client identifier. May also be supplied via HTTP Basic auth.") @RequestParam(value = "client_id", required = false) String clientIdParam,
            @Parameter(description = "Client secret for confidential clients. May also be supplied via HTTP Basic auth.") @RequestParam(value = "client_secret", required = false) String clientSecretParam,
            @Parameter(description = "PKCE code verifier matching the code_challenge supplied at authorize time.") @RequestParam(value = "code_verifier", required = false) String codeVerifier) {
        if (!"authorization_code".equals(grantType)) {
            throw new OidcInvalidRequestException("unsupported_grant_type",
                    "Only authorization_code grant is supported");
        }

        ClientCredentials credentials = resolveClientCredentials(authorizationHeader, clientIdParam, clientSecretParam);
        RegisteredClient client = clientService.requireClient(credentials.clientId());
        clientService.authenticateClient(client, credentials.clientSecret());

        Optional<OidcAuthorizationCode> stored = authorizationService.consumeAuthorizationCode(code);
        if (stored.isEmpty()) {
            throw new OidcInvalidRequestException("invalid_grant", "Authorization code is unknown or already used");
        }
        OidcAuthorizationCode authorizationCode = stored.get();
        if (!authorizationCode.redirectUri().equals(redirectUri)) {
            throw new OidcInvalidRequestException("invalid_grant",
                    "redirect_uri does not match the authorization request");
        }
        if (!authorizationCode.authorization().clientId().equals(client.clientId())) {
            throw new OidcInvalidRequestException("invalid_grant",
                    "Authorization code was issued to a different client");
        }

        clientService.verifyPkce(authorizationCode.codeChallenge(), codeVerifier);

        OidcAuthorization authorization = authorizationCode.authorization();
        OidcTokenResponse tokens = tokenService.issueTokens(authorization);
        return ResponseEntity.ok(tokens);
    }

    private static ClientCredentials resolveClientCredentials(String authorizationHeader, String clientIdParam,
            String clientSecretParam) {
        if (authorizationHeader != null && authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            String token = authorizationHeader.substring(6).trim();
            try {
                String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
                int sep = decoded.indexOf(':');
                if (sep < 0) {
                    throw new OidcInvalidRequestException("invalid_request", "Malformed Basic authorization header");
                }
                return new ClientCredentials(decoded.substring(0, sep), decoded.substring(sep + 1));
            } catch (IllegalArgumentException ex) {
                throw new OidcInvalidRequestException("invalid_request", "Malformed Basic authorization header");
            }
        }
        return new ClientCredentials(clientIdParam, clientSecretParam);
    }

    private static Set<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        String[] parts = scope.split(" ");
        Set<String> scopes = new LinkedHashSet<>();
        for (String part : parts) {
            if (!part.isBlank()) {
                scopes.add(part);
            }
        }
        return scopes.isEmpty() ? Set.of() : scopes;
    }

    /**
     * Normalizes an OIDC {@code login_hint} into a bare E.164 phone number. Matrix
     * clients may prefix the hint (e.g. {@code "phone:+5511..."} or
     * {@code "mxid:..."}); we keep only a phone-like value and ignore anything
     * else.
     */
    private static String normalizeLoginHint(String loginHint) {
        if (loginHint == null || loginHint.isBlank()) {
            return null;
        }
        String value = loginHint.trim();
        int colon = value.indexOf(':');
        if (colon >= 0) {
            String prefix = value.substring(0, colon).toLowerCase(java.util.Locale.ROOT);
            // Only unwrap a phone-style hint; an mxid hint is not a phone number.
            if (prefix.equals("phone") || prefix.equals("tel") || prefix.equals("msisdn")) {
                value = value.substring(colon + 1).trim();
            }
        }
        return value.startsWith("+") ? value : null;
    }

    private record ClientCredentials(String clientId, String clientSecret) {
    }
}
