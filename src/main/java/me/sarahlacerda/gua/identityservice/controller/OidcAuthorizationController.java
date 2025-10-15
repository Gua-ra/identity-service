package me.sarahlacerda.gua.identityservice.controller;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationRequest;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@RestController
@RequiredArgsConstructor
public class OidcAuthorizationController {

    private final OidcAuthorizationService authorizationService;
    private final OidcTokenService tokenService;

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<Void> authorize(
        @RequestParam("response_type") String responseType,
        @RequestParam("client_id") String clientId,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestParam(value = "scope", required = false, defaultValue = "openid") String scope,
        @RequestParam("phone_number") String phoneNumber,
        @RequestParam("otp_code") String otpCode,
        @RequestParam(value = "display_name", required = false) String displayName,
        @RequestParam(value = "state", required = false) String state
    ) {
        if (!"code".equals(responseType)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        OidcAuthorizationRequest request = new OidcAuthorizationRequest(
            clientId,
            redirectUri,
            parseScopes(scope),
            phoneNumber,
            otpCode,
            displayName
        );
        OidcAuthorizationCode authorizationCode = authorizationService.issueAuthorizationCode(request);

        UriComponentsBuilder redirect = UriComponentsBuilder.fromUriString(redirectUri)
            .queryParam("code", authorizationCode.code());
        if (state != null) {
            redirect.queryParam("state", state);
        }
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(redirect.toUriString())).build();
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<OidcTokenResponse> token(
        @RequestParam("grant_type") String grantType,
        @RequestParam("code") String code,
        @RequestParam("redirect_uri") String redirectUri,
        @RequestParam("client_id") String clientId
    ) {
        if (!"authorization_code".equals(grantType)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        Optional<OidcAuthorizationCode> stored = authorizationService.consumeAuthorizationCode(code);
        if (stored.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
        OidcAuthorizationCode authorizationCode = stored.get();
        if (!authorizationCode.redirectUri().equals(redirectUri) ||
            !authorizationCode.authorization().clientId().equals(clientId)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        OidcAuthorization authorization = authorizationCode.authorization();
        OidcTokenResponse tokens = tokenService.issueTokens(authorization);
        return ResponseEntity.ok(tokens);
    }

    private Set<String> parseScopes(String scope) {
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
}
