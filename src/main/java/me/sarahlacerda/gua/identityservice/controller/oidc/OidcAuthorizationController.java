package me.sarahlacerda.gua.identityservice.controller.oidc;

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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorization;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationCode;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationRequest;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthorizationService;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenResponse;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcTokenService;

@RestController
@RequiredArgsConstructor
@Tag(
    name = "OIDC Authorization",
    description = "OAuth 2.0 authorization code endpoints backing the Matrix Authentication Service"
)
public class OidcAuthorizationController {

    private final OidcAuthorizationService authorizationService;
    private final OidcTokenService tokenService;

    @GetMapping("/oauth2/authorize")
    @Operation(
        summary = "Initiate the OAuth 2.0 authorization code flow",
        description = "Validates an OTP challenge for the supplied phone number and returns an authorization code via redirect."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "302", description = "OTP verified; redirecting with an authorization code"),
        @ApiResponse(responseCode = "400", description = "Unsupported response type or OTP validation failure", content = @Content)
    })
    public ResponseEntity<Void> authorize(
        @Parameter(description = "Must be set to `code` for the authorization code flow.", required = true)
        @RequestParam("response_type") String responseType,
        @Parameter(description = "Identifier registered by MAS for this upstream provider.", required = true)
        @RequestParam("client_id") String clientId,
        @Parameter(description = "Redirect URI supplied by MAS to receive the authorization code.", required = true)
        @RequestParam("redirect_uri") String redirectUri,
        @Parameter(description = "Requested scopes separated by spaces. Defaults to `openid` if omitted.")
        @RequestParam(value = "scope", required = false, defaultValue = "openid") String scope,
        @Parameter(description = "E.164 formatted phone number that received the OTP challenge.", required = true, example = "+12025550123")
        @RequestParam("phone_number") String phoneNumber,
        @Parameter(description = "One-time password previously issued to the phone number.", required = true, example = "123456")
        @RequestParam("otp_code") String otpCode,
        @Parameter(description = "Optional display name to persist for the Matrix account.")
        @RequestParam(value = "display_name", required = false) String displayName,
        @Parameter(description = "Opaque state returned to the client on success for CSRF mitigation.")
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
    @Operation(
        summary = "Exchange an authorization code for tokens",
        description = "Validates the authorization code issued by the authorize endpoint and returns an access token and ID token."
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Token exchange succeeded",
            content = @Content(schema = @Schema(implementation = OidcTokenResponse.class))
        ),
        @ApiResponse(responseCode = "400", description = "Invalid grant request", content = @Content)
    })
    public ResponseEntity<OidcTokenResponse> token(
        @Parameter(description = "Must be set to `authorization_code`.", required = true)
        @RequestParam("grant_type") String grantType,
        @Parameter(description = "Authorization code received from /oauth2/authorize.", required = true)
        @RequestParam("code") String code,
        @Parameter(description = "Redirect URI that was used when requesting the authorization code.", required = true)
        @RequestParam("redirect_uri") String redirectUri,
        @Parameter(description = "Client identifier issued to MAS for this upstream integration.", required = true)
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
