package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.util.List;
import java.util.Map;

import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import com.nimbusds.jose.jwk.JWKSet;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

@RestController
@RequiredArgsConstructor
@Tag(name = "OIDC Discovery", description = "OpenID Provider metadata and JSON Web Key Set endpoints")
public class OidcDiscoveryController {

    private final OidcProperties properties;
    private final JWKSet oidcPublicJwkSet;

    @GetMapping("/.well-known/openid-configuration")
    @Operation(
        summary = "Publish OpenID Provider configuration",
        description = "Exposes the discovery document consumed by MAS, including issuer metadata and endpoint URLs."
    )
    @ApiResponse(
        responseCode = "200",
        description = "Discovery metadata",
        content = @Content(schema = @Schema(implementation = Map.class))
    )
    public Map<String, Object> openidConfiguration() {
        return Map.ofEntries(
            Map.entry("issuer", properties.getIssuer()),
            Map.entry("authorization_endpoint", urlFor("/oauth2/authorize")),
            Map.entry("token_endpoint", urlFor("/oauth2/token")),
            Map.entry("userinfo_endpoint", urlFor("/userinfo")),
            Map.entry("jwks_uri", urlFor("/.well-known/jwks.json")),
            Map.entry("response_types_supported", List.of("code")),
            Map.entry("grant_types_supported", List.of("authorization_code")),
            Map.entry("scopes_supported", List.of("openid", "profile", "phone")),
            Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")),
            Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
            Map.entry("code_challenge_methods_supported", List.of("S256")),
            Map.entry("subject_types_supported", List.of("public"))
        );
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(
        summary = "Expose the JSON Web Key Set",
        description = "Publishes the RSA public signing key so relying parties can validate RS256-signed ID and access tokens."
    )
    @ApiResponse(
        responseCode = "200",
        description = "JWKS payload",
        content = @Content(schema = @Schema(implementation = Map.class))
    )
    public Map<String, Object> jwks() {
        return oidcPublicJwkSet.toJSONObject(true);
    }

    private String urlFor(String path) {
        return UriComponentsBuilder.fromUriString(properties.getIssuer()).path(path).build().toUriString();
    }
}

