package me.sarahlacerda.gua.identityservice.controller;

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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

@RestController
@RequiredArgsConstructor
@Tag(name = "OIDC Discovery", description = "OpenID Provider metadata and JSON Web Key Set endpoints")
public class OidcDiscoveryController {

    private final OidcProperties properties;

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
        return Map.of(
            "issuer", properties.getIssuer(),
            "authorization_endpoint", urlFor("/oauth2/authorize"),
            "token_endpoint", urlFor("/oauth2/token"),
            "userinfo_endpoint", urlFor("/userinfo"),
            "jwks_uri", urlFor("/.well-known/jwks.json"),
            "response_types_supported", List.of("code"),
            "grant_types_supported", List.of("authorization_code"),
            "scopes_supported", List.of("openid", "profile", "phone"),
            "token_endpoint_auth_methods_supported", List.of("none"),
            "id_token_signing_alg_values_supported", List.of("HS256")
        );
    }

    @GetMapping("/.well-known/jwks.json")
    @Operation(
        summary = "Expose the JSON Web Key Set",
        description = "Publishes the symmetric signing key parameters so relying parties can validate HMAC-signed ID tokens."
    )
    @ApiResponse(
        responseCode = "200",
        description = "JWKS payload",
        content = @Content(schema = @Schema(implementation = Map.class))
    )
    public Map<String, Object> jwks() {
        OctetSequenceKey key = new OctetSequenceKey.Builder(properties.signingKey())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.HS256)
            .keyID(properties.getJwkKeyId())
            .build();
        return new JWKSet(key).toJSONObject(false);
    }

    private String urlFor(String path) {
        return UriComponentsBuilder.fromUriString(properties.getIssuer()).path(path).build().toUriString();
    }
}
