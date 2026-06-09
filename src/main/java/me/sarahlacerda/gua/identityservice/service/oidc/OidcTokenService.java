package me.sarahlacerda.gua.identityservice.service.oidc;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

@Service
@RequiredArgsConstructor
public class OidcTokenService {

    private static final String TOKEN_TYPE = "Bearer";

    private final OidcProperties properties;
    private final RSAKey signingKey;
    private final TokenRevocationService tokenRevocationService;

    public OidcTokenResponse issueTokens(OidcAuthorization authorization) {
        SignedJWT accessToken = buildJwt(authorization, properties.getAccessTokenTtl().toSeconds());
        SignedJWT idToken = buildJwt(authorization, properties.getIdTokenTtl().toSeconds());

        return new OidcTokenResponse(
                serialize(accessToken),
                properties.getAccessTokenTtl().toSeconds(),
                authorization.scopeAsString(),
                TOKEN_TYPE,
                serialize(idToken));
    }

    public Optional<OidcAuthenticatedPrincipal> parseAccessToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            if (!jwt.verify(new RSASSAVerifier(signingKey.toRSAPublicKey()))) {
                return Optional.empty();
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant now = Instant.now();
            if (claims.getExpirationTime() == null || now.isAfter(claims.getExpirationTime().toInstant())) {
                return Optional.empty();
            }
            if (!properties.getIssuer().equals(claims.getIssuer())) {
                return Optional.empty();
            }
            if (!hasKnownAudience(claims.getAudience())) {
                return Optional.empty();
            }
            Instant issuedAt = claims.getIssueTime() == null ? null : claims.getIssueTime().toInstant();
            if (tokenRevocationService.isRevoked(claims.getSubject(), issuedAt)) {
                return Optional.empty();
            }

            String scope = claims.getStringClaim("scope");
            Set<String> scopes = scope == null ? Set.of() : parseScopes(scope);
            Object nameClaim = claims.getClaim("name");
            String displayName = nameClaim != null ? nameClaim.toString() : null;

            return Optional.of(new OidcAuthenticatedPrincipal(
                    claims.getSubject(),
                    claims.getStringClaim("phone_number"),
                    displayName,
                    scopes));
        } catch (ParseException | JOSEException ex) {
            return Optional.empty();
        }
    }

    /**
     * Per RFC 9068 a resource server must reject access tokens that were not issued
     * for it. Every token we mint carries the requesting client id as its audience,
     * so we accept a token only when its audience includes a currently-registered
     * client.
     */
    private boolean hasKnownAudience(List<String> audience) {
        if (audience == null || audience.isEmpty()) {
            return false;
        }
        Set<String> knownClientIds = properties.getClients().stream()
                .map(OidcProperties.ClientRegistration::getClientId)
                .collect(Collectors.toSet());
        return audience.stream().anyMatch(knownClientIds::contains);
    }

    private SignedJWT buildJwt(OidcAuthorization authorization, long ttlSeconds) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(ttlSeconds);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(authorization.userId())
                .audience(authorization.clientId())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .claim("scope", authorization.scopeAsString())
                .claim("phone_number", authorization.phoneNumber());

        if (authorization.displayName() != null) {
            builder.claim("name", authorization.displayName());
        }

        JWTClaimsSet claims = builder.build();
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims);
        try {
            signedJWT.sign(new RSASSASigner(signingKey.toRSAPrivateKey()));
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to sign JWT", ex);
        }
        return signedJWT;
    }

    private String serialize(SignedJWT jwt) {
        try {
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to serialize JWT", ex);
        }
    }

    private Set<String> parseScopes(String scopeClaim) {
        if (scopeClaim.isBlank()) {
            return Set.of();
        }
        String[] parts = scopeClaim.split(" ");
        Set<String> scopes = new LinkedHashSet<>();
        for (String part : parts) {
            if (!part.isBlank()) {
                scopes.add(part);
            }
        }
        return scopes.isEmpty() ? Set.of() : scopes;
    }
}
