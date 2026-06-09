package me.sarahlacerda.gua.identityservice.service.oidc;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

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

@Service
@RequiredArgsConstructor
public class OidcTokenService {

    private static final String TOKEN_TYPE = "Bearer";

    private final OidcProperties properties;
    private final RSAKey signingKey;

    public OidcTokenResponse issueTokens(OidcAuthorization authorization) {
        SignedJWT accessToken = buildJwt(authorization, properties.getAccessTokenTtl().toSeconds());
        SignedJWT idToken = buildJwt(authorization, properties.getIdTokenTtl().toSeconds());

        return new OidcTokenResponse(
            serialize(accessToken),
            properties.getAccessTokenTtl().toSeconds(),
            authorization.scopeAsString(),
            TOKEN_TYPE,
            serialize(idToken)
        );
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

            String scope = claims.getStringClaim("scope");
            Set<String> scopes = scope == null ? Set.of() : parseScopes(scope);
            Object nameClaim = claims.getClaim("name");
            String displayName = nameClaim != null ? nameClaim.toString() : null;

            return Optional.of(new OidcAuthenticatedPrincipal(
                claims.getSubject(),
                claims.getStringClaim("phone_number"),
                displayName,
                scopes
            ));
        } catch (ParseException | JOSEException ex) {
            return Optional.empty();
        }
    }

    private SignedJWT buildJwt(OidcAuthorization authorization, long ttlSeconds) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(ttlSeconds);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issuer(properties.getIssuer())
            .subject(authorization.userId())
            .audience(authorization.clientId())
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
            claims
        );
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

