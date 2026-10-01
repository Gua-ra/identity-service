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
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.service.security.EndOtherSessionsService;
import me.sarahlacerda.gua.identityservice.service.security.TokenRevocationService;

@Service
@RequiredArgsConstructor
public class OidcTokenService {

    private static final String TOKEN_TYPE = "Bearer";

    /** The authentication service ends every other session of the account when it sees this claim. */
    static final String END_OTHER_SESSIONS_CLAIM = "gua_end_other_sessions";

    private final OidcProperties properties;
    private final RSAKey signingKey;
    private final TokenRevocationService tokenRevocationService;
    private final EndOtherSessionsService endOtherSessionsService;

    public OidcTokenResponse issueTokens(OidcAuthorization authorization) {
        SignedJWT accessToken = buildJwt(authorization, properties.getAccessTokenTtl().toSeconds(), false);
        SignedJWT idToken = buildJwt(authorization, properties.getIdTokenTtl().toSeconds(), true);
        if (authorization.endOtherSessions()) {
            // Settled only once the claim has left in an ID token. A failed or abandoned login keeps it owed.
            endOtherSessionsService.settle(authorization.userId());
        }

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
            String audienceClientId = knownAudience(claims.getAudience()).orElse(null);
            if (audienceClientId == null) {
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
                    claims.getStringClaim("preferred_username"),
                    scopes,
                    audienceClientId));
        } catch (ParseException | JOSEException ex) {
            return Optional.empty();
        }
    }

    /** The hint must be an ID token this service signed. Expiry is ignored so a stale session can still re-verify. */
    public Optional<String> subjectFromIdTokenHint(String idTokenHint) {
        if (idTokenHint == null || idTokenHint.isBlank()) {
            return Optional.empty();
        }
        try {
            SignedJWT jwt = SignedJWT.parse(idTokenHint);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            if (!jwt.verify(new RSASSAVerifier(signingKey.toRSAPublicKey()))) {
                return Optional.empty();
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!properties.getIssuer().equals(claims.getIssuer())) {
                return Optional.empty();
            }
            return Optional.ofNullable(claims.getSubject());
        } catch (ParseException | JOSEException ex) {
            return Optional.empty();
        }
    }

    /** RFC 9068: accept a token only when its audience includes a registered client. */
    private Optional<String> knownAudience(List<String> audience) {
        if (audience == null || audience.isEmpty()) {
            return Optional.empty();
        }
        Set<String> knownClientIds = properties.getClients().stream()
                .map(OidcProperties.ClientRegistration::getClientId)
                .collect(Collectors.toSet());
        return audience.stream().filter(knownClientIds::contains).findFirst();
    }

    private SignedJWT buildJwt(OidcAuthorization authorization, long ttlSeconds, boolean includeNonce) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(ttlSeconds);

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(authorization.userId())
                .audience(authorization.clientId())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .claim("scope", authorization.scopeAsString());

        if (StringUtils.hasText(authorization.phoneNumber())) {
            builder.claim("phone_number", authorization.phoneNumber());
        }

        if (authorization.displayName() != null) {
            builder.claim("name", authorization.displayName());
        }
        if (authorization.preferredUsername() != null) {
            builder.claim("preferred_username", authorization.preferredUsername());
        }
        // The nonce belongs only in the ID token (OIDC core 3.1.3.7).
        if (includeNonce && authorization.nonce() != null) {
            builder.claim("nonce", authorization.nonce());
        }
        if (includeNonce && authorization.endOtherSessions()) {
            builder.claim(END_OTHER_SESSIONS_CLAIM, true);
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
