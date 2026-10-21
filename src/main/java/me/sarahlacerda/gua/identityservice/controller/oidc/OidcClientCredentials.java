package me.sarahlacerda.gua.identityservice.controller.oidc;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;

/**
 * The client id and secret a confidential client presents, by HTTP Basic ({@code client_secret_basic})
 * or in the form body ({@code client_secret_post}). Basic wins when both are present.
 *
 * <p>The Basic user and password are form-urlencoded before base64 (RFC 6749 section 2.3.1) and are
 * decoded here, which is how MAS sends them. A secret made only of unreserved characters reads the same
 * either way.
 */
record OidcClientCredentials(String clientId, String clientSecret) {

    private static final String BASIC_PREFIX = "Basic ";

    static OidcClientCredentials resolve(String authorizationHeader, String clientIdParam, String clientSecretParam) {
        if (authorizationHeader != null
                && authorizationHeader.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            String token = authorizationHeader.substring(BASIC_PREFIX.length()).trim();
            try {
                String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
                int separator = decoded.indexOf(':');
                if (separator < 0) {
                    throw malformedBasic();
                }
                return new OidcClientCredentials(
                        URLDecoder.decode(decoded.substring(0, separator), StandardCharsets.UTF_8),
                        URLDecoder.decode(decoded.substring(separator + 1), StandardCharsets.UTF_8));
            } catch (IllegalArgumentException ex) {
                throw malformedBasic();
            }
        }
        return new OidcClientCredentials(clientIdParam, clientSecretParam);
    }

    private static OidcInvalidRequestException malformedBasic() {
        return new OidcInvalidRequestException("invalid_request", "Malformed Basic authorization header");
    }
}
