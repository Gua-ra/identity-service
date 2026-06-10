package me.sarahlacerda.gua.identityservice.service.oidc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.exception.OidcClientAuthenticationException;
import me.sarahlacerda.gua.identityservice.exception.OidcInvalidRequestException;

/**
 * Validates OIDC client authentication, redirect URIs, scopes, and PKCE per RFC 6749 + RFC 7636.
 */
@Service
@RequiredArgsConstructor
public class OidcClientService {

    private static final Logger log = LoggerFactory.getLogger(OidcClientService.class);
    private static final String PKCE_METHOD_S256 = "S256";

    private final OidcProperties properties;
    private final PasswordEncoder passwordEncoder;

    private Map<String, RegisteredClient> clientsById = Map.of();

    @PostConstruct
    void initialize() {
        Map<String, RegisteredClient> map = new HashMap<>();
        for (OidcProperties.ClientRegistration registration : properties.getClients()) {
            boolean publicClient = registration.getClientSecret() == null || registration.getClientSecret().isBlank();
            String hashedSecret = publicClient ? null : passwordEncoder.encode(registration.getClientSecret());
            RegisteredClient client = new RegisteredClient(
                registration.getClientId(),
                hashedSecret,
                publicClient,
                List.copyOf(registration.getRedirectUris()),
                Set.copyOf(registration.getAllowedScopes()),
                publicClient || registration.isRequirePkce()
            );
            map.put(client.clientId(), client);
        }
        this.clientsById = Map.copyOf(map);
        log.info("Registered {} OIDC clients", clientsById.size());
    }

    public RegisteredClient requireClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new OidcInvalidRequestException("invalid_request", "client_id is required");
        }
        RegisteredClient client = clientsById.get(clientId);
        if (client == null) {
            throw new OidcInvalidRequestException("invalid_client", "Unknown client_id");
        }
        return client;
    }

    public void validateRedirectUri(RegisteredClient client, String redirectUri) {
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new OidcInvalidRequestException("invalid_request", "redirect_uri is required");
        }
        if (!client.redirectUris().contains(redirectUri)) {
            throw new OidcInvalidRequestException("invalid_request", "redirect_uri is not registered for this client");
        }
    }

    public void validateScope(RegisteredClient client, Set<String> requestedScopes) {
        for (String scope : requestedScopes) {
            if (!client.allowedScopes().contains(scope)) {
                throw new OidcInvalidRequestException("invalid_scope", "Scope not permitted: " + scope);
            }
        }
    }

    /**
     * Validates code_challenge_method and challenge format. Returns true when PKCE is in use for this request.
     */
    public boolean validateChallenge(RegisteredClient client, String codeChallenge, String codeChallengeMethod) {
        if (codeChallenge == null || codeChallenge.isBlank()) {
            if (client.requirePkce()) {
                throw new OidcInvalidRequestException("invalid_request", "PKCE code_challenge is required for this client");
            }
            return false;
        }
        if (codeChallengeMethod != null && !PKCE_METHOD_S256.equals(codeChallengeMethod)) {
            throw new OidcInvalidRequestException("invalid_request", "Only S256 code_challenge_method is supported");
        }
        if (codeChallenge.length() < 43 || codeChallenge.length() > 128) {
            throw new OidcInvalidRequestException("invalid_request", "code_challenge must be 43..128 characters");
        }
        return true;
    }

    public void authenticateClient(RegisteredClient client, String suppliedSecret) {
        if (client.publicClient()) {
            if (suppliedSecret != null && !suppliedSecret.isBlank()) {
                throw new OidcClientAuthenticationException("Public client must not present a client_secret");
            }
            return;
        }
        if (suppliedSecret == null || suppliedSecret.isBlank()) {
            throw new OidcClientAuthenticationException("client_secret is required for confidential clients");
        }
        if (!passwordEncoder.matches(suppliedSecret, client.hashedSecret())) {
            throw new OidcClientAuthenticationException("Invalid client_secret");
        }
    }

    /**
     * Verifies that the supplied PKCE verifier matches the previously-supplied challenge using S256.
     * Throws when PKCE was used at /authorize but the verifier is missing or wrong.
     */
    public void verifyPkce(Optional<String> storedChallenge, String suppliedVerifier) {
        if (storedChallenge.isEmpty()) {
            if (suppliedVerifier != null && !suppliedVerifier.isBlank()) {
                throw new OidcInvalidRequestException("invalid_request", "Authorization request did not use PKCE");
            }
            return;
        }
        if (suppliedVerifier == null || suppliedVerifier.isBlank()) {
            throw new OidcInvalidRequestException("invalid_grant", "code_verifier is required");
        }
        if (suppliedVerifier.length() < 43 || suppliedVerifier.length() > 128) {
            throw new OidcInvalidRequestException("invalid_grant", "code_verifier must be 43..128 characters");
        }
        String computed = s256(suppliedVerifier);
        if (!constantTimeEquals(computed, storedChallenge.get())) {
            throw new OidcInvalidRequestException("invalid_grant", "code_verifier does not match the code_challenge");
        }
    }

    private static String s256(String verifier) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int r = 0;
        for (int i = 0; i < a.length(); i++) r |= a.charAt(i) ^ b.charAt(i);
        return r == 0;
    }

    public record RegisteredClient(
        String clientId,
        String hashedSecret,
        boolean publicClient,
        List<String> redirectUris,
        Set<String> allowedScopes,
        boolean requirePkce
    ) {}
}
