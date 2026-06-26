package me.sarahlacerda.gua.identityservice.client.matrix;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import reactor.core.publisher.Mono;

/**
 * GUA FORK: supplies a short-lived MAS access token for the Synapse admin API via the OAuth2
 * <em>client-credentials</em> grant ({@code grant_type=client_credentials}, scope
 * {@code urn:synapse:admin:*}), replacing the static {@code IDENTITY_MATRIX_ADMIN_TOKEN}.
 *
 * <p>Under MAS delegated auth (MSC3861) Synapse no longer validates tokens itself — it introspects
 * every bearer at MAS, and MAS-issued tokens are short-lived. A static token therefore goes stale and
 * is rejected (401). This provider fetches a fresh token on demand and caches it until shortly before
 * it expires.
 *
 * <p>Disabled (and {@link #getToken()} returns empty) unless the MAS client-credentials config is
 * present, so the legacy static-token path keeps working when this isn't configured.
 */
@Component
public class MasAdminTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(MasAdminTokenProvider.class);

    /** Refresh this far before the real expiry to avoid using a token that dies mid-request. */
    private static final Duration REFRESH_SKEW = Duration.ofSeconds(60);
    /** Fallback lifetime if MAS omits {@code expires_in}. */
    private static final long DEFAULT_TTL_SECONDS = 300;

    private final boolean enabled;
    private final WebClient tokenClient;
    private final String basicAuth;
    private final String scope;

    private final AtomicReference<CachedToken> cache = new AtomicReference<>();

    public MasAdminTokenProvider(WebClient.Builder webClientBuilder, IdentityServiceProperties properties) {
        IdentityServiceProperties.MatrixProperties matrix = properties.getMatrix();
        this.enabled = matrix.isClientCredentialsConfigured();
        if (enabled) {
            this.tokenClient = webClientBuilder.clone().baseUrl(matrix.getTokenUri()).build();
            this.basicAuth = "Basic " + Base64.getEncoder().encodeToString(
                    (matrix.getClientId() + ":" + matrix.getClientSecret()).getBytes(StandardCharsets.UTF_8));
            this.scope = matrix.getAdminScope();
            log.info("MAS client-credentials admin auth enabled (token endpoint configured, scope={})", scope);
        } else {
            this.tokenClient = null;
            this.basicAuth = null;
            this.scope = null;
            log.info("MAS client-credentials admin auth NOT configured; falling back to static admin token.");
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return a valid admin access token, fetching/refreshing as needed; empty when not configured.
     */
    public Mono<String> getToken() {
        if (!enabled) {
            return Mono.empty();
        }
        CachedToken current = cache.get();
        if (current != null && current.isValid()) {
            return Mono.just(current.token());
        }
        return fetchToken();
    }

    private Mono<String> fetchToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        if (scope != null && !scope.isBlank()) {
            form.add("scope", scope);
        }
        return tokenClient.post()
                .header(HttpHeaders.AUTHORIZATION, basicAuth)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(response -> {
                    long ttl = response.expiresIn() > 0 ? response.expiresIn() : DEFAULT_TTL_SECONDS;
                    Instant expiresAt = Instant.now().plusSeconds(ttl).minus(REFRESH_SKEW);
                    cache.set(new CachedToken(response.accessToken(), expiresAt));
                    log.debug("Obtained MAS admin token via client-credentials (ttl={}s)", ttl);
                    return response.accessToken();
                });
    }

    private record CachedToken(String token, Instant expiresAt) {
        boolean isValid() {
            return token != null && Instant.now().isBefore(expiresAt);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("expires_in") long expiresIn,
            @JsonProperty("token_type") String tokenType) {
    }
}
