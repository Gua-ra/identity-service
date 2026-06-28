package me.sarahlacerda.gua.identityservice.client.matrix;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;
import reactor.core.publisher.Mono;

@Component
public class WebClientMatrixAdminClient implements MatrixAdminClient {

    private static final Logger log = LoggerFactory.getLogger(WebClientMatrixAdminClient.class);

    private final WebClient adminClient;
    private final WebClient clientApi;

    public WebClientMatrixAdminClient(WebClient.Builder webClientBuilder,
                                      IdentityServiceProperties properties,
                                      MasAdminTokenProvider tokenProvider) {
        IdentityServiceProperties.MatrixProperties matrix = properties.getMatrix();
        // GUA FORK: authenticate the Synapse admin API with a fresh MAS client-credentials token
        // (auto-refreshed) when configured; otherwise fall back to the static admin token. The bearer
        // is injected per-request via a filter rather than a construction-time default header, so the
        // short-lived MAS token is always current.
        this.adminClient = webClientBuilder.clone()
                .baseUrl(matrix.getAdminApiBaseUrl())
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .filter(adminAuthFilter(tokenProvider, matrix.getAdminAccessToken()))
                .filter(maskingRequestLogger())
                .build();
        this.clientApi = webClientBuilder.clone()
                .baseUrl(matrix.getClientApiBaseUrl())
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    /**
     * Injects the admin {@code Authorization: Bearer} header on every admin request: a freshly
     * refreshed MAS client-credentials token when configured, else the legacy static token.
     */
    private static ExchangeFilterFunction adminAuthFilter(MasAdminTokenProvider tokenProvider, String staticToken) {
        return (request, next) -> {
            if (tokenProvider.isEnabled()) {
                return tokenProvider.getToken()
                        .map(token -> ClientRequest.from(request)
                                .headers(headers -> headers.setBearerAuth(token))
                                .build())
                        .flatMap(next::exchange);
            }
            if (staticToken != null && !staticToken.isBlank()) {
                ClientRequest authorized = ClientRequest.from(request)
                        .headers(headers -> headers.setBearerAuth(staticToken))
                        .build();
                return next.exchange(authorized);
            }
            return next.exchange(request);
        };
    }

    private static ExchangeFilterFunction maskingRequestLogger() {
        // Provides a safe DEBUG trace of admin requests with Authorization redacted so
        // wiretap-style
        // logging is unnecessary (and so the bearer token never appears in logs).
        return ExchangeFilterFunction.ofRequestProcessor(request -> {
            if (log.isDebugEnabled()) {
                log.debug("Matrix admin {} {} headers=[{}]",
                        request.method(),
                        request.url(),
                        summarizeHeaders(request));
            }
            return Mono.just(request);
        });
    }

    private static String summarizeHeaders(ClientRequest request) {
        StringBuilder sb = new StringBuilder();
        request.headers().forEach((name, values) -> {
            if (sb.length() > 0)
                sb.append(", ");
            sb.append(name).append('=');
            if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name) || "X-Auth-Token".equalsIgnoreCase(name)) {
                sb.append("***");
            } else {
                sb.append(values);
            }
        });
        return sb.toString();
    }

    @Override
    public void upsertUser(String userId, String password, String phoneToLink, String displayName) {
        Map<String, Object> body = new HashMap<>();
        body.put("password", password);
        body.put("deactivated", false);
        if (phoneToLink != null) {
            body.put("threepids", List.of(Map.of("medium", "msisdn", "address", phoneToLink)));
        }
        if (displayName != null && !displayName.isBlank()) {
            body.put("displayname", displayName);
        }

        adminClient.put()
                .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}").build(encode(userId)))
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Void.class)
                .doOnSuccess(unused -> log.debug("Upserted Matrix user {}", userId))
                .doOnError(ex -> log.error("Failed to upsert Matrix user {}: {}", userId, ex.getMessage()))
                .block();
    }

    @Override
    public List<String> getLinkedPhones(String userId) {
        return fetchThreepids(userId).stream()
                .filter(t -> "msisdn".equalsIgnoreCase(t.medium()))
                .map(ThreePid::address)
                .toList();
    }

    @Override
    public Optional<String> findUserIdByPhone(String phone) {
        if (phone == null || phone.isBlank()) {
            return Optional.empty();
        }
        try {
            ThreepidUserResponse response = adminClient.get()
                    .uri(builder -> builder.path("/_synapse/admin/v1/threepid/msisdn/users/{address}")
                            .build(phone))
                    .exchangeToMono(resp -> {
                        if (resp.statusCode().is2xxSuccessful()) {
                            return resp.bodyToMono(ThreepidUserResponse.class);
                        }
                        // 404 / M_NOT_FOUND means the phone is not bound to any account.
                        return resp.releaseBody().then(Mono.empty());
                    })
                    .onErrorResume(ex -> {
                        log.warn("Reverse phone lookup failed: {}", ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
            if (response == null || response.userId() == null || response.userId().isBlank()) {
                return Optional.empty();
            }
            return Optional.of(response.userId());
        } catch (Exception ex) {
            log.warn("Reverse phone lookup failed: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public void linkPhone(String userId, String phone) {
        List<ThreePid> current = fetchThreepids(userId);
        boolean alreadyLinked = current.stream()
                .anyMatch(t -> "msisdn".equalsIgnoreCase(t.medium()) && phone.equals(t.address()));
        if (alreadyLinked) {
            return;
        }
        List<Map<String, String>> updated = new ArrayList<>();
        for (ThreePid t : current) {
            updated.add(Map.of("medium", t.medium(), "address", t.address()));
        }
        updated.add(Map.of("medium", "msisdn", "address", phone));
        putThreepids(userId, updated, "link", phone);
    }

    @Override
    public void unlinkPhone(String userId, String phone) {
        List<ThreePid> current = fetchThreepids(userId);
        List<Map<String, String>> updated = new ArrayList<>();
        boolean removed = false;
        for (ThreePid t : current) {
            if ("msisdn".equalsIgnoreCase(t.medium()) && phone.equals(t.address())) {
                removed = true;
                continue;
            }
            updated.add(Map.of("medium", t.medium(), "address", t.address()));
        }
        if (!removed) {
            return;
        }
        putThreepids(userId, updated, "unlink", phone);
    }

    private List<ThreePid> fetchThreepids(String userId) {
        UserDetailsResponse details = adminClient.get()
                .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}").build(encode(userId)))
                .retrieve()
                .bodyToMono(UserDetailsResponse.class)
                .onErrorResume(ex -> {
                    log.warn("Failed to fetch Matrix user {}: {}", userId, ex.getMessage());
                    return Mono.empty();
                })
                .block();
        return details == null ? List.of() : Optional.ofNullable(details.threepids()).orElse(List.of());
    }

    private void putThreepids(String userId, List<Map<String, String>> threepids, String op, String phone) {
        Map<String, Object> body = Map.of("threepids", threepids);
        adminClient.put()
                .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}").build(encode(userId)))
                .bodyValue(body)
                .retrieve()
                .bodyToMono(Void.class)
                .doOnError(ex -> log.warn("Failed to {} phone {} for {}: {}", op, phone, userId, ex.getMessage()))
                .block();
    }

    @Override
    public MatrixLoginResponse login(String userId, String password) {
        return clientApi.post()
                .uri("/_matrix/client/v3/login")
                .bodyValue(Map.of(
                        "type", "m.login.password",
                        "identifier", Map.of("type", "m.id.user", "user", userId),
                        "password", password,
                        "refresh_token", false))
                .retrieve()
                .bodyToMono(MatrixLoginResponse.class)
                .block();
    }

    @Override
    public Optional<String> whoami(String userAccessToken) {
        if (userAccessToken == null || userAccessToken.isBlank()) {
            return Optional.empty();
        }
        try {
            Map<String, Object> body = clientApi.get()
                    .uri("/_matrix/client/v3/account/whoami")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userAccessToken)
                    .exchangeToMono(response -> {
                        if (response.statusCode().is2xxSuccessful()) {
                            return response.bodyToMono(Map.class).map(m -> (Map<String, Object>) m);
                        }
                        return response.releaseBody().then(Mono.empty());
                    })
                    .block();
            if (body == null) {
                return Optional.empty();
            }
            Object userId = body.get("user_id");
            return userId == null ? Optional.empty() : Optional.of(userId.toString());
        } catch (Exception ex) {
            log.debug("whoami lookup failed: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public void sendServerNotice(String userId, String message) {
        // Fail-safe by design: a server notice is a best-effort security alert. If the
        // homeserver has server notices disabled (no server_notices config), returns a
        // 4xx, or is unreachable, we log a warning and swallow it so the calling flow
        // (e.g. the cooldown block) is never broken.
        if (userId == null || userId.isBlank() || message == null || message.isBlank()) {
            return;
        }
        try {
            adminClient.post()
                    .uri("/_synapse/admin/v1/send_server_notice")
                    .bodyValue(Map.of(
                            "user_id", userId,
                            "content", Map.of("msgtype", "m.text", "body", message)))
                    .retrieve()
                    .bodyToMono(Void.class)
                    .doOnSuccess(unused -> log.debug("Sent server notice to {}", userId))
                    .onErrorResume(ex -> {
                        log.warn("Failed to send server notice to {}: {}", userId, ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
        } catch (Exception ex) {
            log.warn("Failed to send server notice to {}: {}", userId, ex.getMessage());
        }
    }

    private String encode(String value) {
        return UriUtils.encodePathSegment(value, StandardCharsets.UTF_8);
    }

    @Override
    public boolean userExists(String userId) {
        String path = "/_synapse/admin/v2/users/" + encode(userId);
        Boolean exists = adminClient.get()
                .uri(uriBuilder -> uriBuilder.path(path).build())
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return response.releaseBody().thenReturn(Boolean.TRUE);
                    }
                    if (response.statusCode().value() == 404) {
                        return response.releaseBody().thenReturn(Boolean.FALSE);
                    }
                    return response.createException().flatMap(Mono::error);
                })
                .onErrorResume(ex -> {
                    log.warn("Failed to check existence of Matrix user {}: {}", userId, ex.getMessage());
                    return Mono.just(Boolean.FALSE);
                })
                .block();
        return Boolean.TRUE.equals(exists);
    }

    @Override
    public void deactivateUser(String userId, boolean erase) {
        adminClient.post()
                .uri(builder -> builder.path("/_synapse/admin/v1/deactivate/{userId}").build(encode(userId)))
                .bodyValue(Map.of("erase", erase))
                .retrieve()
                .bodyToMono(Void.class)
                .doOnSuccess(unused -> log.info("Deactivated Matrix user {} (erase={})", userId, erase))
                .doOnError(ex -> log.error("Failed to deactivate Matrix user {}: {}", userId, ex.getMessage()))
                .block();
    }

    @Override
    public String rotatePassword(String userId) {
        byte[] bytes = new byte[24];
        new java.security.SecureRandom().nextBytes(bytes);
        String password = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        adminClient.put()
                .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}").build(encode(userId)))
                .bodyValue(Map.of("password", password, "logout_devices", false))
                .retrieve()
                .bodyToMono(Void.class)
                .doOnSuccess(unused -> log.info("Rotated Matrix password for {} (logout_devices=false)", userId))
                .doOnError(ex -> log.error("Failed to rotate Matrix password for {}: {}", userId, ex.getMessage()))
                .block();
        return password;
    }

    private record UserDetailsResponse(List<ThreePid> threepids) {
    }

    private record ThreePid(String medium, String address) {
    }

    private record ThreepidUserResponse(@com.fasterxml.jackson.annotation.JsonProperty("user_id") String userId) {
    }
}
