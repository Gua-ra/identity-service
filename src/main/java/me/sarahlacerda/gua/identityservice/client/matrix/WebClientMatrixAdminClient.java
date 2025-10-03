package me.sarahlacerda.gua.identityservice.client.matrix;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
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

    public WebClientMatrixAdminClient(WebClient.Builder webClientBuilder, IdentityServiceProperties properties) {
        IdentityServiceProperties.MatrixProperties matrix = properties.getMatrix();
        this.adminClient = webClientBuilder.clone()
            .baseUrl(matrix.getAdminApiBaseUrl())
            .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + matrix.getAdminAccessToken())
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
        this.clientApi = webClientBuilder.clone()
            .baseUrl(matrix.getClientApiBaseUrl())
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
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
        return adminClient.get()
            .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}").build(encode(userId)))
            .retrieve()
            .bodyToMono(UserDetailsResponse.class)
            .map(UserDetailsResponse::msisdnAddresses)
            .blockOptional()
            .orElse(List.of());
    }

    @Override
    public void linkPhone(String userId, String phone) {
        Map<String, Object> payload = Map.of(
            "threepid", Map.of(
                "medium", "msisdn",
                "address", phone,
                "validated_at", Instant.now().toEpochMilli(),
                "added_at", Instant.now().toEpochMilli()
            )
        );

        adminClient.post()
            .uri(builder -> builder.path("/_synapse/admin/v2/users/{userId}/threepid").build(encode(userId)))
            .bodyValue(payload)
            .retrieve()
            .bodyToMono(Void.class)
            .doOnError(ex -> log.warn("Failed to link phone {} to {}: {}", phone, userId, ex.getMessage()))
            .onErrorResume(ex -> Mono.empty())
            .block();
    }

    @Override
    public void unlinkPhone(String userId, String phone) {
        adminClient.delete()
            .uri(builder -> builder
                .path("/_synapse/admin/v2/users/{userId}/threepid/msisdn/{phone}")
                .build(encode(userId), UriUtils.encodePathSegment(phone, StandardCharsets.UTF_8)))
            .retrieve()
            .bodyToMono(Void.class)
            .doOnError(ex -> log.warn("Failed to unlink phone {} from {}: {}", phone, userId, ex.getMessage()))
            .onErrorResume(ex -> Mono.empty())
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
                "refresh_token", false
            ))
            .retrieve()
            .bodyToMono(MatrixLoginResponse.class)
            .block();
    }

    private String encode(String value) {
        return UriUtils.encodePathSegment(value, StandardCharsets.UTF_8);
    }

    private record UserDetailsResponse(List<ThreePid> threepids) {
        List<String> msisdnAddresses() {
            return Optional.ofNullable(threepids)
                .orElse(List.of())
                .stream()
                .filter(threepid -> "msisdn".equalsIgnoreCase(threepid.medium()))
                .map(ThreePid::address)
                .toList();
        }
    }

    private record ThreePid(String medium, String address) { }
}
