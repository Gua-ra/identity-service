// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import reactor.core.publisher.Mono;

/**
 * The primary MAS read path: the MAS admin API, with a {@code client_credentials} token.
 *
 * <p><b>Not available on this deployment.</b> The links endpoint requires the {@code urn:mas:admin}
 * scope, and the MAS authorization policy grants that scope through {@code client_credentials} only to
 * client ids listed in its policy data {@code admin_clients}. This service's MAS client id is not
 * listed, so this reader stays off ({@code identity.placement.mas.admin-api.enabled}) until a
 * deployment change adds it. This is a policy-data change, not the Synapse admin-scope problem recorded
 * elsewhere, which {@code urn:mas:admin} does not share.
 *
 * <p>Because that scope has never been granted, the response envelope below is written from the MAS
 * admin handler and model definitions rather than from a live call, and it is tolerant of unknown
 * fields. Confirm it against a real MAS the first time the scope exists; the contract this class
 * presents to the reconciler does not change either way.
 */
@Component
public class MasAdminApiLinkReader implements MasLinkReader {

    private static final Logger log = LoggerFactory.getLogger(MasAdminApiLinkReader.class);

    private static final String ADMIN_SCOPE = "urn:mas:admin";
    private static final String LINKS_PATH = "/api/admin/v1/upstream-oauth-links";
    private static final String USERS_PATH = "/api/admin/v1/users/";

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record TokenResponse(@JsonProperty("access_token") String accessToken) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record LinkAttributes(@JsonProperty("provider_id") String providerId, String subject,
            @JsonProperty("user_id") String userId) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record LinkResource(String id, LinkAttributes attributes) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record LinkListResponse(List<LinkResource> data) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record UserAttributes(String username) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record UserResource(String id, UserAttributes attributes) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record UserResponse(UserResource data) {
    }

    private final IdentityServiceProperties properties;
    private final WebClient.Builder webClientBuilder;
    private final FederationIds federationIds;

    public MasAdminApiLinkReader(IdentityServiceProperties properties, WebClient.Builder webClientBuilder,
            FederationIds federationIds) {
        this.properties = properties;
        this.webClientBuilder = webClientBuilder;
        this.federationIds = federationIds;
    }

    @Override
    public boolean isConfigured() {
        return properties.getPlacement().getMas().getAdminApi().isEnabled() && !usableHomeservers().isEmpty();
    }

    @Override
    public String describe() {
        return "MAS admin API (" + ADMIN_SCOPE + " via client_credentials)";
    }

    private List<HomeserverConfig> usableHomeservers() {
        List<HomeserverConfig> usable = new ArrayList<>();
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            IdentityServiceProperties.MasConfig mas = homeserver.getMas();
            if (!mas.getAdminApiBaseUrl().isBlank() && !mas.getClientId().isBlank()
                    && !mas.getUpstreamProviderId().isBlank()) {
                usable.add(homeserver);
            }
        }
        return usable;
    }

    @Override
    public List<MasLink> linksFor(String subject) {
        List<MasLink> links = new ArrayList<>();
        for (HomeserverConfig homeserver : usableHomeservers()) {
            links.addAll(linksOn(homeserver, subject));
        }
        return links;
    }

    private List<MasLink> linksOn(HomeserverConfig homeserver, String subject) {
        IdentityServiceProperties.MasConfig mas = homeserver.getMas();
        String federationId = federationIds.of(homeserver);
        try {
            WebClient client = webClientBuilder.clone().baseUrl(mas.getAdminApiBaseUrl().trim()).build();
            String token = requestToken(client, mas);
            if (token == null) {
                log.warn("No {} token for homeserver {}; its links were not read", ADMIN_SCOPE, federationId);
                return List.of();
            }
            LinkListResponse response = client.get()
                    .uri(builder -> builder.path(LINKS_PATH)
                            .queryParam("filter[provider]", mas.getUpstreamProviderId())
                            .queryParam("filter[subject]", subject)
                            .build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToMono(LinkListResponse.class)
                    .timeout(Duration.ofSeconds(15))
                    .onErrorResume(ex -> {
                        log.warn("Could not read MAS links on homeserver {}: {}", federationId, ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
            if (response == null || response.data() == null) {
                return List.of();
            }
            List<MasLink> links = new ArrayList<>();
            for (LinkResource resource : response.data()) {
                LinkAttributes attributes = resource.attributes();
                // A link with no MAS user is an unfinished login, not evidence of placement.
                if (attributes == null || attributes.userId() == null || attributes.userId().isBlank()) {
                    continue;
                }
                links.add(new MasLink(federationId, attributes.subject(), attributes.userId(),
                        usernameOf(client, token, attributes.userId(), federationId)));
            }
            return links;
        } catch (RuntimeException ex) {
            log.warn("Could not read MAS links on homeserver {}: {}", federationId, ex.getMessage());
            return List.of();
        }
    }

    private String requestToken(WebClient client, IdentityServiceProperties.MasConfig mas) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", ADMIN_SCOPE);
        form.add("client_id", mas.getClientId());
        form.add("client_secret", mas.getClientSecret());
        TokenResponse response = client.post()
                .uri(mas.getTokenUrl().isBlank() ? "/oauth2/token" : mas.getTokenUrl())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .timeout(Duration.ofSeconds(15))
                .onErrorResume(ex -> {
                    // The message never carries the response body: a token endpoint can echo the client
                    // secret back in an error.
                    log.warn("The MAS token request failed");
                    return Mono.empty();
                })
                .block();
        return response == null ? null : response.accessToken();
    }

    private String usernameOf(WebClient client, String token, String masUserId, String federationId) {
        UserResponse response = client.get()
                .uri(USERS_PATH + masUserId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(UserResponse.class)
                .timeout(Duration.ofSeconds(15))
                .onErrorResume(ex -> {
                    log.warn("Could not read a MAS username on homeserver {}: {}", federationId, ex.getMessage());
                    return Mono.empty();
                })
                .block();
        return response == null || response.data() == null || response.data().attributes() == null
                ? null
                : response.data().attributes().username();
    }

    /**
     * The admin API cannot answer this: its provider model omits {@code claims_imports} altogether, so
     * the on-conflict gauge needs the SQL path or the rendered configuration.
     */
    @Override
    public Map<String, String> localpartOnConflictByHomeserver() {
        return Map.of();
    }
}
