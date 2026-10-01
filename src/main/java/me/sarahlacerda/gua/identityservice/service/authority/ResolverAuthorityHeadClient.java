// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import reactor.core.publisher.Mono;

/** The resolver side is not implemented yet. A resolver that does not serve the path yields REJECTED. */
@Component
public class ResolverAuthorityHeadClient {

    private static final Logger log = LoggerFactory.getLogger(ResolverAuthorityHeadClient.class);

    static final String HEADS_PATH = "/account/authority/heads";

    public enum PublishOutcome {
        PUBLISHED,
        /** Not an error: the resolver already holds this head or a later one. */
        ALREADY_PUBLISHED,
        REJECTED,
        UNAVAILABLE
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SignedHeadEnvelope(String record, String signature) {
    }

    private final WebClient webClient;
    private final boolean configured;

    public ResolverAuthorityHeadClient(WebClient.Builder webClientBuilder, IdentityServiceProperties properties) {
        String baseUrl = properties.getAuthority().getPublication().getResolverBaseUrl();
        this.configured = baseUrl != null && !baseUrl.isBlank();
        this.webClient = configured
                ? webClientBuilder.clone().baseUrl(baseUrl.trim())
                        .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE).build()
                : null;
    }

    public boolean isConfigured() {
        return configured;
    }

    public PublishOutcome publish(String recordB64, String signatureB64) {
        if (!configured || recordB64 == null || signatureB64 == null) {
            return PublishOutcome.UNAVAILABLE;
        }
        try {
            HttpStatus status = webClient.post()
                    .uri(HEADS_PATH)
                    .bodyValue(new SignedHeadEnvelope(recordB64, signatureB64))
                    .exchangeToMono(response -> response.releaseBody()
                            .thenReturn(HttpStatus.valueOf(response.statusCode().value())))
                    .timeout(Duration.ofSeconds(10))
                    .onErrorResume(ex -> {
                        log.warn("Could not publish an authority head: {}", ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
            if (status == null) {
                return PublishOutcome.UNAVAILABLE;
            }
            if (status.is2xxSuccessful()) {
                return PublishOutcome.PUBLISHED;
            }
            if (status == HttpStatus.CONFLICT) {
                return PublishOutcome.ALREADY_PUBLISHED;
            }
            if (status.is4xxClientError()) {
                return PublishOutcome.REJECTED;
            }
            return PublishOutcome.UNAVAILABLE;
        } catch (RuntimeException ex) {
            log.warn("Could not publish an authority head: {}", ex.getMessage());
            return PublishOutcome.UNAVAILABLE;
        }
    }
}
