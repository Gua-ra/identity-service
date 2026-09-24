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

/**
 * The one resolver surface the authority publication talks to (ADM-009 decision 12).
 *
 * <p>The same envelope shape and the same outcomes as the placement path: {@code {record, signature}}, the
 * canonical bytes base64url unpadded and the detached signature base64, to a single endpoint that verifies
 * the object before it reads any stored state. That is what lets the endpoint be public and unauthenticated
 * on the far side, exactly as {@code POST /placement/records} is: a head that does not verify under an ACTIVE
 * roster member's key is refused before anything is looked up, so there is no credential for a caller to
 * hold and no state for an unauthenticated caller to probe.
 *
 * <p>The resolver half of this is not in this repository and is not implemented yet. This client therefore
 * reports {@code REJECTED} against a resolver that does not serve the path, which is the correct reading:
 * nothing was published. It is also why publishing defaults off. Rolling it out is two flags, in this order:
 * the resolver accepts heads, then this deployment sends them.
 */
@Component
public class ResolverAuthorityHeadClient {

    private static final Logger log = LoggerFactory.getLogger(ResolverAuthorityHeadClient.class);

    /** The reserved path for the leaf of decision 12. */
    static final String HEADS_PATH = "/account/authority/heads";

    /** What happened to one publish attempt. */
    public enum PublishOutcome {
        /** The resolver stored the head and committed its leaf. */
        PUBLISHED,
        /**
         * The resolver holds a head for this account at the same or a later position. Not an error: the log
         * is append-only and a head already committed needs no second leaf, which is what makes resending
         * the stored bytes safe.
         */
        ALREADY_PUBLISHED,
        /** The resolver refused it: bad signature, inactive signer, bad window, unreadable bytes. */
        REJECTED,
        /** The resolver could not be reached, or answered an unexpected status. */
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

    /**
     * Publishes one signed head.
     *
     * <p>The bytes are passed through exactly as they were stored. A retry is therefore byte-identical to the
     * attempt it retries, so it commits the same payload hash and the resolver can answer
     * {@code ALREADY_PUBLISHED} instead of appending a second leaf. That is the whole of what makes a
     * republish idempotent, and it is why nothing here re-signs.
     */
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
