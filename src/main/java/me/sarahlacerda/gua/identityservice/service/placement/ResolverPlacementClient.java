// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.account.genesis.InvalidGenesisException;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecord;
import me.sarahlacerda.gua.identityservice.account.genesis.PlacementRecordCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import reactor.core.publisher.Mono;

/**
 * The gua-resolver surfaces this service talks to for placement: the public roster, and the placement
 * record endpoints.
 *
 * <p>This is not a reintroduction of the deleted directory-publishing client. That one bound a phone
 * digest to a homeserver and the resolver accepted any active member's signature for any row, so a
 * member could bind any phone number to itself (ADM-001 L1b). A placement record binds an accountId,
 * which is a hash with no identifier in its preimage, one accountId has one home, and nothing is served
 * from the records in this phase.
 */
@Component
public class ResolverPlacementClient {

    private static final Logger log = LoggerFactory.getLogger(ResolverPlacementClient.class);

    private static final String RECORDS_PATH = "/placement/records";

    /** What happened to one publish attempt. */
    public enum PublishOutcome {
        /** The resolver stored the record. */
        PUBLISHED,
        /** A record for this accountId already names another homeserver; never overwritten. */
        CONFLICT,
        /** The resolver refused the record: bad signature, inactive signer, bad window. */
        REJECTED,
        /** The resolver could not be reached, or answered an unexpected status. */
        UNAVAILABLE
    }

    /** Only the roster fields the consistency check needs. Everything else is ignored on purpose. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RosterView(long version, List<RosterEntryView> entries) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RosterEntryView(HomeserverView homeserver, String status) {
        public boolean isActive() {
            return "ACTIVE".equals(status);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record HomeserverView(String id, String serverName, String signingKey) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SignedRecordEnvelope(String record, String signature) {
    }

    private final WebClient webClient;
    private final boolean configured;

    public ResolverPlacementClient(WebClient.Builder webClientBuilder, IdentityServiceProperties properties) {
        String baseUrl = properties.getPlacement().getResolverBaseUrl();
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
     * The published roster. Public and unauthenticated by design, so reading it needs no credential.
     *
     * @return empty when the resolver is unreachable or answers something unreadable
     */
    public Optional<RosterView> fetchRoster() {
        if (!configured) {
            return Optional.empty();
        }
        try {
            RosterView roster = webClient.get()
                    .uri("/roster")
                    .retrieve()
                    .bodyToMono(RosterView.class)
                    .timeout(Duration.ofSeconds(10))
                    .onErrorResume(ex -> {
                        log.warn("Could not read the federation roster: {}", ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
            return Optional.ofNullable(roster);
        } catch (RuntimeException ex) {
            log.warn("Could not read the federation roster: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    /**
     * The published record for one account, decoded from the signed envelope.
     *
     * <p>Reading a record here is the comparison, not a routing lookup: the value never reaches the
     * resolution path, and no caller of this method decides where an account lives.
     *
     * @return empty when there is no record, or when the resolver could not be reached
     */
    public Optional<PlacementRecord> findRecord(String accountId) {
        if (!configured) {
            return Optional.empty();
        }
        try {
            SignedRecordEnvelope envelope = webClient.get()
                    .uri(builder -> builder.path(RECORDS_PATH + "/{accountId}").build(accountId))
                    .exchangeToMono(response -> {
                        if (response.statusCode().is2xxSuccessful()) {
                            return response.bodyToMono(SignedRecordEnvelope.class);
                        }
                        return response.releaseBody().then(Mono.empty());
                    })
                    .timeout(Duration.ofSeconds(10))
                    .onErrorResume(ex -> {
                        log.warn("Could not read a placement record: {}", ex.getMessage());
                        return Mono.empty();
                    })
                    .block();
            if (envelope == null || envelope.record() == null) {
                return Optional.empty();
            }
            byte[] canonical = Base64.getUrlDecoder().decode(envelope.record());
            return Optional.of(PlacementRecordCodec.decode(canonical));
        } catch (InvalidGenesisException ex) {
            log.warn("A published placement record does not decode: {}", ex.reason());
            return Optional.empty();
        } catch (RuntimeException ex) {
            log.warn("Could not read a placement record: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Publishes one signed record.
     *
     * <p>A conflict is reported, never retried and never forced: one accountId has one home, and a
     * record naming another homeserver is evidence of a duplicate identity or a bad signer, which a
     * person has to explain (ADM-001 L9 refuses migration outright).
     */
    public PublishOutcome publish(PlacementRecordSigner.SignedPlacementRecord signed) {
        if (!configured) {
            return PublishOutcome.UNAVAILABLE;
        }
        try {
            HttpStatus status = webClient.post()
                    .uri(RECORDS_PATH)
                    .bodyValue(new SignedRecordEnvelope(signed.recordB64(), signed.signatureB64()))
                    .exchangeToMono(response -> response.releaseBody()
                            .thenReturn(HttpStatus.valueOf(response.statusCode().value())))
                    .timeout(Duration.ofSeconds(10))
                    .onErrorResume(ex -> {
                        log.warn("Could not publish a placement record: {}", ex.getMessage());
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
                return PublishOutcome.CONFLICT;
            }
            if (status.is4xxClientError()) {
                return PublishOutcome.REJECTED;
            }
            return PublishOutcome.UNAVAILABLE;
        } catch (RuntimeException ex) {
            log.warn("Could not publish a placement record: {}", ex.getMessage());
            return PublishOutcome.UNAVAILABLE;
        }
    }
}
