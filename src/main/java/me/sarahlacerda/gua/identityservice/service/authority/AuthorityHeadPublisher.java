// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecord;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.domain.AuthorityHeadPublication;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.Resolved;

/**
 * Publishes an account's settled chain head. Never publishes while a record is pending, only moves the
 * published head forward, and delivers after the transaction commits.
 */
@Component
public class AuthorityHeadPublisher {

    private static final Logger log = LoggerFactory.getLogger(AuthorityHeadPublisher.class);

    private final IdentityServiceProperties properties;
    private final AuthorityHeadPublicationRepository repository;
    private final AuthorityHeadSigner signer;
    private final ResolverAuthorityHeadClient resolver;
    private final AuthorityHeadPublications publications;
    private final Clock clock;

    public AuthorityHeadPublisher(IdentityServiceProperties properties,
            AuthorityHeadPublicationRepository repository, AuthorityHeadSigner signer,
            ResolverAuthorityHeadClient resolver, AuthorityHeadPublications publications, Clock clock) {
        this.properties = properties;
        this.repository = repository;
        this.signer = signer;
        this.resolver = resolver;
        this.publications = publications;
        this.clock = clock;
    }

    public boolean isEnabled() {
        return properties.getAuthority().getPublication().isEnabled();
    }

    /** Never throws into the caller: a failed publication must not fail the transition. */
    public void publishSettledHead(Resolved account, AuthorityChainHead head, Instant now) {
        if (!isEnabled()) {
            return;
        }
        try {
            publish(account, head, now);
        } catch (RuntimeException ex) {
            log.error("authority_head_publish_failed seq={} reason={}", head.getHeadSeq(), ex.toString());
        }
    }

    private void publish(Resolved account, AuthorityChainHead head, Instant now) {
        if (head.hasPending()) {
            return;
        }
        if (head.isChainEmpty()) {
            return;
        }
        if (!signer.canSign()) {
            log.error("authority_head_publish_skipped seq={} reason=no_signing_key", head.getHeadSeq());
            return;
        }

        Optional<AuthorityHeadPublication> existing = repository.findByAccount(account.reference());
        AuthorityHeadPublication publication;
        if (existing.isPresent() && existing.get().publishes(head.getHeadSeq(), head.getHeadHash())) {
            publication = existing.get();
            if (publication.isConfirmed() && !isDueForReissue(publication, now)) {
                return;
            }
            if (publication.isConfirmed()) {
                publication = sign(publication, account, head, now);
            } else if (publication.isRetryTooSoon(now,
                    properties.getAuthority().getPublication().getRetryAfter())) {
                return;
            }
        } else if (existing.isPresent() && existing.get().getHeadSeq() > head.getHeadSeq()) {
            // Should be unreachable. The published head must never move backwards.
            log.info("authority_head_publish_skipped seq={} publishedSeq={} reason=head_rolled_back",
                    head.getHeadSeq(), existing.get().getHeadSeq());
            return;
        } else {
            publication = sign(existing.orElse(null), account, head, now);
        }

        deliverAfterCommit(publication.getAccount(), publication.getHeadSeq(), publication.getHeadHash(),
                publication.getRecordB64(), publication.getSignatureB64());
    }

    private AuthorityHeadPublication sign(AuthorityHeadPublication existing, Resolved account,
            AuthorityChainHead head, Instant now) {
        AuthorityHeadSigner.SignedHead signed =
                signer.sign(account.bytes(), head.getHeadHash(), head.getHeadSeq(), now);
        AuthorityHeadPublication publication;
        if (existing == null) {
            publication = AuthorityHeadPublication.of(account.reference(), signed.headSeq(), signed.headHash(),
                    signed.homeserverId(), signed.recordB64(), signed.signatureB64(), signed.payloadHash(),
                    signed.issuedAt(), signed.notAfter(), now);
        } else {
            publication = existing;
            publication.replaceWith(signed.headSeq(), signed.headHash(), signed.homeserverId(),
                    signed.recordB64(), signed.signatureB64(), signed.payloadHash(), signed.issuedAt(),
                    signed.notAfter(), now);
        }
        repository.save(publication);
        log.info("authority_head_signed leaf={} seq={} homeserver={}", AuthorityHeadRecord.LEAF_TYPE,
                signed.headSeq(), signed.homeserverId());
        return publication;
    }

    private boolean isDueForReissue(AuthorityHeadPublication publication, Instant now) {
        return publication.getIssuedAt()
                .plus(properties.getAuthority().getPublication().getRepublishAfter())
                .isBefore(now);
    }

    /** Uses afterCompletion, and only on commit: a rolled-back transition must deliver nothing. */
    private void deliverAfterCommit(String account, long headSeq, String headHash, String recordB64,
            String signatureB64) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            deliver(account, headSeq, headHash, recordB64, signatureB64);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status == TransactionSynchronization.STATUS_COMMITTED) {
                    deliver(account, headSeq, headHash, recordB64, signatureB64);
                }
            }
        });
    }

    private void deliver(String account, long headSeq, String headHash, String recordB64, String signatureB64) {
        ResolverAuthorityHeadClient.PublishOutcome outcome;
        try {
            outcome = resolver.publish(recordB64, signatureB64);
        } catch (RuntimeException ex) {
            log.error("authority_head_publish_failed seq={} reason={}", headSeq, ex.toString());
            return;
        }
        boolean held = outcome == ResolverAuthorityHeadClient.PublishOutcome.PUBLISHED
                || outcome == ResolverAuthorityHeadClient.PublishOutcome.ALREADY_PUBLISHED;
        try {
            publications.recordAttempt(account, headSeq, headHash, held, clock.instant());
        } catch (RuntimeException ex) {
            log.warn("authority_head_ack_not_recorded seq={} reason={}", headSeq, ex.toString());
        }
        if (held) {
            log.info("authority_head_published leaf={} seq={} outcome={}", AuthorityHeadRecord.LEAF_TYPE,
                    headSeq, outcome);
        } else {
            log.error("authority_head_publish_failed seq={} outcome={}", headSeq, outcome);
        }
    }
}
