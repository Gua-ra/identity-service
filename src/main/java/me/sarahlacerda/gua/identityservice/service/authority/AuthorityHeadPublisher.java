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
 * Publishes an account's settled chain head as the {@code ACCOUNT_AUTHORITY} leaf ADM-009 decision 12
 * reserves.
 *
 * <p>Decision 12 is the one gap in ADM-009 that is not an argument about rules: a class {@code 0x00}
 * account's chain is an assertion by the homeserver that stores it, the records are already
 * self-evidencing, and what is missing is a publication. This class is that publication, and it is
 * deliberately the smallest thing that is one.
 *
 * <h2>Only a settled head, and only forwards</h2>
 *
 * <p>The head row's {@code headHash} is not always a settled head. It names the last record <em>placed</em>
 * in a slot and not yet cancelled, which includes one still inside its opposition window, and a cancellation
 * rolls the head back to that record's own {@code prevHash} and {@code seq - 1}
 * ({@code AuthorityChainHead.rollBackTo}). The log is append-only. So a head published from inside a window
 * would be a leaf about a record that later stops existing, and no leaf can be unsaid. Two rules follow, and
 * they are the whole of the correctness argument here:
 *
 * <ul>
 *   <li>nothing is published while {@code head.hasPending()}, so a pending record's hash never reaches the
 *       log, and the transition is published when its window completes instead;</li>
 *   <li>a publication is replaced only when the settled head moves strictly forward, so a rollback leaves
 *       the published position where it was rather than trying to retract it.</li>
 * </ul>
 *
 * <h2>On transitions, not on a timer</h2>
 *
 * <p>Called at the two moments the settled head moves: when a record is accepted that takes effect
 * immediately, and when a pending record is promoted at the end of its window. Nothing in this application
 * schedules anything for the authority chain, and a scheduler started for this one sweep would start one for
 * everything else. Promotion is already lazy, on the next read or write of the chain, so publication inherits
 * that: the same call also catches up a delivery that failed and re-issues a head whose window is aging,
 * which needs no timer because the account holder's own client reads its state.
 *
 * <h2>Idempotency</h2>
 *
 * <p>A republish of a head this deployment has already signed resends the stored bytes verbatim. It is
 * therefore byte-identical, commits the same payload hash, and is answered {@code ALREADY_PUBLISHED} rather
 * than appended a second time. Signing again on every pass would have grown the log once per read, and the
 * log's size is the roster version, which seeds the weighted fallback that places new accounts (ADM-001 L6):
 * a churning log moves where new accounts land. One leaf per settled transition is the cost this feature
 * accepts and states; one per read would not have been.
 *
 * <h2>The network call is made after the transaction commits</h2>
 *
 * <p>The decision and the row are written inside the caller's transaction, under the head lock that made the
 * decision safe. The POST is registered to run after that commit, so a slow or hanging resolver cannot hold
 * a per-account row lock open on a user's request. The cost is that an acknowledgement can be lost, which is
 * harmless in one direction only: an unconfirmed row is retried with the same bytes.
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

    /** Whether this deployment publishes heads at all. Off by default, separately from the chain itself. */
    public boolean isEnabled() {
        return properties.getAuthority().getPublication().isEnabled();
    }

    /**
     * Publishes the account's settled head, if there is one to publish and it is not already published.
     *
     * <p>Safe to call on every pass over an account, including one that changed nothing: that is what the
     * catch-up depends on. Never throws into the transition it is called from. A publication that cannot be
     * signed or cannot be delivered leaves the chain exactly as it was, because a head that reaches the log
     * late is a delay and a transition refused because federation state was unreachable would be an outage.
     *
     * @param head the head row, already locked and already settled by the caller
     */
    public void publishSettledHead(Resolved account, AuthorityChainHead head, Instant now) {
        if (!isEnabled()) {
            // Nothing is signed, nothing is sent, and no row is written. With the flag off this method is
            // the only thing the feature costs a deployment, and it costs one boolean read.
            return;
        }
        try {
            publish(account, head, now);
        } catch (RuntimeException ex) {
            // Never into the caller. The transition itself is not a publication and must not fail as one.
            log.error("authority_head_publish_failed seq={} reason={}", head.getHeadSeq(), ex.toString());
        }
    }

    private void publish(Resolved account, AuthorityChainHead head, Instant now) {
        if (head.hasPending()) {
            // The head names a record inside its opposition window. Publishing it would commit a leaf about a
            // record an opposition can still cancel, and the log cannot take it back.
            return;
        }
        if (head.isChainEmpty()) {
            // Nothing to attest, and an object saying "this account holds no authority" would be a
            // non-membership claim with nothing to check it against (ADM-005 requirement 9).
            return;
        }
        if (!signer.canSign()) {
            // A deployment error, not a per-account one, and AuthorityPublicationStartupCheck refuses to
            // start a deployment in this state. Logged once per attempt rather than thrown, so a
            // misconfiguration cannot take the chain down with it.
            log.error("authority_head_publish_skipped seq={} reason=no_signing_key", head.getHeadSeq());
            return;
        }

        Optional<AuthorityHeadPublication> existing = repository.findByAccount(account.reference());
        AuthorityHeadPublication publication;
        if (existing.isPresent() && existing.get().publishes(head.getHeadSeq(), head.getHeadHash())) {
            publication = existing.get();
            if (publication.isConfirmed() && !isDueForReissue(publication, now)) {
                // Already in the log, and its window is not aging. This is the idempotent no-op every extra
                // pass over the account lands on.
                return;
            }
            if (publication.isConfirmed()) {
                // The head has not moved for longer than republish-after, so the attestation is re-issued
                // with a fresh window. A new window is a new statement and a new leaf; it is not a duplicate,
                // and it is what keeps a quiet account from going stale in the client.
                publication = sign(publication, account, head, now);
            } else if (publication.isRetryTooSoon(now,
                    properties.getAuthority().getPublication().getRetryAfter())) {
                // Too soon. This catch-up rides the lazy path the account holder's own reads take, so an
                // unreachable resolver would otherwise put a socket timeout in front of every one of those
                // reads. A head still unsent when the next transition happens is sent then.
                return;
            }
            // Otherwise the bytes are resent exactly as they were signed, which is the retry.
        } else if (existing.isPresent() && existing.get().getHeadSeq() > head.getHeadSeq()) {
            // The settled head is behind what was published. Unreachable as the rules above stand, because only
            // a settled head is ever published and only a pending record is ever cancelled, so the position in
            // the log is one the chain has passed. Kept because it is the one state the log could not survive:
            // a leaf is append-only, so if the head ever did go backwards the published position has to stay
            // where it is rather than a lower one being asserted over it.
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

    /** A still-valid head old enough that its window should be refreshed before it approaches its expiry. */
    private boolean isDueForReissue(AuthorityHeadPublication publication, Instant now) {
        return publication.getIssuedAt()
                .plus(properties.getAuthority().getPublication().getRepublishAfter())
                .isBefore(now);
    }

    /**
     * Sends the envelope once the transition has committed, or immediately when there is no transaction to
     * wait for, which is how a direct call behaves.
     *
     * <p>{@code afterCompletion} rather than {@code afterCommit}, and only on a commit: the acknowledgement is
     * written in a transaction of its own, and opening one is safe once the outer transaction's resources have
     * been released rather than while they are still bound. A rollback delivers nothing, which is the
     * behaviour that matters: a transition that was refused after the head row was written must not leave a
     * leaf about a head that does not exist.
     */
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
            // An unrecorded acknowledgement costs one byte-identical retry on the next pass.
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
