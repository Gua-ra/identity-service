// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.AuthorityHeadPublication;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;

/**
 * Writes the outcome of one delivery attempt, in a transaction of its own.
 *
 * <p>Its own transaction because the delivery happens after the transition has committed. A head is signed
 * and its row written while the caller holds the head lock; the network call is made once that lock is gone,
 * so the acknowledgement arrives with no transaction to join and must not be able to reopen the one that
 * decided it. Keeping it in a separate bean is also the only way the annotation applies at all: a self-call
 * inside {@link AuthorityHeadPublisher} would bypass the proxy and silently run without one.
 *
 * <p>{@code REQUIRES_NEW} rather than a plain {@code @Transactional}, and that is load-bearing rather than
 * defensive. The delivery runs from the completing transaction's own synchronization, and the persistence
 * context of that transaction is still bound to the thread at that point: a write that joined it would never be
 * flushed, because the transaction it belonged to has already committed. Suspending it and opening a new one is
 * what makes the acknowledgement actually reach the row.
 *
 * <p>Losing an acknowledgement is harmless in exactly one direction, which is why it is written here rather
 * than guarded. An unconfirmed row is retried with the stored bytes, and a retry of a head the resolver
 * already holds is byte-identical, so it commits the same payload hash and is answered
 * {@code ALREADY_PUBLISHED} rather than appended twice.
 */
@Component
public class AuthorityHeadPublications {

    private static final Logger log = LoggerFactory.getLogger(AuthorityHeadPublications.class);

    private final AuthorityHeadPublicationRepository repository;

    public AuthorityHeadPublications(AuthorityHeadPublicationRepository repository) {
        this.repository = repository;
    }

    /**
     * Records that one attempt was made, and whether the resolver holds the head now.
     *
     * <p>Guarded on the position and the hash: an acknowledgement that arrives after the account has already
     * moved on describes a head this row no longer publishes, and marking the newer one confirmed on the
     * strength of the older one's answer would retire a delivery that never happened.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordAttempt(String account, long headSeq, String headHash, boolean held, Instant now) {
        AuthorityHeadPublication publication = repository.findByAccount(account).orElse(null);
        if (publication == null || !publication.publishes(headSeq, headHash)) {
            log.debug("authority_head_ack_ignored seq={} reason=row_moved_on", headSeq);
            return;
        }
        publication.setAttempts(publication.getAttempts() + 1);
        if (held) {
            publication.setConfirmedAt(now);
        }
        repository.save(publication);
    }
}
