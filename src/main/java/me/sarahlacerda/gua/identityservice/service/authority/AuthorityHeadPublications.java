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
 * Runs after the transition has committed, so it needs REQUIRES_NEW: a write that joined the completed
 * transaction would never flush. A separate bean because the annotation only applies through the proxy.
 */
@Component
public class AuthorityHeadPublications {

    private static final Logger log = LoggerFactory.getLogger(AuthorityHeadPublications.class);

    private final AuthorityHeadPublicationRepository repository;

    public AuthorityHeadPublications(AuthorityHeadPublicationRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordAttempt(String account, long headSeq, String headHash, boolean held, Instant now) {
        AuthorityHeadPublication publication = repository.findByAccount(account).orElse(null);
        if (publication == null || !publication.publishes(headSeq, headHash)) {
            log.debug("authority_head_ack_ignored seq={} reason=row_moved_on", headSeq);
            return;
        }
        publication.setAttempts(publication.getAttempts() + 1);
        publication.setLastAttemptAt(now);
        if (held) {
            publication.setConfirmedAt(now);
        }
        repository.save(publication);
    }
}
