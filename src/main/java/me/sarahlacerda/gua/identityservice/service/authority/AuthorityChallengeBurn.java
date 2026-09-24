// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;

/**
 * The one write that must survive the refusal it belongs to: marking a challenge spent (ADM-009 decision 2).
 *
 * <p>"Single use, burned on acceptance <em>and</em> on refusal" is a claim about what is left in the table
 * after the request, and every refusal on the submission path throws a {@code RuntimeException} out of the
 * transaction the spend joined. So a burn written inside that transaction was rolled back with it, and one
 * passkey assertion or PIN entry paid for unlimited submission attempts inside the challenge's fifteen
 * minutes: the signature, the channel check, the position rules, the compare-and-set, the rank resolution,
 * the backoff, the cooldown and the signer rules could all be probed with the same challenge.
 *
 * <p>Its own bean rather than a method on {@link AuthorityChallengeService}, because {@code REQUIRES_NEW} is
 * applied by the proxy and a service calling itself does not go through one. {@code AuthorityWebStepUpService}
 * reaches the same guarantee the same way, and it is the pattern this file follows deliberately.
 */
@Service
public class AuthorityChallengeBurn {

    private final AuthorityChallengeRepository repository;

    public AuthorityChallengeBurn(AuthorityChallengeRepository repository) {
        this.repository = repository;
    }

    /**
     * Marks the challenge with this hash spent, in a transaction of its own, and commits.
     *
     * <p>Looked up again by hash rather than taking the caller's entity, so the write belongs entirely to this
     * transaction and nothing depends on the caller's persistence context.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void burn(String challengeHash, Instant now) {
        AuthorityChallenge row = repository.findByChallengeHash(challengeHash).orElse(null);
        if (row == null || row.getSpentAt() != null) {
            return;
        }
        row.setSpentAt(now);
        repository.save(row);
    }
}
