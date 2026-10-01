// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;

/**
 * Marks a challenge spent in its own transaction, so the burn survives a refusal that rolls back the
 * caller. A separate bean because REQUIRES_NEW only applies through the proxy.
 */
@Service
public class AuthorityChallengeBurn {

    private final AuthorityChallengeRepository repository;

    public AuthorityChallengeBurn(AuthorityChallengeRepository repository) {
        this.repository = repository;
    }

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
