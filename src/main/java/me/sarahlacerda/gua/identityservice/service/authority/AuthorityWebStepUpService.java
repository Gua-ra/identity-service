// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityWebStepUp;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

/**
 * Records a step-up proved in the web sheet. The proof is a row this service wrote, never a token the
 * client carries.
 */
@Service
public class AuthorityWebStepUpService {

    private static final Logger log = LoggerFactory.getLogger(AuthorityWebStepUpService.class);

    private final AuthorityWebStepUpRepository repository;
    private final AuthorityPolicy policy;
    private final Clock clock;

    public AuthorityWebStepUpService(AuthorityWebStepUpRepository repository, AuthorityPolicy policy, Clock clock) {
        this.repository = repository;
        this.policy = policy;
        this.clock = clock;
    }

    public void requireMayOpen(Optional<String> clientId, Purpose purpose) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        policy.requireStepUpSheetPurpose(purpose);
    }

    public static String sessionHash(String authorizationHeader) {
        return AuthorityChallengeService.sessionHash(authorizationHeader == null ? "" : authorizationHeader);
    }

    public void requireOpen(String purposeName) {
        Purpose purpose = purposeOrRefuse(purposeName);
        policy.requireEnabled();
        policy.requireStepUpSheetPurpose(purpose);
    }

    /** Needs its own {@code @Transactional}: the call below is a self-invocation that bypasses the proxy. */
    @Transactional
    public Instant proved(String userId, String sessionHash, String purposeName, AuthFactor factor,
            Instant factorCreatedAt) {
        return proved(userId, sessionHash, purposeOrRefuse(purposeName), factor, factorCreatedAt);
    }

    private static Purpose purposeOrRefuse(String purposeName) {
        try {
            return Purpose.valueOf(purposeName);
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_purpose_refused",
                    "That confirmation is not one this page can run. Please start again from the app.");
        }
    }

    @Transactional
    public Instant proved(String userId, String sessionHash, Purpose purpose, AuthFactor factor,
            Instant factorCreatedAt) {
        policy.requireEnabled();
        policy.requireStepUpSheetPurpose(purpose);
        if (factor != AuthFactor.PASSKEY && factor != AuthFactor.PIN) {
            throw new IllegalArgumentException("An authority step-up is a passkey or the PIN, never " + factor);
        }

        Instant now = clock.instant();
        Instant expiresAt = now.plus(policy.challengeTtl());
        for (AuthorityWebStepUp earlier : live(userId, sessionHash, purpose)) {
            earlier.setConsumedAt(now);
            repository.save(earlier);
        }
        repository.save(AuthorityWebStepUp.proved(userId, sessionHash, purpose, factor, factorCreatedAt,
                expiresAt, now));
        repository.deleteExpired(now);
        log.info("Authority web step-up recorded for purpose {} on factor {}", purpose, factor);
        return expiresAt;
    }

    /** Burned in its own transaction, so a later refusal cannot leave the proof spendable. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Optional<Proved> consume(String userId, String sessionHash, Purpose purpose) {
        if (!policy.isEnabled() || !policy.canOpenStepUpSheet(purpose)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Optional<AuthorityWebStepUp> newest = live(userId, sessionHash, purpose).stream()
                .filter(stepUp -> stepUp.isSpendable(now))
                .max(Comparator.comparing(AuthorityWebStepUp::getCreatedAt));
        if (newest.isEmpty()) {
            return Optional.empty();
        }
        AuthorityWebStepUp stepUp = newest.get();
        stepUp.setConsumedAt(now);
        repository.save(stepUp);
        return Optional.of(new Proved(stepUp.getFactor(), stepUp.getFactorCreatedAt()));
    }

    private List<AuthorityWebStepUp> live(String userId, String sessionHash, Purpose purpose) {
        return repository.findByUserIdAndSessionHashAndPurposeAndConsumedAtIsNull(userId, sessionHash, purpose);
    }

    public record Proved(AuthFactor factor, Instant factorCreatedAt) {
    }
}
