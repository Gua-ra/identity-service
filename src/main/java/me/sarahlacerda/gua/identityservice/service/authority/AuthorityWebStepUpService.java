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
 * The step-up an authority transition can take in the web sheet instead of natively (ADM-009 decision 4
 * step 2).
 *
 * <p>The mechanism is the one the passkey-first milestone already shipped for factor enrollment: a one-time
 * URL opens in a web sheet, the page runs the ceremony against this service, the session records what it
 * proved, and control returns to the app through the app's own redirect scheme. This class is the recording
 * half, scoped to an authority transition rather than to enrollment.
 *
 * <p>Why it has to exist. The policy is passkey preferred, PIN fallback, phone code never. One client platform
 * cannot produce a WebAuthn assertion at all, so on that platform the policy would collapse to PIN-only, and
 * an account that correctly chose passkey-only at signup would be told to add a PIN to gain authority. That is
 * a worse account than the one it started with, offered as a security step, which is not a trade this product
 * asks anybody to make.
 *
 * <p>What it is not, and this is the whole of its safety: it is not a token a client hands back, and not a
 * claim a client makes. It is a row this service wrote about a ceremony this service ran, bound to the
 * account, to the access token that asked for the sheet and to one purpose, spendable once, inside the
 * challenge's own life. Nothing here sends a code to a phone number, nothing here reads one, and
 * {@link AuthFactor#PIN} and the passkey are the only two values {@link #proved} will record, because they are
 * the only two the sheet can run.
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

    /**
     * Refuses to open a sheet this deployment, this caller or this purpose has no step-up for.
     *
     * <p>Three rules, asked before a session is minted, so none of them is discovered on a page somebody is
     * already looking at. The feature's own flag. The native-session rule of ADM-009 decision 4 step 1, which
     * is why a browser cannot open one of these for itself: the browser holds no authority, ever, and a sheet
     * it opened for itself would be a browser arranging its own authority proof. And the purpose, derived from
     * {@link AuthorityPolicy#stepUpFor(Purpose)} rather than written out again, because a purpose that asks
     * for no factor would get a page with nothing to ask.
     */
    public void requireMayOpen(Optional<String> clientId, Purpose purpose) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        policy.requireStepUpSheetPurpose(purpose);
    }

    /**
     * The binding between a sheet and the access token that asked for it: the SHA-256 of the
     * {@code Authorization} header, computed exactly as the challenge endpoint computes it, so the two agree
     * on what "the same session" means.
     */
    public static String sessionHash(String authorizationHeader) {
        return AuthorityChallengeService.sessionHash(authorizationHeader == null ? "" : authorizationHeader);
    }

    /**
     * The same three rules for the page itself, which holds the purpose as the name it was stamped with.
     *
     * <p>Asked again on every call the page makes, and not only where the sheet was minted: a deployment can be
     * switched off in between, and a page that went on accepting proofs for a feature nobody is running would
     * be recording rows the chain will never read. The native-session rule is not re-asked, because the page
     * is not the app: it was reached through the one-time URL a native session asked for, and the session it
     * runs in is what carries that fact.
     */
    public void requireOpen(String purposeName) {
        Purpose purpose = purposeOrRefuse(purposeName);
        policy.requireEnabled();
        policy.requireStepUpSheetPurpose(purpose);
    }

    /**
     * {@link #proved} for the page, which carries the purpose as the name the session was stamped with.
     *
     * <p>Annotated in its own right, and that is not redundant. This overload is the only entry point the
     * hosted sheet has, and the call below is a self-invocation: it reaches the other {@code proved} directly
     * rather than through the proxy, so the annotation there does not apply and the transaction has to start
     * here or nowhere. Without it the write path's {@code deleteExpired} throws
     * {@code InvalidDataAccessApiUsageException: Executing an update/delete query}, the sheet answers 500, and
     * the page reports a generic passkey failure for a ceremony that in fact verified. Pinned by
     * {@code AuthorityWebStepUpTransactionTest}, which is the only shape of test that can see it.
     */
    @Transactional
    public Instant proved(String userId, String sessionHash, String purposeName, AuthFactor factor,
            Instant factorCreatedAt) {
        return proved(userId, sessionHash, purposeOrRefuse(purposeName), factor, factorCreatedAt);
    }

    /**
     * Reads a stamped purpose back, and refuses rather than guessing.
     *
     * <p>The value was written by this service from a validated request, so an unreadable one means a session
     * written by another build or tampered with in the store. Either way the honest answer is that this page
     * has no transition to confirm, not a default one.
     */
    private static Purpose purposeOrRefuse(String purposeName) {
        try {
            return Purpose.valueOf(purposeName);
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_purpose_refused",
                    "That confirmation is not one this page can run. Please start again from the app.");
        }
    }

    /**
     * Records what the sheet proved, and returns when it stops being spendable.
     *
     * <p>Called only from the page's own step-up endpoints, after the ceremony verified and resolved to this
     * session's account. The factor is the server's observation of that ceremony; there is no parameter for a
     * client to state one.
     *
     * <p>Any earlier unspent step-up of the same account, session and purpose is burned first. Two live proofs
     * for one transition would mean a caller could grind the sheet and keep the oldest, and one transition
     * needs one proof.
     */
    @Transactional
    public Instant proved(String userId, String sessionHash, Purpose purpose, AuthFactor factor,
            Instant factorCreatedAt) {
        policy.requireEnabled();
        policy.requireStepUpSheetPurpose(purpose);
        if (factor != AuthFactor.PASSKEY && factor != AuthFactor.PIN) {
            // Unconditional, and stated as a refusal rather than as a filter. The sheet has two arms and the
            // page cannot reach a third, so the only way to arrive here with anything else is an edit that
            // added one, and an edit that adds one should fail the build and then this.
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
        // Housekeeping on the write path, exactly as the challenge and candidate tables do it.
        repository.deleteExpired(now);
        log.info("Authority web step-up recorded for purpose {} on factor {}", purpose, factor);
        return expiresAt;
    }

    /**
     * Spends the proof the sheet left behind, if there is one for this account, this session and this purpose.
     *
     * <p>Burned before the caller does anything with it, and in its own transaction, so no arrangement of
     * later refusals can leave it spendable. That is the same rule the challenge itself follows: single use
     * means burned on acceptance <em>and</em> on refusal, which is one code path rather than two.
     *
     * <p>Empty when there is none, which is not an error. It means the caller produced no factor in this
     * request and ran no sheet either, and the refusal that follows belongs to the step-up service, in the
     * same words it uses for a caller that presented nothing.
     */
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

    /**
     * What a spent sheet proved.
     *
     * @param factor          the passkey or the PIN, as the server observed it
     * @param factorCreatedAt when that credential came into being, which is what the fresh-factor hold weighs
     */
    public record Proved(AuthFactor factor, Instant factorCreatedAt) {
    }
}
