// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.AuthorityProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

/**
 * Every authority rule is decided here; callers must not decide any of it locally. No accepted factor set
 * may contain the phone OTP (AccountAuthorityGuardTest).
 */
@Service
public class AuthorityPolicy {

    private final IdentityServiceProperties properties;
    private final UserSecurityService userSecurityService;

    public AuthorityPolicy(IdentityServiceProperties properties, UserSecurityService userSecurityService) {
        this.properties = properties;
        this.userSecurityService = userSecurityService;
    }

    public boolean isEnabled() {
        return authority().isEnabled();
    }

    public void requireEnabled() {
        if (!isEnabled()) {
            throw new AuthorityTransitionException(HttpStatus.SERVICE_UNAVAILABLE, "authority_disabled",
                    "The account authority chain is not enabled on this deployment.");
        }
    }

    public void requireAdoptionPermitted() {
        if (!authority().isAdoptionPermitted()) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_adoption_not_permitted",
                    "Adoption is not permitted on this deployment.");
        }
    }

    /**
     * The client id comes from the verified token audience. A token with no client id, which is every
     * homeserver-issued token and so both apps, is accepted; the allowlist only constrains tokens that name one.
     */
    public void requireNativeSession(Optional<String> clientId) {
        if (!mayHoldAuthority(clientId)) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_native_session_required",
                    "This step must be taken in the app.");
        }
    }

    public boolean mayHoldAuthority(Optional<String> clientId) {
        List<String> nativeClientIds = authority().getNativeClientIds();
        return clientId.isEmpty() || nativeClientIds.contains(clientId.get());
    }

    /** Depends on the purpose only, never on which factors the account holds. */
    public StepUpPolicy stepUpFor(Purpose purpose) {
        return switch (purpose) {
            case ADOPT, GRANT, REVOKE, RECOVER -> new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
            // Authorized by a device signature instead of a factor.
            case APPROVE, OPPOSE, NOTIFY -> new StepUpPolicy(List.of(), false);
        };
    }

    public boolean canOpenStepUpSheet(Purpose purpose) {
        return stepUpFor(purpose).required();
    }

    public void requireStepUpSheetPurpose(Purpose purpose) {
        if (!canOpenStepUpSheet(purpose)) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_step_up_purpose_refused",
                    "That step is not confirmed this way.");
        }
    }

    /** Accepted at any factor age: the fresh-factor hold gates starting a transition, never opposing one. */
    public StepUpPolicy oppositionStepUp() {
        return new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
    }

    /** The caller must also apply the fresh-factor hold. */
    public StepUpPolicy notificationRemovalStepUp() {
        return new StepUpPolicy(List.of(AuthFactor.PASSKEY, AuthFactor.PIN), true);
    }

    public boolean notificationsEnabled() {
        return authority().getNotifications().isEnabled();
    }

    public void requireNotificationsEnabled() {
        if (!notificationsEnabled()) {
            throw new AuthorityTransitionException(HttpStatus.SERVICE_UNAVAILABLE,
                    "authority_notifications_disabled",
                    "Security notifications are not switched on for this deployment.");
        }
    }

    public Duration registrationLife() {
        return authority().getNotifications().getRegistrationLife();
    }

    public int registrationFailureLimit() {
        return authority().getNotifications().getFailureLimit();
    }

    public void requireReachableOutOfBand(boolean reachable) {
        if (!reachable) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_no_notification_channel",
                    "Turn on security notifications on a device of this account before making this change.");
        }
    }

    public void requireExtensionUnspent(boolean alreadyExtended) {
        if (alreadyExtended) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_extension_spent",
                    "This step has already been postponed once. It cannot be postponed again.");
        }
    }

    public boolean oppositionNeedsStepUp(int oppositionsAlreadyMade) {
        return oppositionsAlreadyMade >= 1;
    }

    public Duration challengeTtl() {
        return authority().getChallengeTtl();
    }

    public void enforceFreshFactorHold(Instant factorCreatedAt) {
        long remaining = userSecurityService.freshFactorHoldRemaining(factorCreatedAt);
        if (remaining > 0) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_factor_too_fresh",
                    "That way of confirming it is you was set up too recently to authorize this.", remaining);
        }
    }

    /**
     * Refuses a transition while the account's last completed recovery is inside the hold, so a PIN minted
     * by that recovery cannot authorize one.
     */
    public void enforceRecoveryOutsideHold(String userId) {
        long remaining = userSecurityService.recoveryCompletionHoldRemaining(userId);
        if (remaining > 0) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_recovery_too_recent",
                    "This account was recovered too recently to authorize this.", remaining);
        }
    }

    public void requirePermittedAt(AuthorityRecordType type, Integer authorization, ChainContext context) {
        boolean permitted = switch (type) {
            case ADOPT_ROOT -> context.chainEmpty() && !context.genesisRooted();
            case AUTHORITY_RECOVERY -> context.holdsCommittedAuthority()
                    && !(context.genesisRooted()
                            && authorization != null
                            && authorization == AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY);
            case DEVICE_GRANT, DEVICE_REVOKE -> context.unquarantinedActiveDevices() >= 1;
            // Fails closed: an Oppose must never go through the submission path.
            case OPPOSE -> false;
        };
        if (!permitted) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_position_refused",
                    "This account cannot take that step.");
        }
    }

    /** A quarantined device may not sign and does not count as an active device. */
    public Instant quarantineUntil(Instant now) {
        return now.plus(authority().getOppositionWindow());
    }

    public void requireNotQuarantined(boolean quarantined) {
        if (quarantined) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_device_quarantined",
                    "This device cannot authorize that yet.");
        }
    }

    public void requireLeavesAnActiveDevice(int unquarantinedActiveAfter) {
        if (unquarantinedActiveAfter < 1) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_last_device",
                    "That would leave the account with no device that can authorize anything.");
        }
    }

    /**
     * The device a revocation names may oppose it only when accepting would leave the signer as the sole
     * active device. A recovery signed by the committed recovery key is extended once, never cancelled.
     */
    public Opposition opposition(AuthorityRecordType pendingType, Integer pendingAuthorization,
            boolean opposerIsNamedDevice, boolean acceptingWouldLeaveSignerAlone) {
        return switch (pendingType) {
            case DEVICE_GRANT -> opposerIsNamedDevice ? Opposition.REFUSED : Opposition.CANCELS;
            case DEVICE_REVOKE -> !opposerIsNamedDevice || acceptingWouldLeaveSignerAlone
                    ? Opposition.CANCELS
                    : Opposition.REFUSED;
            case ADOPT_ROOT -> Opposition.CANCELS;
            case AUTHORITY_RECOVERY -> pendingAuthorization != null
                    && pendingAuthorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY
                            ? Opposition.EXTENDS_ONCE
                            : Opposition.CANCELS;
            case OPPOSE -> Opposition.REFUSED;
        };
    }

    /**
     * A bearer session alone may oppose only an adoption. Every other record needs an Oppose signed by an
     * active device.
     */
    public void requireSessionMayOppose(AuthorityRecordType pendingType, Integer pendingAuthorization) {
        boolean sessionIsEnough = pendingType == AuthorityRecordType.ADOPT_ROOT
                || (pendingType == AuthorityRecordType.AUTHORITY_RECOVERY && pendingAuthorization != null
                        && pendingAuthorization == AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY);
        if (!sessionIsEnough) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_device_required",
                    "Objecting to that step has to come from a device that holds this account's authority.");
        }
    }

    public enum Opposition {
        CANCELS,
        EXTENDS_ONCE,
        REFUSED
    }

    /**
     * Higher rank wins: recovery by the committed recovery key (2), any device-signed record (1), recovery
     * through account recovery (0).
     */
    public short rankOf(AuthorityRecordType type, Integer authorization) {
        if (type != AuthorityRecordType.AUTHORITY_RECOVERY) {
            return 1;
        }
        return authorization != null && authorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY
                ? (short) 2
                : (short) 0;
    }

    public SlotOutcome resolveAgainstPending(short submittedRank, short pendingRank) {
        if (submittedRank > pendingRank) {
            return SlotOutcome.CANCELS_PENDING;
        }
        return SlotOutcome.REFUSED;
    }

    public enum SlotOutcome {
        CANCELS_PENDING,
        REFUSED
    }

    public Duration backoffAfter(int cancellations) {
        if (cancellations <= 0) {
            return Duration.ZERO;
        }
        long multiplier = 1L << Math.min(cancellations - 1, 3);
        return authority().getOppositionWindow().multipliedBy(multiplier);
    }

    public void requireOutsideBackoff(Instant until, Instant now) {
        if (until != null && now.isBefore(until)) {
            throw new AuthorityTransitionException(HttpStatus.TOO_MANY_REQUESTS, "authority_backoff",
                    "Try that again later.", Math.max(Duration.between(now, until).toSeconds(), 1L));
        }
    }

    public void requireOutsideCooldown(Instant cooldownUntil, String cooldownMagic, String submittedMagic,
            Instant now) {
        if (cooldownUntil != null && cooldownMagic != null && cooldownMagic.equals(submittedMagic)
                && now.isBefore(cooldownUntil)) {
            throw new AuthorityTransitionException(HttpStatus.TOO_MANY_REQUESTS, "authority_cooldown",
                    "Try that again later.", Math.max(Duration.between(now, cooldownUntil).toSeconds(), 1L));
        }
    }

    public Duration windowFor(AuthorityRecordType type, Integer authorization) {
        if (type == AuthorityRecordType.AUTHORITY_RECOVERY && authorization != null
                && authorization == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY) {
            return authority().getRecoveryWindow();
        }
        return authority().getOppositionWindow();
    }

    public Duration oppositionWindow() {
        return authority().getOppositionWindow();
    }

    /** A grant opens no window but still changes the device set, so it must be announced too. */
    public boolean mustBeAnnounced(AuthorityRecord record) {
        return !takesEffectImmediately(record) || record.type() == AuthorityRecordType.DEVICE_GRANT;
    }

    public boolean takesEffectImmediately(AuthorityRecord record) {
        return record.type() == AuthorityRecordType.DEVICE_GRANT || record.isSelfRevocation();
    }

    public Duration candidateLife() {
        return authority().getCandidateLife();
    }

    /** One refusal for an unknown and an expired candidate, so a grant cannot probe which keys were offered. */
    public void requireLiveCandidate(boolean live) {
        if (!live) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_unknown_candidate",
                    "That device has not offered its key to this account, or the offer has expired.");
        }
    }

    /** A key is granted once per account: a revoked key does not come back, the device offers a new one. */
    public void requireKeyNewToTheAccount(boolean alreadyHeld) {
        if (alreadyHeld) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_device_known",
                    "That device key has already been on this account. Set the device up again to add it.");
        }
    }

    public Duration approvalTtl() {
        return authority().getApprovalTtl();
    }

    public int maxLiveApprovals() {
        return authority().getMaxLiveApprovals();
    }

    private AuthorityProperties authority() {
        return properties.getAuthority();
    }

    public record ChainContext(boolean chainEmpty, boolean genesisRooted, boolean holdsCommittedAuthority,
            int unquarantinedActiveDevices) {
    }

    public record StepUpPolicy(List<AuthFactor> accepted, boolean hardBlockWhenUnsatisfied) {

        public boolean accepts(AuthFactor factor) {
            return accepted.contains(factor);
        }

        public boolean required() {
            return !accepted.isEmpty();
        }
    }
}
