// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityFingerprint;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordCodec;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.account.authority.InvalidAuthorityRecordException;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDeviceCandidate;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.AuthorityStateResponse;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.ChainState;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.DeviceView;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.PendingView;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.Resolved;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.ChainContext;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.Opposition;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPolicy.SlotOutcome;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityStepUpService.Accepted;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * One transactional method per transition of the authority chain (ADM-009).
 *
 * <p>Every write takes the head row {@code FOR UPDATE} and is a compare-and-set on {@code prevHash} and
 * {@code seq}. Two devices acting at once therefore produce one winner and one refusal carrying the current
 * head, and the loser re-reads and decides again with the winner's record in view. There is no merge, no
 * last-writer-wins and no state in which two chains exist.
 *
 * <p><b>Windows are settled lazily, on read and on the next write.</b> Nothing in this application enables
 * scheduling, and starting a scheduler for this one sweep would start one for everything else. A pending
 * record whose window has passed is therefore promoted the next time anybody looks at the chain, which is
 * either the account holder reading their own state or the next transition taking the lock. That is the same
 * choice the genesis sweep makes, and it is safe for the same reason: nothing reads a pending record as
 * though it were active, so a late promotion changes when the chain is written and never what it says.
 *
 * <p>What this class deliberately does not do: decide anything. Every rule lives in {@link AuthorityPolicy},
 * so the branches here read as a sequence of questions rather than as a second copy of the answers.
 */
@Service
public class AccountAuthorityService {

    private static final Logger log = LoggerFactory.getLogger(AccountAuthorityService.class);

    private final AuthorityPolicy policy;
    private final AuthorityAccounts accounts;
    private final AuthorityChallengeService challenges;
    private final AuthorityStepUpService stepUps;
    private final AuthorityChainHeadRepository headRepository;
    private final AuthorityChainRecordRepository recordRepository;
    private final AuthorityDeviceRepository deviceRepository;
    private final AuthorityDeviceCandidateRepository candidateRepository;
    private final AuthorityNotifications notifications;
    private final AuthorityBackoff backoff;
    private final SecurityAuditLogger auditLogger;
    private final Clock clock;

    public AccountAuthorityService(AuthorityPolicy policy, AuthorityAccounts accounts,
            AuthorityChallengeService challenges, AuthorityStepUpService stepUps,
            AuthorityChainHeadRepository headRepository, AuthorityChainRecordRepository recordRepository,
            AuthorityDeviceRepository deviceRepository, AuthorityDeviceCandidateRepository candidateRepository,
            AuthorityNotifications notifications, AuthorityBackoff backoff, SecurityAuditLogger auditLogger,
            Clock clock) {
        this.policy = policy;
        this.accounts = accounts;
        this.challenges = challenges;
        this.stepUps = stepUps;
        this.headRepository = headRepository;
        this.recordRepository = recordRepository;
        this.deviceRepository = deviceRepository;
        this.candidateRepository = candidateRepository;
        this.notifications = notifications;
        this.backoff = backoff;
        this.auditLogger = auditLogger;
        this.clock = clock;
    }

    // --- The challenge --------------------------------------------------------

    /**
     * Mints the challenge a record must sign, after the step-up that purpose is scoped to.
     *
     * <p>The step-up and the challenge are minted in one call on purpose. ADM-009 decision 4 asks for a
     * step-up "no older than the challenge", and the only way to make that true by construction rather than
     * by a second comparison is to leave no step-up artifact that outlives the challenge.
     */
    @Transactional
    public AuthorityChallengeService.Minted challenge(String userId, Optional<String> clientId, String sessionHash,
            Purpose purpose, String passkeyStepUpId, JsonNode passkeyCredential, String pin, String requesterIp) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        Resolved account = accounts.require(userId);

        // The purpose-scoped overload, so a platform that cannot run a WebAuthn assertion natively can have
        // taken the same step-up in the web sheet. A request that carries its own assertion or PIN never
        // looks at the sheet, so nothing about the native path changes.
        Accepted accepted = stepUps.accept(userId, purpose, sessionHash, policy.stepUpFor(purpose),
                passkeyStepUpId, passkeyCredential, pin, requesterIp);
        // Weighed after the factor is known to be the caller's own, and both refusals expire on their own.
        stepUps.enforceHolds(userId, purpose, accepted);

        Instant now = clock.instant();
        return challenges.mint(account.reference(), sessionHash, purpose, accepted.factor(),
                accepted.factorCreatedAt(), now);
    }

    // --- Adoption -------------------------------------------------------------

    /**
     * Records a pending adoption (ADM-009 decision 4).
     *
     * <p>The recovery artifact is confirmed before anything is written, because the end state is permanent:
     * an account that loses every device and its recovery authority key keeps its id, its login and its data
     * and never regains authority. It may not adopt again, since a second adoption authorized by login
     * factors alone is precisely the seizure O9 rejected. So adoption is refused without that confirmation
     * rather than completing and leaving the holder unaware of what they did not keep.
     */
    @Transactional
    public Submitted adopt(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64, boolean recoveryArtifactConfirmed) {
        policy.requireEnabled();
        policy.requireAdoptionPermitted();
        policy.requireNativeSession(clientId);
        if (!recoveryArtifactConfirmed) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_artifact_unconfirmed",
                    "Save your recovery key before rooting this account.");
        }
        return submit(userId, sessionHash, Purpose.ADOPT, AuthorityRecordType.ADOPT_ROOT, recordB64, signatureB64,
                challengeB64);
    }

    /**
     * Cancels every pending adoption on the account (ADM-009 decision 4, bounds).
     *
     * <p>Every one of them, not only the one named. One pending adoption per account is the rule, so the
     * difference is invisible in normal operation and decisive if it is ever not: an opposition that could be
     * made to miss a second pending record would be a veto that does not veto.
     *
     * <p>Deliberately cheap the first time. At {@code seq = 1} the account holds no authority to weigh, so
     * the honest veto is "someone who can already read this account's notifications says no". The second and
     * later oppositions need a step-up, on any factor and at any age, so a stolen bearer session cannot veto
     * the account out of ever gaining authority while remaining account-equivalent itself, and an owner whose
     * only factor is fresh can still object.
     */
    @Transactional
    public void oppose(String userId, String recordHash, String passkeyStepUpId, JsonNode passkeyCredential,
            String pin, String requesterIp) {
        policy.requireEnabled();
        Resolved account = accounts.require(userId);
        Instant now = clock.instant();
        AuthorityChainHead head = lockHead(account, now);

        // From the head rather than from the cancelled rows: a cancelled record's slot goes back, so a retry
        // replaces the row and a count taken from the rows would hand out a free veto over and over.
        if (policy.oppositionNeedsStepUp(head.getCancelledCount())) {
            // Any factor, at any age. The hold gates starting a transition and never opposing one.
            stepUps.accept(userId, policy.oppositionStepUp(), "AUTHORITY_OPPOSE", passkeyStepUpId,
                    passkeyCredential, pin, requesterIp);
        }

        if (!head.hasPending()) {
            // Nothing live. Answered the same way whether one had just completed or none ever existed, so an
            // opposition cannot be used to ask what state the account is in.
            return;
        }
        AuthorityChainRecord pending = requirePending(account, head);
        AuthorityRecord decoded = decodeStored(pending);

        // A bearer session cannot show that it is an active device, so it may only object to what decision 4
        // lets the account object to on the session alone.
        policy.requireSessionMayOppose(decoded.type(), decoded.authorization());

        Opposition outcome = policy.opposition(decoded.type(), decoded.authorization(), false, false);
        if (outcome == Opposition.REFUSED) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_refused",
                    "This account cannot object to that step.");
        }
        if (outcome == Opposition.EXTENDS_ONCE) {
            // L13.3: an active key an intruder may hold is not allowed to be the veto of a recovery signed by
            // the key the account committed for exactly this. The window is extended once and the
            // notification raised, and nothing more.
            extendOnce(account, head, pending, decoded, now);
            return;
        }

        cancelPending(account, head, pending, decoded, now, "opposed by the account holder");
        chargeCancellation(account, decoded, now);
    }

    /**
     * Cancels the pending record an active device objects to, with an {@code Oppose} it signed (ADM-009
     * decision 2's fifth record).
     *
     * <p>Separate from {@link #oppose} because the two are different claims. A bearer session can say "someone
     * who can already read this account's notifications says no", which decision 4 accepts at {@code seq = 1}
     * and nowhere else: accepting it for a grant or a revocation would let a stolen session veto the owner's
     * own revocation of the thief's device, which is the inversion decision 5's exclusion exists to prevent.
     * An {@code Oppose} is the stronger claim, signed by a key the chain has active and unquarantined right
     * now, and it is what decisions 5 and 7 mean by "an active device may oppose".
     *
     * <p><b>It takes no slot and starts no window.</b> It cancels the record it names, or it is refused, and it
     * is never appended to the chain: an objection that consumed a position would let one device cycle
     * objections and move the chain forward without any transition ever happening. The record therefore stands
     * at the same position as the record it cancels, which is what its {@code seq} and {@code prevHash} are
     * checked against.
     *
     * <p>No hold is weighed anywhere here. The fresh-factor hold and the recovery hold gate <em>starting</em> a
     * transition and never opposing one: an owner who has just changed their PIN to lock a thief out must not
     * be the one disarmed by it.
     */
    @Transactional
    public void opposeWithRecord(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        Resolved account = accounts.require(userId);
        AuthorityRecord record = decodeSubmitted(recordB64, AuthorityRecordType.OPPOSE);
        accounts.requireMatches(account, record.accountReference());

        Instant now = clock.instant();
        AuthorityChallengeService.Spent spent =
                challenges.spend(account.reference(), sessionHash, Purpose.OPPOSE, challengeB64, now);
        byte[] signature = decode(signatureB64, "bad_signature_encoding");
        if (!AuthorityProofs.verifyRecord(record, spent.challenge(), signature)) {
            throw new InvalidAuthorityRecordException("invalid_signature",
                    "the signature does not verify over magic, challenge and canonical bytes");
        }

        AuthorityChainHead head = lockHead(account, now);
        if (!head.hasPending()) {
            // Settled while this was in flight, or never there. Answered the same way either way, so an
            // opposition cannot be used to ask what state the account is in.
            return;
        }
        AuthorityChainRecord pending = requirePending(account, head);
        if (!head.getPendingHash().equalsIgnoreCase(record.opposedRecordHashHex())
                || record.seq() != pending.getSeq()
                || !record.prevHashHex().equalsIgnoreCase(pending.getPrevHash())) {
            // Named something else, or was built against another position of this chain. Either way it is not
            // an objection to what is actually pending.
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_opposition_stale",
                    "That objection names a different step. Read the chain again.");
        }

        List<AuthorityDevice> devices = deviceRepository.findByAccount(account.reference());
        AuthorityDevice signer = requireKnownDevice(devices, record.verifyingKey());
        // A quarantined device may not sign an authority-sensitive approval, and an objection is one.
        policy.requireNotQuarantined(signer.isQuarantined(now));

        AuthorityRecord decoded = decodeStored(pending);
        boolean opposerIsNamedDevice = decoded.deviceKey() != null
                && encode(decoded.deviceKey()).equals(signer.getDeviceKeyB64());
        Opposition outcome = policy.opposition(decoded.type(), decoded.authorization(), opposerIsNamedDevice,
                acceptingWouldLeaveSignerAlone(decoded, devices, now));
        if (outcome == Opposition.REFUSED) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_refused",
                    "That device cannot object to this step.");
        }
        if (outcome == Opposition.EXTENDS_ONCE) {
            extendOnce(account, head, pending, decoded, now);
            return;
        }
        cancelPending(account, head, pending, decoded, now, "opposed by an active device");
        chargeCancellation(account, decoded, now);
    }

    /**
     * Whether accepting the pending revocation would leave the device that signed it as the only active one.
     *
     * <p>The carve-out of decision 5. Revision 2's unconditional "the named device may not veto its own
     * removal" handed the mirror-image power to an intruder: one device evicting the other with no objection
     * possible is a takeover, while a standoff between two devices is a worse outcome for nobody. The standoff
     * is broken by the rank-2 record, which no pending revocation can block and no device can cast.
     */
    private static boolean acceptingWouldLeaveSignerAlone(AuthorityRecord pending, List<AuthorityDevice> devices,
            Instant now) {
        if (pending.type() != AuthorityRecordType.DEVICE_REVOKE) {
            return false;
        }
        String target = Base64.getUrlEncoder().withoutPadding().encodeToString(pending.deviceKey());
        long remaining = devices.stream()
                .filter(device -> !device.getDeviceKeyB64().equals(target))
                .filter(device -> device.isUnquarantinedActive(now))
                .count();
        return remaining == 1;
    }

    // --- Devices --------------------------------------------------------------

    /**
     * Offers this device's own public key as a candidate for a grant (ADM-009 decision 5, revision 4).
     *
     * <p>The new device posts only its public key, under its own authenticated session, and gets back a short
     * fingerprint. Revisions 1 to 3 fixed both ends of the transfer and left this middle undefined: the new
     * device generates its own key and never receives another device's, an existing device signs a grant over
     * it, and nothing said how the public key crossed between them.
     *
     * <p>No step-up and no native-session rule here, deliberately. Offering a public key grants nothing: it
     * creates something an existing active device must then sign over, after a human has compared the
     * fingerprint on both screens. The controls belong on the grant, which is where authority actually moves.
     *
     * <p>An upsert, so a device that offers twice refreshes its own row rather than filling the account with
     * copies of one key.
     */
    @Transactional
    public Candidate registerCandidate(String userId, String deviceKeyB64, String label) {
        policy.requireEnabled();
        Resolved account = accounts.require(userId);
        byte[] deviceKey = decode(deviceKeyB64, "bad_device_key_encoding");
        if (deviceKey.length != AuthorityRecord.KEY_LENGTH) {
            throw new InvalidAuthorityRecordException("invalid_device_key",
                    "a device key is " + AuthorityRecord.KEY_LENGTH + " bytes");
        }
        String encoded = encode(deviceKey);
        Instant now = clock.instant();
        // Swept here rather than by a scheduler, as the challenge table is swept and for the same reason.
        candidateRepository.deleteExpired(now);

        Instant expiresAt = now.plus(policy.candidateLife());
        AuthorityDeviceCandidate candidate = candidateRepository
                .findByAccountAndDeviceKeyB64(account.reference(), encoded)
                .orElseGet(() -> AuthorityDeviceCandidate.offered(account.reference(), encoded,
                        AuthorityFingerprint.of(deviceKey), label, now, expiresAt));
        candidate.setLabel(label);
        candidate.setExpiresAt(expiresAt);
        candidateRepository.save(candidate);

        return new Candidate(encoded, candidate.getFingerprint(), candidate.getLabel(),
                expiresAt.getEpochSecond());
    }

    /**
     * The keys this account's new devices have offered, for the device that will sign the grant.
     *
     * <p>The granting device shows the fingerprint beside the label, and the person holding the other phone
     * reads the same eight characters off their own screen. That comparison is the only thing binding the key
     * to the person, which is why the fingerprint is derived from the key rather than issued by the server.
     */
    @Transactional
    public List<Candidate> candidates(String userId) {
        policy.requireEnabled();
        Resolved account = accounts.require(userId);
        Instant now = clock.instant();
        candidateRepository.deleteExpired(now);
        return candidateRepository.findByAccount(account.reference()).stream()
                .filter(candidate -> candidate.isLive(now))
                .map(candidate -> new Candidate(candidate.getDeviceKeyB64(), candidate.getFingerprint(),
                        candidate.getLabel(), candidate.getExpiresAt().getEpochSecond()))
                .toList();
    }

    /**
     * Activates another device key (ADM-009 decision 5).
     *
     * <p>Takes effect on acceptance, because it only adds, and reserves no slot. What waits is the granted
     * device's quarantine: it may not sign a grant, a revocation or an approval, and it does not count toward
     * the active device a revocation must leave behind. Without that second half a borrowed unlocked phone
     * grants a device and then self-revokes, which is two records, no delay and nothing to oppose, and the
     * owner's own phone is left with no authority.
     */
    @Transactional
    public Submitted grantDevice(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.GRANT, AuthorityRecordType.DEVICE_GRANT, recordB64, signatureB64,
                challengeB64);
    }

    /**
     * Removes a device key (ADM-009 decision 5).
     *
     * <p>Revoking another device waits out the window and is notified. Revoking itself takes effect
     * immediately, because a device removing its own authority reduces what an attacker holding it could do
     * and delaying that helps nobody. Neither may leave the account with no unquarantined active device: an
     * account with one device that wants to replace it goes through {@code AuthorityRecovery}, which installs
     * the replacement in the same record.
     */
    @Transactional
    public Submitted revokeDevice(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.REVOKE, AuthorityRecordType.DEVICE_REVOKE, recordB64,
                signatureB64, challengeB64);
    }

    /**
     * Replaces the device set with one device and installs a new recovery authority key (ADM-009 decision 7).
     *
     * <p>Both authorizations carry adoption's controls: the native app, a server challenge inside the
     * preimage, a step-up scoped to this operation on a factor past the fresh-factor hold, and the refusal
     * while the account's last completed recovery is inside that hold. Revision 2 of ADM-009 bolted every new
     * control to the adoption record and left this one as it was, which meant one magic byte reached the same
     * seizure by a shorter route.
     *
     * <p>Neither path is gated on the account having no active device. A lost phone stays active in the chain
     * until something revokes it, so gating it that way left the ordinary lost-phone case with no path at all
     * and made a remote wipe terminal. The immediate active-device veto on the weaker path is what protects
     * it, and that does not need a precondition the chain cannot observe.
     */
    @Transactional
    public Submitted recoverAuthority(String userId, Optional<String> clientId, String sessionHash,
            String recordB64, String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.RECOVER, AuthorityRecordType.AUTHORITY_RECOVERY, recordB64,
                signatureB64, challengeB64);
    }

    // --- The one submission path ---------------------------------------------

    /**
     * Everything the four transitions share, in the order ADM-009 decision 3 states it.
     *
     * <p>One method rather than four, because revision 2's holes were all of the same shape: a control written
     * for one record type and missing from another. A reader checking that every record signs a challenge,
     * that every record is matched against the account the session resolved, and that every record is refused
     * at a position its type does not permit has one place to check.
     */
    private Submitted submit(String userId, String sessionHash, Purpose purpose, AuthorityRecordType expected,
            String recordB64, String signatureB64, String challengeB64) {
        Resolved account = accounts.require(userId);
        AuthorityRecord record = decodeSubmitted(recordB64, expected);

        // Decision 3 rule 2: the account comes from the server's own session state, and the value in the
        // request is only ever compared against it, never used to look anything up.
        accounts.requireMatches(account, record.accountReference());

        Instant now = clock.instant();
        // Burned here, before the record is verified, so acceptance and refusal burn it alike. A caller whose
        // record was refused asks for a new challenge rather than retrying against the old one.
        AuthorityChallengeService.Spent spent =
                challenges.spend(account.reference(), sessionHash, purpose, challengeB64, now);

        // Re-weighed at submission and not only at minting, because a recovery can complete in between and
        // the point of the rule is the composition of the two clocks.
        if (spent.factor() != null) {
            policy.enforceFreshFactorHold(spent.factorCreatedAt());
        }
        policy.enforceRecoveryOutsideHold(userId);

        byte[] signature = decode(signatureB64, "bad_signature_encoding");
        if (!AuthorityProofs.verifyRecord(record, spent.challenge(), signature)) {
            // Under the key the type names, which is not yet a statement that the account accepts that key.
            throw new InvalidAuthorityRecordException("invalid_signature",
                    "the signature does not verify over magic, challenge and canonical bytes");
        }

        boolean immediate = policy.takesEffectImmediately(record);
        if (!immediate) {
            // ADM-009 gate 2, asked about this account rather than about the deployment. A window is the whole
            // security of the transition, so one whose holder cannot be told is a delay and not a control: the
            // honest answer is to refuse the transition, not to run the window and hope.
            policy.requireReachableOutOfBand(notifications.reachesOutOfBandChannel(userId));
        }

        AuthorityChainHead head = lockHead(account, now);
        List<AuthorityDevice> devices = deviceRepository.findByAccount(account.reference());

        policy.requirePermittedAt(record.type(), record.authorization(),
                new ChainContext(head.isChainEmpty(), account.genesisRooted(),
                        holdsCommittedAuthority(account, head), countUnquarantinedActive(devices, now)));

        // Decision 3 rule 1, and the whole of the compare-and-set. Checked under the lock, so the refusal a
        // loser gets carries the head the winner left behind.
        if (record.seq() != head.nextSeq()
                || !record.prevHashHex().equalsIgnoreCase(head.nextPrevHash())) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_head_conflict",
                    "The chain moved. Read it again and decide with the other record in view.");
        }

        // Both budgets are read here, before this request has written anything to the head. Read after the
        // cancellation below, the cooldown read is the value this very request just wrote, which refused every
        // outranking record for a full window and made the rank-2 escape hatch of decision 3 unreachable for
        // every rank pair.
        policy.requireOutsideBackoff(backoff.until(account.reference(), encode(record.verifyingKey())).orElse(null),
                now);
        policy.requireOutsideCooldown(head.getCooldownUntil(), head.getCooldownMagic(), record.type().magic(),
                now);

        short rank = policy.rankOf(record.type(), record.authorization());
        AuthorityChainRecord cancelled = null;
        AuthorityRecord cancelledRecord = null;
        if (head.hasPending()) {
            if (policy.resolveAgainstPending(rank, head.getPendingRank()) == SlotOutcome.REFUSED) {
                throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_pending_conflict",
                        "Another step is already waiting on this account.");
            }
            // A higher rank is accepted while a lower one is pending, and cancels it. Rank 2 is therefore
            // always reachable: the one record the owner can always land is the one signed by the key they
            // committed for exactly this, and it is not a key an intruder holding devices has.
            cancelled = requirePending(account, head);
            cancelledRecord = decodeStored(cancelled);
            cancelPending(account, head, cancelled, cancelledRecord, now, "outranked by a later record");
        }

        requireSignerMayAct(account, record, devices, now);

        if (cancelledRecord != null) {
            // ADM-002 D2's last sentence, charged only once this submission is known to be accepted. The
            // backoff lives in Redis and commits independently of this transaction, so a charge made before
            // the last refusal survives the rollback of everything else: four refused attempts reached the cap
            // and locked the victim's own key out for days, which is precisely the starvation the rank table
            // exists to prevent.
            chargeCancellation(account, cancelledRecord, now);
        }

        Instant effectiveAt = immediate ? now : now.plus(policy.windowFor(record.type(), record.authorization()));
        // The position the record itself claims, which the compare-and-set above already proved was the next
        // one. Read from the record rather than from the head, because a cancellation between the two gave the
        // outranked record's slot back and this record must still land where it was built and signed for.
        long seq = record.seq();

        recordRepository.save(AuthorityChainRecord.of(account.reference(), seq, record.type().magic(), recordB64,
                record.hashHex(), record.prevHashHex(), signatureB64, encode(record.verifyingKey()),
                immediate ? AuthorityChainRecord.State.ACTIVE : AuthorityChainRecord.State.PENDING,
                effectiveAt, now));
        head.place(record.hashHex(), seq, record.type().magic(), rank, immediate ? null : effectiveAt, now);
        headRepository.save(head);

        if (immediate) {
            applyEffect(account, record, seq, now, false);
            notifications.completed(userId, record.type().name(), record.label());
        } else {
            // Every channel the account has, at least one of which must be one an account recovery cannot
            // empty. The notification names the device label and the time the transition will complete.
            notifications.pending(userId, record.type().name(), record.label(), effectiveAt);
        }
        auditLogger.reauthFailed(userId, "AUTHORITY_" + purpose + "_ACCEPTED", null);
        log.info("Authority transition {} accepted at seq {} (pending={})", record.type(), seq, !immediate);

        return new Submitted(seq, !immediate, effectiveAt.getEpochSecond(), record.hashHex());
    }

    /**
     * Whether the key that signed may do this to this account's device set (ADM-009 decisions 5 and 7).
     *
     * <p>{@code AdoptRoot} is signed by the device key it installs, so there is nothing to look up. A
     * recovery under the committed recovery authority key must name the key the chain last committed for that
     * purpose, and one authorized through account recovery is signed by the device it installs. A grant and a
     * revocation must be signed by an active, unquarantined device.
     */
    private void requireSignerMayAct(Resolved account, AuthorityRecord record, List<AuthorityDevice> devices,
            Instant now) {
        switch (record.type()) {
            case ADOPT_ROOT -> {
                // Signed by the key it installs. Holding it proves only that it was generated on the device
                // that submitted, which is what the step-up, the challenge and the window are for.
            }
            case DEVICE_GRANT, DEVICE_REVOKE -> {
                AuthorityDevice signer = requireKnownDevice(devices, record.verifyingKey());
                policy.requireNotQuarantined(signer.isQuarantined(now));
                if (record.type() == AuthorityRecordType.DEVICE_GRANT) {
                    // The key has to be one a device of this account offered, and offered recently. Without
                    // it a grant is a signature over 32 bytes from anywhere, and the human fingerprint
                    // comparison the ceremony rests on has nothing behind it on the server side.
                    policy.requireLiveCandidate(candidateRepository
                            .findByAccountAndDeviceKeyB64(account.reference(), encode(record.deviceKey()))
                            .filter(candidate -> candidate.isLive(now))
                            .isPresent());
                }
                if (record.type() == AuthorityRecordType.DEVICE_REVOKE) {
                    policy.requireLeavesAnActiveDevice(
                            countUnquarantinedActiveAfterRevoking(devices, record.deviceKey(), now));
                }
            }
            case AUTHORITY_RECOVERY -> {
                if (record.authorization() == AuthorityRecord.AUTHORIZATION_RECOVERY_KEY
                        && !committedRecoveryKey(account).equals(Optional.of(encode(record.verifyingKey())))) {
                    throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_signer_refused",
                            "That is not the recovery key this account committed.");
                }
            }
            case OPPOSE -> throw new IllegalStateException("an Oppose never joins the chain");
        }
    }

    private AuthorityDevice requireKnownDevice(List<AuthorityDevice> devices, byte[] key) {
        String encoded = encode(key);
        return devices.stream()
                .filter(device -> device.getDeviceKeyB64().equals(encoded))
                .filter(device -> device.getState() != AuthorityDevice.State.REVOKED)
                .findFirst()
                .orElseThrow(() -> new AuthorityTransitionException(HttpStatus.FORBIDDEN,
                        "authority_signer_refused", "That device cannot authorize this."));
    }

    private static int countUnquarantinedActive(List<AuthorityDevice> devices, Instant now) {
        return (int) devices.stream().filter(device -> device.isUnquarantinedActive(now)).count();
    }

    private static int countUnquarantinedActiveAfterRevoking(List<AuthorityDevice> devices, byte[] deviceKey,
            Instant now) {
        String target = Base64.getUrlEncoder().withoutPadding().encodeToString(deviceKey);
        return (int) devices.stream()
                .filter(device -> !device.getDeviceKeyB64().equals(target))
                .filter(device -> device.isUnquarantinedActive(now))
                .count();
    }

    /**
     * The recovery authority key the chain last committed: the one an adoption or an earlier recovery
     * installed, or the one a class 0x01 accountId committed in its genesis.
     *
     * <p>Read back out of the chain rather than kept in a column of its own, because the chain is the
     * authority and a second copy is a second thing that can disagree with it.
     */
    private Optional<String> committedRecoveryKey(Resolved account) {
        List<AuthorityChainRecord> rows = recordRepository.findByAccountOrderBySeqAsc(account.reference());
        for (int i = rows.size() - 1; i >= 0; i--) {
            AuthorityChainRecord row = rows.get(i);
            if (row.getState() != AuthorityChainRecord.State.ACTIVE) {
                continue;
            }
            AuthorityRecord decoded = decodeStored(row);
            if (decoded.recoveryAuthorityKey() != null) {
                return Optional.of(encode(decoded.recoveryAuthorityKey()));
            }
        }
        // A class 0x01 account committed one inside its genesis, which this service reads through the one file
        // allowed to resolve an account object.
        return Optional.ofNullable(account.committedRecoveryKeyB64());
    }

    /**
     * Whether the account already holds a committed authority, which decision 3 rule 3 requires before an
     * {@code AuthorityRecovery} may be accepted: a class 0x01 account's genesis key, or a class 0x00
     * account's completed adoption. It is never a bootstrap account's first record.
     */
    private boolean holdsCommittedAuthority(Resolved account, AuthorityChainHead head) {
        if (account.genesisRooted()) {
            return true;
        }
        return recordRepository.findByAccountAndState(account.reference(), AuthorityChainRecord.State.ACTIVE)
                .stream()
                .anyMatch(row -> AuthorityRecordType.ADOPT_ROOT.magic().equals(row.getMagic()));
    }

    // --- Reading --------------------------------------------------------------

    /**
     * The account's chain, device set and pending transition, for its own holder.
     *
     * <p>Settles a window that has passed before reporting, so the holder is never shown a pending record the
     * server would treat as complete.
     */
    @Transactional
    public AuthorityStateResponse state(String userId) {
        policy.requireEnabled();
        Resolved account = accounts.require(userId);
        Instant now = clock.instant();
        AuthorityChainHead head = lockHead(account, now);

        List<AuthorityDevice> devices = deviceRepository.findByAccount(account.reference());
        List<DeviceView> views = new ArrayList<>();
        for (AuthorityDevice device : devices) {
            views.add(new DeviceView(device.getDeviceKeyB64(), device.getLabel(), device.getState().name(),
                    device.getQuarantineUntil() == null ? null : device.getQuarantineUntil().getEpochSecond(),
                    device.getGrantedSeq()));
        }

        PendingView pending = null;
        if (head.hasPending()) {
            pending = new PendingView(typeOfMagic(head.getPendingMagic()).name(), head.getPendingSeq(),
                    head.getPendingEffectiveAt().getEpochSecond(), head.getPendingHash());
        }

        return new AuthorityStateResponse(account.reference(), account.className(),
                chainState(account, head, devices, now).wire(), head.getHeadSeq(), head.getHeadHash(), views,
                pending);
    }

    // --- Head, locking and lazy settlement -----------------------------------

    /**
     * Locks the head row, creating it for an account that has never had one, and settles a window that has
     * passed.
     *
     * <p>Created and flushed under the lock so two creators meet on the primary key rather than both
     * inserting, which is the shape every other writer of a one-row-per-account table here uses.
     */
    private AuthorityChainHead lockHead(Resolved account, Instant now) {
        AuthorityChainHead head = headRepository.findByAccountForUpdate(account.reference())
                .orElseGet(() -> {
                    AuthorityChainHead created = headRepository.saveAndFlush(
                            AuthorityChainHead.empty(account.reference(), now));
                    return headRepository.findByAccountForUpdate(created.getAccount()).orElse(created);
                });
        materialiseCommittedDevice(account, now);
        settle(account, head, now);
        return head;
    }

    /**
     * Gives a class 0x01 account the device row its accountId already committed.
     *
     * <p>Decision 10: such an account is {@code ROOTED} from creation with an empty chain, because its genesis
     * authority key is its first device key, committed by the id itself rather than by a record. Materialising
     * it at position 0 is what lets every later rule read the device set instead of carrying a special case
     * for "the key that is in the id".
     */
    private void materialiseCommittedDevice(Resolved account, Instant now) {
        if (!account.genesisRooted() || !StringUtils.hasText(account.committedAuthorityKeyB64())) {
            return;
        }
        String key = account.committedAuthorityKeyB64();
        if (deviceRepository.findByAccountAndDeviceKeyB64(account.reference(), key).isPresent()) {
            return;
        }
        deviceRepository.save(AuthorityDevice.granted(account.reference(), key, null, 0L, null,
                AuthorityDevice.State.ACTIVE, now));
    }

    /** Promotes a pending record whose window has passed, and ends a quarantine that has run out. */
    private void settle(Resolved account, AuthorityChainHead head, Instant now) {
        for (AuthorityDevice device : deviceRepository.findByAccount(account.reference())) {
            if (device.getState() == AuthorityDevice.State.QUARANTINED && !device.isQuarantined(now)) {
                device.setState(AuthorityDevice.State.ACTIVE);
                deviceRepository.save(device);
            }
        }
        if (!head.hasPending() || now.isBefore(head.getPendingEffectiveAt())) {
            return;
        }
        AuthorityChainRecord pending = requirePending(account, head);
        AuthorityRecord decoded = decodeStored(pending);
        applyEffect(account, decoded, pending.getSeq(), now, true);

        pending.setState(AuthorityChainRecord.State.ACTIVE);
        pending.setSettledAt(now);
        recordRepository.save(pending);

        head.setHeadHash(pending.getRecordHash());
        head.setHeadSeq(pending.getSeq());
        head.clearPending();
        head.setUpdatedAt(now);
        headRepository.save(head);

        // The account holder, not null. Everything raised outside the submitting request used to pass none,
        // and the notifier drops a notification with no holder to name, so the completion of every window, the
        // cancellation of every transition and the one thing decision 7 leaves an active device able to do
        // against a rank-2 recovery all reached nobody.
        notifications.completed(account.userId(), decoded.type().name(), decoded.label());
        log.info("Authority transition {} completed after its window", decoded.type());
    }

    private AuthorityChainRecord requirePending(Resolved account, AuthorityChainHead head) {
        return recordRepository.findByAccountAndSeq(account.reference(), head.getPendingSeq())
                .orElseThrow(() -> new IllegalStateException(
                        "the head reserves a slot with no record behind it"));
    }

    /**
     * Extends the pending window once, which is all decision 7 lets an active device do to a rank-2 recovery.
     *
     * <p>Once, and the head carries whether it has happened. The alternative is not "an extension per
     * objection": an Oppose costs no factor and no backoff, and nothing an extension changes is part of the
     * staleness check, so a second one is the same objection again and a thief holding every active key would
     * postpone the owner's recovery indefinitely.
     */
    private void extendOnce(Resolved account, AuthorityChainHead head, AuthorityChainRecord pending,
            AuthorityRecord decoded, Instant now) {
        policy.requireExtensionUnspent(head.isPendingExtended());
        Instant extended = head.getPendingEffectiveAt().plus(policy.oppositionWindow());
        head.setPendingEffectiveAt(extended);
        head.setPendingExtended(true);
        head.setUpdatedAt(now);
        headRepository.save(head);
        pending.setEffectiveAt(extended);
        recordRepository.save(pending);
        notifications.pending(account.userId(), decoded.type().name(), decoded.label(), extended);
    }

    private void cancelPending(Resolved account, AuthorityChainHead head, AuthorityChainRecord pending,
            AuthorityRecord decoded, Instant now, String reason) {
        pending.setState(AuthorityChainRecord.State.CANCELLED);
        pending.setSettledAt(now);
        recordRepository.save(pending);

        // The slot goes back. A cancelled record that kept it left a bootstrap account with headSeq 1 and no
        // route to adoption ever again, because AdoptRoot is permitted only on an empty chain: one free
        // opposition, or one mistaken tap, denied the account its authority permanently and reported it as
        // AUTHORITY_LOST. The retry then lands at the position both clients build it for.
        head.rollBackTo(pending.getPrevHash(), pending.getSeq());
        head.clearPending();
        head.startCooldown(decoded.type().magic(), now.plus(policy.oppositionWindow()));
        head.setUpdatedAt(now);
        headRepository.save(head);

        challenges.burnUnspent(account.reference(), purposeOf(decoded.type()), now);
        notifications.cancelled(account.userId(), decoded.type().name(), decoded.label());
        log.info("Authority transition {} cancelled: {}", decoded.type(), reason);
    }

    /**
     * ADM-002 D2's last sentence: the key set that opened the cancelled initiation pays the doubling.
     *
     * <p>Charged by the caller, once the cancellation is certain, rather than inside {@code cancelPending}.
     * The counter is in Redis, which has no part in this transaction, so a charge made before a later refusal
     * is not undone by the rollback: on the submission path that let an attacker charge the <em>victim's</em>
     * device key, repeatedly and for free, with a record that was then refused for a reason of its own.
     */
    private void chargeCancellation(Resolved account, AuthorityRecord cancelled, Instant now) {
        backoff.recordCancellation(account.reference(), encode(cancelled.verifyingKey()), now);
    }

    // --- Effects on the device set -------------------------------------------

    private void applyEffect(Resolved account, AuthorityRecord record, long seq, Instant now, boolean settled) {
        switch (record.type()) {
            case ADOPT_ROOT -> deviceRepository.save(AuthorityDevice.granted(account.reference(),
                    encode(record.deviceKey()), record.label(), seq, null, AuthorityDevice.State.ACTIVE, now));
            case DEVICE_GRANT -> {
                deviceRepository.save(AuthorityDevice.granted(account.reference(), encode(record.deviceKey()),
                        record.label(), seq, policy.quarantineUntil(now), AuthorityDevice.State.QUARANTINED,
                        now));
                // Spent. A candidate that outlived the grant it was offered for would let a second grant be
                // signed over the same key without anybody comparing a fingerprint again.
                candidateRepository.findByAccountAndDeviceKeyB64(account.reference(), encode(record.deviceKey()))
                        .ifPresent(candidateRepository::delete);
            }
            case DEVICE_REVOKE -> revokeDeviceRow(account, record.deviceKey(), seq, now);
            case AUTHORITY_RECOVERY -> {
                // Replaces the set with one device. Every previous key goes, because the premise of recovering
                // authority is that the set cannot be used by the account holder.
                for (AuthorityDevice device : deviceRepository.findByAccount(account.reference())) {
                    if (device.getState() != AuthorityDevice.State.REVOKED) {
                        device.setState(AuthorityDevice.State.REVOKED);
                        device.setRevokedSeq(seq);
                        deviceRepository.save(device);
                    }
                }
                deviceRepository.save(AuthorityDevice.granted(account.reference(), encode(record.deviceKey()),
                        record.label(), seq, null, AuthorityDevice.State.ACTIVE, now));
            }
            // It takes no slot and starts no window: it cancels the record it names, or it is refused.
            case OPPOSE -> throw new IllegalStateException("an Oppose has no effect to apply");
        }
    }

    private void revokeDeviceRow(Resolved account, byte[] deviceKey, long seq, Instant now) {
        deviceRepository.findByAccountAndDeviceKeyB64(account.reference(), encode(deviceKey))
                .ifPresent(device -> {
                    device.setState(AuthorityDevice.State.REVOKED);
                    device.setRevokedSeq(seq);
                    deviceRepository.save(device);
                });
    }

    // --- Small helpers --------------------------------------------------------

    /** The five states of decision 10, which is a statement about keys rather than about chain length. */
    private ChainState chainState(Resolved account, AuthorityChainHead head, List<AuthorityDevice> devices,
            Instant now) {
        if (head.hasPending()) {
            return typeOfMagic(head.getPendingMagic()) == AuthorityRecordType.ADOPT_ROOT
                    ? ChainState.ADOPTION_PENDING
                    : ChainState.RECOVERY_PENDING;
        }
        boolean anyActive = devices.stream().anyMatch(device -> device.isUnquarantinedActive(now));
        if (anyActive) {
            return ChainState.ROOTED;
        }
        boolean everRooted = account.genesisRooted() || head.getHeadSeq() > 0;
        if (!everRooted) {
            return ChainState.BOOTSTRAP;
        }
        // Rooted with nothing active left. Whether it is recoverable depends on a key the server does not
        // hold, so this is reported as the terminal state and the chain still accepts a rank-2 recovery: an
        // account that can produce the committed recovery key is not lost, and one that cannot is.
        return ChainState.AUTHORITY_LOST;
    }

    private static Purpose purposeOf(AuthorityRecordType type) {
        return switch (type) {
            case ADOPT_ROOT -> Purpose.ADOPT;
            case DEVICE_GRANT -> Purpose.GRANT;
            case DEVICE_REVOKE -> Purpose.REVOKE;
            case AUTHORITY_RECOVERY -> Purpose.RECOVER;
            case OPPOSE -> Purpose.OPPOSE;
        };
    }

    private static AuthorityRecordType typeOfMagic(String magic) {
        for (AuthorityRecordType type : AuthorityRecordType.values()) {
            if (type.magic().equals(magic)) {
                return type;
            }
        }
        throw new IllegalStateException("a stored record carries an unknown magic");
    }

    private AuthorityRecord decodeSubmitted(String recordB64, AuthorityRecordType expected) {
        AuthorityRecord record = AuthorityRecordCodec.decode(decode(recordB64, "bad_record_encoding"));
        if (record.type() != expected) {
            // The endpoint fixes the type, so a record of another type arriving here is a client error rather
            // than a policy question. Refusing it by name also means no endpoint can be talked into accepting
            // a transition it does not implement.
            throw new InvalidAuthorityRecordException("unexpected_record_type",
                    "this endpoint accepts " + expected + " only");
        }
        return record;
    }

    private AuthorityRecord decodeStored(AuthorityChainRecord row) {
        return AuthorityRecordCodec.decode(decode(row.getRecordB64(), "bad_record_encoding"));
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] decode(String value, String reason) {
        if (!StringUtils.hasText(value)) {
            throw new InvalidAuthorityRecordException(reason, "value is missing");
        }
        try {
            return Base64.getUrlDecoder().decode(value.trim());
        } catch (IllegalArgumentException ex) {
            throw new InvalidAuthorityRecordException(reason, "value is not base64url", ex);
        }
    }

    /**
     * What a submitted record did.
     *
     * @param seq                      the position it took
     * @param pending                  whether it is inside a window rather than in the chain
     * @param effectiveAtEpochSeconds  when it completes, or when it completed
     * @param recordHash               SHA-256 hex over its canonical bytes, which an opposition names
     */
    public record Submitted(long seq, boolean pending, long effectiveAtEpochSeconds, String recordHash) {
    }

    /**
     * A key a new device has offered.
     *
     * @param deviceKeyB64          the raw Ed25519 public key it generated, base64url
     * @param fingerprint           the eight characters both devices compute and a person compares
     * @param label                 what the new device suggests calling itself
     * @param expiresAtEpochSeconds when the offer stops being grantable
     */
    public record Candidate(String deviceKeyB64, String fingerprint, String label, long expiresAtEpochSeconds) {
    }
}
