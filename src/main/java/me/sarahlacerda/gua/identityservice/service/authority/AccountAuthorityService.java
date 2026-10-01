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
 * Every write locks the head row and is a compare-and-set on prevHash and seq. Windows settle lazily, on
 * read and on the next write; there is no scheduler.
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
    private final AuthorityHeadPublisher publisher;
    private final SecurityAuditLogger auditLogger;
    private final Clock clock;

    public AccountAuthorityService(AuthorityPolicy policy, AuthorityAccounts accounts,
            AuthorityChallengeService challenges, AuthorityStepUpService stepUps,
            AuthorityChainHeadRepository headRepository, AuthorityChainRecordRepository recordRepository,
            AuthorityDeviceRepository deviceRepository, AuthorityDeviceCandidateRepository candidateRepository,
            AuthorityNotifications notifications, AuthorityBackoff backoff, AuthorityHeadPublisher publisher,
            SecurityAuditLogger auditLogger, Clock clock) {
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
        this.publisher = publisher;
        this.auditLogger = auditLogger;
        this.clock = clock;
    }

    @Transactional
    public AuthorityChallengeService.Minted challenge(String userId, Optional<String> clientId, String sessionHash,
            Purpose purpose, String passkeyStepUpId, JsonNode passkeyCredential, String pin, String requesterIp) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        Resolved account = accounts.require(userId);

        Accepted accepted = stepUps.accept(userId, purpose, sessionHash, policy.stepUpFor(purpose),
                passkeyStepUpId, passkeyCredential, pin, requesterIp);
        stepUps.enforceHolds(userId, purpose, accepted);

        Instant now = clock.instant();
        return challenges.mint(account.reference(), sessionHash, purpose, accepted.factor(),
                accepted.factorCreatedAt(), now);
    }

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

    /** The first opposition needs no step-up. */
    @Transactional
    public void oppose(String userId, String recordHash, String passkeyStepUpId, JsonNode passkeyCredential,
            String pin, String requesterIp) {
        policy.requireEnabled();
        Resolved account = accounts.require(userId);
        Instant now = clock.instant();
        AuthorityChainHead head = lockHead(account, now);

        if (policy.oppositionNeedsStepUp(head.getCancelledCount())) {
            stepUps.accept(userId, policy.oppositionStepUp(), "AUTHORITY_OPPOSE", passkeyStepUpId,
                    passkeyCredential, pin, requesterIp);
        }

        if (!head.hasPending()) {
            // Same answer whether or not anything was pending, so the caller learns nothing about the account.
            return;
        }
        if (!head.getPendingHash().equalsIgnoreCase(recordHash)) {
            throw opposesADifferentStep();
        }
        AuthorityChainRecord pending = requirePending(account, head);
        AuthorityRecord decoded = decodeStored(pending);

        policy.requireSessionMayOppose(decoded.type(), decoded.authorization());

        Opposition outcome = policy.opposition(decoded.type(), decoded.authorization(), false, false);
        if (outcome == Opposition.REFUSED) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_refused",
                    "This account cannot object to that step.");
        }
        if (outcome == Opposition.EXTENDS_ONCE) {
            // A recovery signed by the committed recovery key cannot be vetoed, only extended once.
            extendOnce(account, head, pending, decoded, now);
            return;
        }

        cancelPending(account, head, pending, decoded, now, "opposed by the account holder");
        chargeCancellation(account, decoded, now);
    }

    /** An Oppose is never appended to the chain: it cancels the record it names and takes no slot. */
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
        boolean namesThePending = head.hasPending()
                && head.getPendingHash().equalsIgnoreCase(record.opposedRecordHashHex());
        // A grant holds no pending slot; it stays opposable while the granted device is quarantined.
        AuthorityChainRecord opposable = namesThePending
                ? requirePending(account, head)
                : liveGrant(account, record.opposedRecordHashHex(), now).orElse(null);
        if (opposable == null) {
            if (head.hasPending()) {
                throw opposesADifferentStep();
            }
            return;
        }
        if (record.seq() != opposable.getSeq()
                || !record.prevHashHex().equalsIgnoreCase(opposable.getPrevHash())) {
            throw opposesADifferentStep();
        }

        List<AuthorityDevice> devices = deviceRepository.findByAccount(account.reference());
        AuthorityDevice signer = requireKnownDevice(devices, record.verifyingKey());
        policy.requireNotQuarantined(signer.isQuarantined(now));

        AuthorityRecord decoded = decodeStored(opposable);
        boolean opposerIsNamedDevice = decoded.deviceKey() != null
                && encode(decoded.deviceKey()).equals(signer.getDeviceKeyB64());
        Opposition outcome = policy.opposition(decoded.type(), decoded.authorization(), opposerIsNamedDevice,
                acceptingWouldLeaveSignerAlone(decoded, devices, now));
        if (outcome == Opposition.REFUSED) {
            throw new AuthorityTransitionException(HttpStatus.FORBIDDEN, "authority_opposition_refused",
                    "That device cannot object to this step.");
        }
        if (outcome == Opposition.EXTENDS_ONCE) {
            extendOnce(account, head, opposable, decoded, now);
            return;
        }
        if (!namesThePending) {
            // Opposing a grant revokes the granted device; the grant record itself stays in the chain.
            revokeGrantedDevice(account, head, opposable, decoded, now);
            chargeCancellation(account, decoded, now);
            return;
        }
        cancelPending(account, head, opposable, decoded, now, "opposed by an active device");
        chargeCancellation(account, decoded, now);
    }

    private static AuthorityTransitionException opposesADifferentStep() {
        return new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_opposition_stale",
                "That objection names a different step. Read the chain again.");
    }

    private Optional<AuthorityChainRecord> liveGrant(Resolved account, String recordHash, Instant now) {
        return recordRepository.findByAccountAndRecordHash(account.reference(), recordHash)
                .filter(row -> AuthorityRecordType.DEVICE_GRANT.magic().equals(row.getMagic()))
                .filter(row -> row.getState() == AuthorityChainRecord.State.ACTIVE)
                .filter(row -> deviceRepository
                        .findByAccountAndDeviceKeyB64(account.reference(), encode(decodeStored(row).deviceKey()))
                        .filter(device -> device.getState() != AuthorityDevice.State.REVOKED)
                        .filter(device -> device.isQuarantined(now))
                        .isPresent());
    }

    private void revokeGrantedDevice(Resolved account, AuthorityChainHead head, AuthorityChainRecord grant,
            AuthorityRecord decoded, Instant now) {
        revokeDeviceRow(account, decoded.deviceKey(), grant.getSeq(), now);
        head.startCooldown(decoded.type().magic(), now.plus(policy.oppositionWindow()));
        head.setUpdatedAt(now);
        headRepository.save(head);
        challenges.burnUnspent(account.reference(), purposeOf(decoded.type()), now);
        notifications.cancelled(account.userId(), decoded.type().name(), decoded.label());
        log.info("Authority transition {} at seq {} was opposed and its device revoked", decoded.type(),
                grant.getSeq());
    }

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

    /** Needs no step-up: offering a public key grants nothing until an active device signs a grant over it. */
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

    @Transactional
    public Submitted grantDevice(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.GRANT, AuthorityRecordType.DEVICE_GRANT, recordB64, signatureB64,
                challengeB64);
    }

    @Transactional
    public Submitted revokeDevice(String userId, Optional<String> clientId, String sessionHash, String recordB64,
            String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.REVOKE, AuthorityRecordType.DEVICE_REVOKE, recordB64,
                signatureB64, challengeB64);
    }

    @Transactional
    public Submitted recoverAuthority(String userId, Optional<String> clientId, String sessionHash,
            String recordB64, String signatureB64, String challengeB64) {
        policy.requireEnabled();
        policy.requireNativeSession(clientId);
        return submit(userId, sessionHash, Purpose.RECOVER, AuthorityRecordType.AUTHORITY_RECOVERY, recordB64,
                signatureB64, challengeB64);
    }

    private Submitted submit(String userId, String sessionHash, Purpose purpose, AuthorityRecordType expected,
            String recordB64, String signatureB64, String challengeB64) {
        Resolved account = accounts.require(userId);
        AuthorityRecord record = decodeSubmitted(recordB64, expected);

        // The account comes from the session; the reference in the request is only compared against it.
        accounts.requireMatches(account, record.accountReference());

        Instant now = clock.instant();
        // Burned before verification, so a refused record cannot be retried against the same challenge.
        AuthorityChallengeService.Spent spent =
                challenges.spend(account.reference(), sessionHash, purpose, challengeB64, now);

        // Checked again here: a recovery can complete between minting the challenge and submitting the record.
        if (spent.factor() != null) {
            policy.enforceFreshFactorHold(spent.factorCreatedAt());
        }
        policy.enforceRecoveryOutsideHold(userId);

        byte[] signature = decode(signatureB64, "bad_signature_encoding");
        if (!AuthorityProofs.verifyRecord(record, spent.challenge(), signature)) {
            throw new InvalidAuthorityRecordException("invalid_signature",
                    "the signature does not verify over magic, challenge and canonical bytes");
        }

        boolean immediate = policy.takesEffectImmediately(record);
        if (policy.mustBeAnnounced(record)) {
            policy.requireReachableOutOfBand(notifications.reachesOutOfBandChannel(userId));
        }

        AuthorityChainHead head = lockHead(account, now);
        List<AuthorityDevice> devices = deviceRepository.findByAccount(account.reference());

        policy.requirePermittedAt(record.type(), record.authorization(),
                new ChainContext(head.isChainEmpty(), account.genesisRooted(),
                        holdsCommittedAuthority(account, head), countUnquarantinedActive(devices, now)));

        if (record.seq() != head.nextSeq()
                || !record.prevHashHex().equalsIgnoreCase(head.nextPrevHash())) {
            throw new AuthorityTransitionException(HttpStatus.CONFLICT, "authority_head_conflict",
                    "The chain moved. Read it again and decide with the other record in view.");
        }

        // Read both before this request writes the head: the cancellation below sets the cooldown.
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
            cancelled = requirePending(account, head);
            cancelledRecord = decodeStored(cancelled);
            cancelPending(account, head, cancelled, cancelledRecord, now, "outranked by a later record");
        }

        requireSignerMayAct(account, record, devices, now);

        if (cancelledRecord != null) {
            // Charged only once acceptance is certain: the backoff lives in Redis and would survive a rollback.
            chargeCancellation(account, cancelledRecord, now);
        }

        Instant effectiveAt = immediate ? now : now.plus(policy.windowFor(record.type(), record.authorization()));
        // From the record, not the head: the cancellation above may have rolled the head back.
        long seq = record.seq();

        recordRepository.save(AuthorityChainRecord.of(account.reference(), seq, record.type().magic(), recordB64,
                record.hashHex(), record.prevHashHex(), signatureB64, encode(record.verifyingKey()),
                immediate ? AuthorityChainRecord.State.ACTIVE : AuthorityChainRecord.State.PENDING,
                effectiveAt, now));
        head.place(record.hashHex(), seq, record.type().magic(), rank, immediate ? null : effectiveAt, now);
        headRepository.save(head);

        if (immediate) {
            applyEffect(account, record, seq, now, false);
            publisher.publishSettledHead(account, head, now);
            notifications.completed(userId, record.type().name(), record.label());
        } else {
            notifications.pending(userId, record.type().name(), record.label(), effectiveAt);
        }
        auditLogger.authorityTransitionAccepted(userId, record.type().name(), seq, !immediate, effectiveAt);
        log.info("Authority transition {} accepted at seq {} (pending={})", record.type(), seq, !immediate);

        return new Submitted(seq, !immediate, effectiveAt.getEpochSecond(), record.hashHex());
    }

    private void requireSignerMayAct(Resolved account, AuthorityRecord record, List<AuthorityDevice> devices,
            Instant now) {
        switch (record.type()) {
            case ADOPT_ROOT -> {
            }
            case DEVICE_GRANT, DEVICE_REVOKE -> {
                AuthorityDevice signer = requireKnownDevice(devices, record.verifyingKey());
                policy.requireNotQuarantined(signer.isQuarantined(now));
                if (record.type() == AuthorityRecordType.DEVICE_GRANT) {
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
        return Optional.ofNullable(account.committedRecoveryKeyB64());
    }

    private boolean holdsCommittedAuthority(Resolved account, AuthorityChainHead head) {
        if (account.genesisRooted()) {
            return true;
        }
        return recordRepository.findByAccountAndState(account.reference(), AuthorityChainRecord.State.ACTIVE)
                .stream()
                .anyMatch(row -> AuthorityRecordType.ADOPT_ROOT.magic().equals(row.getMagic()));
    }

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
            // From the stored record: once a record is placed, the head holds that record's hash instead.
            AuthorityChainRecord pendingRecord = requirePending(account, head);
            pending = new PendingView(typeOfMagic(head.getPendingMagic()).name(), head.getPendingSeq(),
                    head.getPendingEffectiveAt().getEpochSecond(), head.getPendingHash(),
                    pendingRecord.getPrevHash());
        }

        return new AuthorityStateResponse(account.reference(), account.className(),
                chainState(account, head, devices, now).wire(), head.getHeadSeq(), head.getHeadHash(), views,
                pending);
    }

    private AuthorityChainHead lockHead(Resolved account, Instant now) {
        AuthorityChainHead head = headRepository.findByAccountForUpdate(account.reference())
                .orElseGet(() -> {
                    AuthorityChainHead created = headRepository.saveAndFlush(
                            AuthorityChainHead.empty(account.reference(), now));
                    return headRepository.findByAccountForUpdate(created.getAccount()).orElse(created);
                });
        materialiseCommittedDevice(account, now);
        settle(account, head, now);
        publisher.publishSettledHead(account, head, now);
        return head;
    }

    /** A genesis-rooted account's first device key is committed by its id, not by a record. It is stored at seq 0. */
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

        notifications.completed(account.userId(), decoded.type().name(), decoded.label());
        log.info("Authority transition {} completed after its window", decoded.type());
    }

    private AuthorityChainRecord requirePending(Resolved account, AuthorityChainHead head) {
        return recordRepository.findByAccountAndSeq(account.reference(), head.getPendingSeq())
                .orElseThrow(() -> new IllegalStateException(
                        "the head reserves a slot with no record behind it"));
    }

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

        // A cancelled record gives its slot back, so a retry lands at the same position.
        head.rollBackTo(pending.getPrevHash(), pending.getSeq());
        head.clearPending();
        head.startCooldown(decoded.type().magic(), now.plus(policy.oppositionWindow()));
        head.setUpdatedAt(now);
        headRepository.save(head);

        challenges.burnUnspent(account.reference(), purposeOf(decoded.type()), now);
        notifications.cancelled(account.userId(), decoded.type().name(), decoded.label());
        log.info("Authority transition {} cancelled: {}", decoded.type(), reason);
    }

    private void chargeCancellation(Resolved account, AuthorityRecord cancelled, Instant now) {
        backoff.recordCancellation(account.reference(), encode(cancelled.verifyingKey()), now);
    }

    private void applyEffect(Resolved account, AuthorityRecord record, long seq, Instant now, boolean settled) {
        switch (record.type()) {
            case ADOPT_ROOT -> deviceRepository.save(AuthorityDevice.granted(account.reference(),
                    encode(record.deviceKey()), record.label(), seq, null, AuthorityDevice.State.ACTIVE, now));
            case DEVICE_GRANT -> {
                deviceRepository.save(AuthorityDevice.granted(account.reference(), encode(record.deviceKey()),
                        record.label(), seq, policy.quarantineUntil(now), AuthorityDevice.State.QUARANTINED,
                        now));
                candidateRepository.findByAccountAndDeviceKeyB64(account.reference(), encode(record.deviceKey()))
                        .ifPresent(candidateRepository::delete);
            }
            case DEVICE_REVOKE -> revokeDeviceRow(account, record.deviceKey(), seq, now);
            case AUTHORITY_RECOVERY -> {
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
        // Reported as lost, but a recovery signed by the committed recovery key is still accepted.
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

    public record Submitted(long seq, boolean pending, long effectiveAtEpochSeconds, String recordHash) {
    }

    public record Candidate(String deviceKeyB64, String fingerprint, String label, long expiresAtEpochSeconds) {
    }
}
