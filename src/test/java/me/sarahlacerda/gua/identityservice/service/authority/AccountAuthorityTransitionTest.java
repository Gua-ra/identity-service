// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordCodec;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecords;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The transitions against a real database engine, because the compare-and-set, the slot reservation and the
 * lazy settlement are all claims about what the rows say and a mocked repository cannot show them.
 *
 * <p>The schema comes from the entity mapping rather than from Flyway, for the reason
 * {@code AccountGenesisRepositoryTest} gives: the migrations are Postgres-only. That the mapping and V13 agree is
 * {@code SchemaParityTest}'s question, on Postgres.
 *
 * <p>The clock is mutable, so a window can be walked past without waiting 72 hours.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        // H2's own dialect, so the head lock is emitted as "FOR UPDATE" rather than Postgres's "FOR NO KEY
        // UPDATE", which H2 does not parse. The lock is therefore really taken here; that the Postgres form
        // of it behaves is what the Testcontainers concurrency classes answer, on the engine production uses.
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class AccountAuthorityTransitionTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final String NATIVE_CLIENT = "gua-ios";

    @Autowired
    private AccountGenesisRepository genesisRepository;

    @Autowired
    private AuthorityChainHeadRepository headRepository;

    @Autowired
    private AuthorityChainRecordRepository recordRepository;

    @Autowired
    private AuthorityDeviceRepository deviceRepository;

    @Autowired
    private AuthorityChallengeRepository challengeRepository;

    @Autowired
    private me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository candidateRepository;

    private final TestEd25519.Pair firstDevice = TestEd25519.generate();
    private final TestEd25519.Pair secondDevice = TestEd25519.generate();
    private final TestEd25519.Pair thirdDevice = TestEd25519.generate();
    private final TestEd25519.Pair recoveryKey = TestEd25519.generate();
    private final TestEd25519.Pair replacementRecoveryKey = TestEd25519.generate();

    private IdentityServiceProperties properties;
    private AuthorityPolicy policy;
    private AuthorityChallengeService challenges;
    private AuthorityStepUpService stepUps;
    private AccountAuthorityService service;
    private AuthorityAccounts accounts;
    private MutableClock clock;
    private StubChannel channel;
    private NoBackoff backoff;
    private byte[] reference;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-09-19T12:00:00Z"));
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().setProductionAdoption(true);
        properties.getAuthority().getNativeClientIds().add(NATIVE_CLIENT);

        // Mocked, and answering "nothing is held", because the two holds have their own unit tests and this
        // class is about what the chain rows say.
        UserSecurityService userSecurityService = org.mockito.Mockito.mock(UserSecurityService.class);
        policy = new AuthorityPolicy(properties, userSecurityService);
        accounts = new AuthorityAccounts(genesisRepository);
        challenges = new AuthorityChallengeService(challengeRepository, policy,
                new AuthorityChallengeBurn(challengeRepository));
        // Mocked, and never asked for anything the other classes cover: what this class needs from it is
        // whether an opposition was asked to present a factor at all.
        stepUps = org.mockito.Mockito.mock(AuthorityStepUpService.class);
        channel = new StubChannel();
        backoff = new NoBackoff(policy);
        service = new AccountAuthorityService(policy, accounts, challenges, stepUps, headRepository, recordRepository,
                deviceRepository, candidateRepository, new AuthorityNotifications(List.of(channel)),
                backoff, new LoggingSecurityAuditLogger(), clock);

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), clock.instant()));
        reference = genesis.accountId().rawBytes();
    }

    // --- Adoption -----------------------------------------------------------

    @Test
    void anAdoptionTakesSeqOneAndHoldsItForTheWholeWindow() {
        AccountAuthorityService.Submitted submitted = adopt();

        assertThat(submitted.seq()).isEqualTo(1);
        assertThat(submitted.pending()).isTrue();
        assertThat(submitted.effectiveAtEpochSeconds())
                .isEqualTo(clock.instant().plus(Duration.ofHours(72)).getEpochSecond());

        // The slot is reserved, so an immediate record cannot starve the delayed one.
        assertThat(head().getPendingSeq()).isEqualTo(1L);
        assertThat(head().getHeadSeq()).isEqualTo(1L);
        assertThat(head().getPendingRank()).isEqualTo((short) 1);
        // Nothing is authority yet.
        assertThat(deviceRepository.findByAccount(account())).isEmpty();
        assertThat(recordRepository.findByAccountAndSeq(account(), 1L).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.PENDING);
    }

    @Test
    void theAccountIdDoesNotChangeAndTheGenesisRowIsUntouched() {
        String before = genesisRepository.findByUserId(USER).orElseThrow().getAccountId();
        AccountGenesisRecord.Origin origin = genesisRepository.findByUserId(USER).orElseThrow().getOrigin();

        adopt();

        // Decision 1: adoption leaves the id, the row and its origin exactly as they are. An adopted account
        // holds authority its id does not commit, and a verifier reads the chain.
        AccountGenesisRecord after = genesisRepository.findByUserId(USER).orElseThrow();
        assertThat(after.getAccountId()).isEqualTo(before);
        assertThat(after.getOrigin()).isEqualTo(origin);
        assertThat(after.getAuthorityKeyB64()).isNull();
    }

    @Test
    void theAdoptionCompletesOnTheFirstLookAfterItsWindow() {
        adopt();

        clock.advance(Duration.ofHours(73));
        service.state(USER);

        assertThat(head().hasPending()).isFalse();
        assertThat(recordRepository.findByAccountAndSeq(account(), 1L).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.ACTIVE);
        assertThat(deviceRepository.findByAccount(account()))
                .singleElement()
                .satisfies(device -> {
                    assertThat(device.getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
                    assertThat(device.getLabel()).isEqualTo("iPhone");
                    assertThat(device.getGrantedSeq()).isEqualTo(1L);
                });
    }

    @Test
    void anOppositionInsideTheWindowCancelsItAndLeavesNoAuthority() {
        adopt();

        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");

        assertThat(head().hasPending()).isFalse();
        assertThat(recordRepository.findByAccountAndSeq(account(), 1L).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(deviceRepository.findByAccount(account())).isEmpty();
        // A cooldown of one window before another adoption may be opened.
        assertThat(head().getCooldownUntil()).isEqualTo(clock.instant().plus(Duration.ofHours(72)));
    }

    @Test
    void theCancelledRecordGivesItsSlotBackSoARetryLandsWhereBothClientsBuildIt() {
        adopt();
        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");

        // While the cancelled record kept its slot, headSeq stayed at 1 forever and AdoptRoot is permitted
        // only on an empty chain, so one free opposition, or one mistaken tap, denied the account its
        // authority permanently and reported it as AUTHORITY_LOST without it ever having been rooted.
        assertThat(head().getHeadSeq()).isEqualTo(0L);
        assertThat(head().nextSeq()).isEqualTo(1L);
        assertThat(head().getHeadHash())
                .isEqualTo(java.util.HexFormat.of().formatHex(AuthorityRecord.emptyPrevHash()));
        assertThat(service.state(USER).state()).isEqualTo("BOOTSTRAP");

        // And the retry is the record both clients already build: seq 1, prevHash all zero. Past the cooldown
        // one cancellation of this shape owes.
        clock.advance(Duration.ofHours(73));
        AccountAuthorityService.Submitted retry = adopt();

        assertThat(retry.seq()).isEqualTo(1L);
        assertThat(head().getPendingSeq()).isEqualTo(1L);
    }

    @Test
    void theRetryDoesNotBuyAnotherFreeObjection() {
        adopt();
        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");
        clock.advance(Duration.ofHours(73));
        adopt();

        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");

        // Decision 4's bound. The first objection is deliberately free, because at seq 1 the account holds no
        // authority to weigh; the second and later ones need a factor, so a stolen bearer session cannot veto
        // the account out of ever gaining authority while remaining account-equivalent itself. Counted from
        // the cancelled rows, the retry that replaced the row would have made this one free again.
        org.mockito.Mockito.verify(stepUps).accept(USER, policy.oppositionStepUp(), "AUTHORITY_OPPOSE", null,
                null, null, "127.0.0.1");
    }

    @Test
    void opposingWithNothingPendingIsAnswredTheSameWayAsOpposingSomething() {
        // Answered the same way whether one had just completed or none ever existed, so an opposition cannot be
        // used to ask what state the account is in.
        service.oppose(USER, "whatever", null, null, null, "127.0.0.1");
    }

    @Test
    void aSecondAdoptionIsRefusedOnceTheFirstIsInTheChain() {
        adopt();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        clock.advance(Duration.ofHours(73));

        // A second adoption authorized by login factors alone is precisely the seizure O9 rejected.
        assertThat(refusalFrom(this::adopt)).isEqualTo("authority_position_refused");
    }

    @Test
    void aRecordBuiltForAnotherAccountIsRefusedWhateverItsSignatureSays() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = AuthorityRecords.adoptRootFor(AuthorityRecords.REFERENCE, firstDevice.rawPublicKey(),
                recoveryKey.rawPublicKey(), "iPhone", 1, AuthorityRecord.emptyPrevHash());

        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true)))
                .isEqualTo("authority_account_mismatch");
    }

    @Test
    void anAdoptionWithoutTheRecoveryArtifactConfirmationIsRefusedBeforeAnythingIsWritten() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = adoptRootBytes();

        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, false)))
                .isEqualTo("authority_artifact_unconfirmed");
        assertThat(headRepository.findByAccount(account())).isEmpty();
    }

    @Test
    void aWebSessionCannotRootAnAccount() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = adoptRootBytes();

        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of("gua-web"), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true)))
                .isEqualTo("authority_native_session_required");
    }

    @Test
    void aRecordWhoseSignatureCoversAnotherChallengeIsRefusedAndBurnsTheChallenge() {
        String challenge = mint(Purpose.ADOPT);
        String otherChallenge = mint(Purpose.ADOPT);
        byte[] bytes = adoptRootBytes();

        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, otherChallenge, bytes), challenge, true)))
                .isEqualTo("invalid_authority_record");
        // Burned on refusal as well as on acceptance, so the captured body cannot be replayed with it.
        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true)))
                .isEqualTo("authority_challenge_invalid");
    }

    @Test
    void aRecordAtTheWrongPositionIsRefusedByTheCompareAndSet() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = AuthorityRecords.adoptRootFor(reference, firstDevice.rawPublicKey(),
                recoveryKey.rawPublicKey(), "iPhone", 2, AuthorityRecord.emptyPrevHash());

        assertThat(refusalFrom(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true)))
                .isEqualTo("authority_head_conflict");
    }

    // --- Devices ------------------------------------------------------------

    @Test
    void aGrantTakesEffectAtOnceAndQuarantinesTheDeviceItNames() {
        rootTheAccount();

        AccountAuthorityService.Submitted granted = grantSecondDevice();

        assertThat(granted.pending()).isFalse();
        assertThat(head().hasPending()).isFalse();
        // It only adds, so it reserves no slot; what waits is what the granted device may do.
        AuthorityDevice grantee = device(secondDevice.rawPublicKey());
        assertThat(grantee.getState()).isEqualTo(AuthorityDevice.State.QUARANTINED);
        assertThat(grantee.getQuarantineUntil()).isEqualTo(clock.instant().plus(Duration.ofHours(72)));
        assertThat(grantee.isUnquarantinedActive(clock.instant())).isFalse();
    }

    @Test
    void aQuarantinedDeviceCannotGrantOrRevokeAnything() {
        rootTheAccount();
        grantSecondDevice();

        String challenge = mint(Purpose.REVOKE);
        byte[] bytes = AuthorityRecords.revokeFor(reference, firstDevice.rawPublicKey(),
                secondDevice.rawPublicKey(), AuthorityRecord.REASON_COMPROMISED, head().nextSeq(),
                hexToBytes(head().getHeadHash()));

        assertThat(refusalFrom(() -> service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(secondDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, bytes), challenge)))
                .isEqualTo("authority_device_quarantined");
    }

    @Test
    void theBorrowedPhoneAttackCannotStripTheOwnerInTwoRecords() {
        rootTheAccount();
        grantSecondDevice();

        // The grant is immediate, so a borrowed unlocked phone gets a device at once. What it cannot do is
        // then self-revoke the owner's device out of the set, because its own grant is quarantined and a
        // quarantined device does not count toward the active device a revocation must leave behind.
        String challenge = mint(Purpose.REVOKE);
        byte[] bytes = AuthorityRecords.revokeFor(reference, firstDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), AuthorityRecord.REASON_LOST, head().nextSeq(),
                hexToBytes(head().getHeadHash()));

        assertThat(refusalFrom(() -> service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, bytes), challenge)))
                .isEqualTo("authority_last_device");
    }

    @Test
    void aGrantedDeviceBecomesAuthorityWhenItsQuarantinePasses() {
        rootTheAccount();
        grantSecondDevice();

        clock.advance(Duration.ofHours(73));
        service.state(USER);

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
    }

    @Test
    void revokingAnotherDeviceWaitsOutItsWindowAndRevokingItselfDoesNot() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        String challenge = mint(Purpose.REVOKE);
        byte[] other = AuthorityRecords.revokeFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), AuthorityRecord.REASON_LOST, head().nextSeq(),
                hexToBytes(head().getHeadHash()));
        AccountAuthorityService.Submitted pending = service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION,
                encode(other), sign(firstDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, other), challenge);

        assertThat(pending.pending()).isTrue();
        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);

        clock.advance(Duration.ofHours(73));
        service.state(USER);

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.REVOKED);
    }

    @Test
    void aSelfRevocationTakesEffectImmediatelyWhenAnotherDeviceRemains() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        String challenge = mint(Purpose.REVOKE);
        byte[] itself = AuthorityRecords.revokeFor(reference, secondDevice.rawPublicKey(),
                secondDevice.rawPublicKey(), AuthorityRecord.REASON_REPLACED, head().nextSeq(),
                hexToBytes(head().getHeadHash()));

        AccountAuthorityService.Submitted submitted = service.revokeDevice(USER, Optional.of(NATIVE_CLIENT),
                SESSION, encode(itself), sign(secondDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, itself),
                challenge);

        // A device removing its own authority reduces what an attacker holding it could do, and delaying that
        // helps nobody.
        assertThat(submitted.pending()).isFalse();
        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.REVOKED);
    }

    @Test
    void aGrantSignedByAKeyTheChainDoesNotKnowIsRefused() {
        rootTheAccount();
        String challenge = mint(Purpose.GRANT);
        TestEd25519.Pair stranger = TestEd25519.generate();
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(), stranger.rawPublicKey(),
                "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));

        // Holding a valid signature by a key nobody granted is not authority.
        assertThat(refusalFrom(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(stranger, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge)))
                .isEqualTo("authority_signer_refused");
    }

    @Test
    void objectingToAGrantOrARevocationFromASessionAloneIsRefused() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        String challenge = mint(Purpose.REVOKE);
        byte[] other = AuthorityRecords.revokeFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), AuthorityRecord.REASON_LOST, head().nextSeq(),
                hexToBytes(head().getHeadHash()));
        service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(other),
                sign(firstDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, other), challenge);

        // A bearer session cannot show it is an active device, and accepting it on the session would let a
        // stolen session veto the owner's own revocation of the thief's device.
        assertThat(refusalFrom(() -> service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1")))
                .isEqualTo("authority_opposition_device_required");
    }

    // --- The slot, the rank and the cooldown ---------------------------------

    @Test
    void theRankTwoRecordTakesAnOccupiedSlotRatherThanRefusingItself() {
        rootTheAccount();
        // L13.2's own pair: a recovery authorized through account recovery, outranked and cancelled by one
        // signed by the key the chain committed for exactly this. Same magic, so the cooldown the cancellation
        // writes is the cooldown the submission is then measured against.
        AccountAuthorityService.Submitted weaker = recoverThroughAccountRecovery();
        assertThat(weaker.pending()).isTrue();
        assertThat(head().getPendingRank()).isEqualTo((short) 0);

        AccountAuthorityService.Submitted stronger = recoverWithTheCommittedKey();

        // The cooldown used to be read five lines after this very request wrote it, so the escape hatch
        // refused itself with authority_cooldown and no higher-rank record could ever take an occupied slot.
        assertThat(stronger.pending()).isTrue();
        assertThat(head().getPendingRank()).isEqualTo((short) 2);
        assertThat(recordRepository.findByAccountAndSeq(account(), weaker.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(head().getCooldownMagic()).isEqualTo(AuthorityRecordType.AUTHORITY_RECOVERY.magic());
        // And ADM-002 D2's doubling is charged to the key set that opened the record that was cancelled, which
        // is the whole of what stops the cancel becoming the attack.
        assertThat(backoff.charged).containsExactly(encode(secondDevice.rawPublicKey()));
    }

    @Test
    void theRecoveryKeyPathAlsoOutranksAPendingRevocationRatherThanWaitingForIt() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        AccountAuthorityService.Submitted revocation = revokeSecondDevice();

        AccountAuthorityService.Submitted recovery = recoverWithTheCommittedKey();

        assertThat(recovery.pending()).isTrue();
        assertThat(head().getPendingRank()).isEqualTo((short) 2);
        assertThat(recordRepository.findByAccountAndSeq(account(), revocation.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
    }

    @Test
    void anActiveDeviceExtendsARecoveryWindowOnceAndNotTwice() {
        rootTheAccount();
        AccountAuthorityService.Submitted recovery = recoverWithTheCommittedKey();
        Instant firstEffectiveAt = head().getPendingEffectiveAt();

        // Decision 7: an active key an intruder may hold is not allowed to be the veto of a recovery signed by
        // the key the account committed for exactly this. It gets one extension and the notification.
        opposeAs(firstDevice, recovery.recordHash());
        Instant extended = head().getPendingEffectiveAt();
        assertThat(extended).isEqualTo(firstEffectiveAt.plus(Duration.ofHours(72)));
        assertThat(head().hasPending()).isTrue();
        assertThat(head().isPendingExtended()).isTrue();

        // And not a second one. Uncounted, the same objection postpones the recovery forever, which is the
        // outcome L13.3 refuses to hand a possibly stolen device.
        assertThat(refusalFrom(() -> opposeAs(firstDevice, recovery.recordHash())))
                .isEqualTo("authority_extension_spent");
        assertThat(head().getPendingEffectiveAt()).isEqualTo(extended);
    }

    @Test
    void aRefusedSubmissionChargesNobodysBackoff() {
        rootTheAccount();
        AccountAuthorityService.Submitted weaker = recoverThroughAccountRecovery();

        // Rank 2 by its authorization byte, signed by a key the account never committed for that purpose. It
        // outranks the pending record, so the cancellation runs, and then the submission is refused on its own
        // merits. The backoff counter lives in Redis and commits whatever this transaction does, so a charge
        // taken here would stand: four passes reached the cap and the victim's own device key could not
        // initiate anything for days, which is the starvation the rank table exists to prevent.
        String challenge = mint(Purpose.RECOVER);
        byte[] bytes = AuthorityRecords.recoveryFor(reference, secondDevice.rawPublicKey(),
                replacementRecoveryKey.rawPublicKey(), "iPhone", AuthorityRecord.AUTHORIZATION_RECOVERY_KEY,
                thirdDevice.rawPublicKey(), head().nextSeq(), hexToBytes(head().getHeadHash()));

        assertThat(refusalFrom(() -> service.recoverAuthority(USER, Optional.of(NATIVE_CLIENT), SESSION,
                encode(bytes), sign(thirdDevice, AuthorityRecordType.AUTHORITY_RECOVERY, challenge, bytes),
                challenge))).isEqualTo("authority_signer_refused");
        assertThat(backoff.charged).isEmpty();
        assertThat(weaker.pending()).isTrue();
    }

    @Test
    void theCooldownAnObjectionWritesRefusesThatShapeAndLeavesTheOthersAlone() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        AccountAuthorityService.Submitted revocation = revokeSecondDevice();
        opposeAsSecondDevice(revocation.recordHash());

        // Same shape: refused for one window, which is the bound decision 4 states.
        assertThat(refusalFrom(this::revokeSecondDevice)).isEqualTo("authority_cooldown");

        // Another shape: untouched. An account-wide cooldown here was decision 3's rejected absolute freeze
        // reached from the other side, where an intruder cycling a revocation froze everything the owner
        // could do, one window at a time, by being objected to.
        service.registerCandidate(USER, encode(thirdDevice.rawPublicKey()), "iPad");
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, thirdDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        AccountAuthorityService.Submitted grant = service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION,
                encode(bytes), sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge);

        assertThat(grant.pending()).isFalse();
        assertThat(device(thirdDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.QUARANTINED);
    }

    @Test
    void theReadEndpointReportsTheChainTheDevicesAndThePendingStep() {
        rootTheAccount();
        grantSecondDevice();

        AuthorityAccounts.AuthorityStateResponse state = service.state(USER);

        assertThat(state.accountId()).isEqualTo(account());
        assertThat(state.accountClass()).isEqualTo("BOOTSTRAP");
        assertThat(state.state()).isEqualTo("ROOTED");
        assertThat(state.headSeq()).isEqualTo(2L);
        assertThat(state.devices()).hasSize(2);
        assertThat(state.pending()).isNull();
    }

    @Test
    void theReportedStateNamesTheWindowThatIsRunning() {
        adopt();

        AuthorityAccounts.AuthorityStateResponse state = service.state(USER);

        assertThat(state.state()).isEqualTo("ADOPTION_PENDING");
        assertThat(state.pending()).isNotNull();
        assertThat(state.pending().type()).isEqualTo("ADOPT_ROOT");
        assertThat(state.pending().seq()).isEqualTo(1L);
    }

    @Test
    void anAdoptionIsRefusedWhileNothingCanTellTheAccountHolderItIsRunning() {
        // Gate 2, asked about this account rather than about the deployment. A window whose holder is never
        // told is a delay and not a control, so the transition is refused rather than run in the dark.
        channel.reaches = false;

        assertThat(refusalFrom(this::adopt)).isEqualTo("authority_no_notification_channel");
        assertThat(recordRepository.findByAccountOrderBySeqAsc(account())).isEmpty();
    }

    // --- The grant, and the objection decision 5 gives it --------------------

    @Test
    void objectingToAGrantRevokesTheGrantedDeviceAtOnce() {
        rootTheAccount();
        AccountAuthorityService.Submitted grant = grantSecondDevice();
        channel.sent.clear();

        // Decision 5: a grant is opposable by any active device other than the one it names, and opposing it
        // revokes the granted device immediately. A grant holds no slot, so both opposition paths used to
        // return early on "nothing is pending" and this clause was unreachable from any caller: a borrowed
        // unlocked phone's grant could only be answered with a revocation that waits out a full window.
        opposeTheGrantAs(firstDevice, grant.recordHash());

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.REVOKED);
        assertThat(channel.sent).containsExactly("CANCELLED DEVICE_GRANT " + USER);
        // The record itself stays in the chain: it was accepted, and every later prevHash covers it. What the
        // objection undoes is its effect.
        assertThat(recordRepository.findByAccountAndSeq(account(), grant.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.ACTIVE);
        // And another grant waits out one window, so objecting is not a way to cycle grants for free.
        assertThat(head().getCooldownMagic()).isEqualTo(AuthorityRecordType.DEVICE_GRANT.magic());
    }

    @Test
    void theGrantedDeviceCannotObjectToItsOwnGrant() {
        rootTheAccount();
        AccountAuthorityService.Submitted grant = grantSecondDevice();

        // Its own grant is inside its window, and a quarantined device may not sign an authority-sensitive
        // approval. Decision 5 names the same device again in the opposition rules, which is what would refuse
        // it if a quarantine ever stopped being what the window is.
        assertThat(refusalFrom(() -> opposeTheGrantAs(secondDevice, grant.recordHash())))
                .isEqualTo("authority_device_quarantined");
        assertThat(device(secondDevice.rawPublicKey()).getState())
                .isEqualTo(AuthorityDevice.State.QUARANTINED);
    }

    @Test
    void aGrantWhoseWindowHasPassedIsNoLongerOpposable() {
        rootTheAccount();
        AccountAuthorityService.Submitted grant = grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        // Answered the same way as an objection to something that never existed, so an opposition cannot be
        // used to ask what state the account is in. Removing it now is a revocation, with its own window.
        opposeTheGrantAs(firstDevice, grant.recordHash());

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
    }

    @Test
    void aGrantIsRefusedWhileNothingCanTellTheAccountHolderAboutIt() {
        rootTheAccount();
        service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad");
        channel.reaches = false;

        // A grant takes effect at once, so it has no window of its own to run in the dark; what it has is a
        // device set changed in silence, on the one transition that can happen on an account with no live
        // registration at all.
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        assertThat(refusalFrom(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge)))
                .isEqualTo("authority_no_notification_channel");
        assertThat(deviceRepository.findByAccountAndDeviceKeyB64(account(), encode(secondDevice.rawPublicKey())))
                .isEmpty();
    }

    // --- Who is told, and about what -----------------------------------------

    @Test
    void everyNotificationNamesTheAccountHolderAndNotNobody() {
        // The three raised outside the submitting request used to pass a null user id, and a notifier with no
        // holder to name sends nothing. So the completion of every window, the cancellation of every
        // transition and the extension decision 7 leaves an active device able to raise all reached nobody,
        // which makes a window a delay rather than a control.
        adopt();
        assertThat(channel.sent).containsExactly("PENDING ADOPT_ROOT " + USER);

        clock.advance(Duration.ofHours(73));
        service.state(USER);
        assertThat(channel.sent).contains("COMPLETED ADOPT_ROOT " + USER);

        AccountAuthorityService.Submitted revocation = revokeFirstDeviceWithTheSecondGranted();
        channel.sent.clear();
        opposeAs(firstDevice, revocation.recordHash());
        assertThat(channel.sent).containsExactly("CANCELLED DEVICE_REVOKE " + USER);

        AccountAuthorityService.Submitted recovery = recoverWithTheCommittedKey();
        channel.sent.clear();
        opposeAs(firstDevice, recovery.recordHash());
        assertThat(channel.sent).containsExactly("PENDING AUTHORITY_RECOVERY " + USER);
    }

    @Test
    void anotificationWithNoAccountHolderIsLoudRatherThanSilent() {
        AuthorityPushNotifier notifier = new AuthorityPushNotifier(
                org.mockito.Mockito.mock(AuthorityNotificationRegistry.class), List.of(), policy, clock);

        // Swallowed by AuthorityNotifications, so it still cannot roll back an accepted transition, but it is
        // in the log rather than nowhere.
        assertThatThrownBy(() -> notifier.notifyTransitionCompleted(null, "ADOPT_ROOT", "iPhone"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no account holder");
    }

    // --- Oppose, and the candidate step -------------------------------------

    @Test
    void anActiveDeviceCancelsAPendingRevocationWithASignedOppose() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        // The first device asks for the second to be removed; the second objects. A bearer session cannot
        // make that objection, because a stolen session would then veto the owner's own revocation.
        AccountAuthorityService.Submitted revocation = revokeSecondDevice();
        assertThat(revocation.pending()).isTrue();

        opposeAsSecondDevice(revocation.recordHash());

        assertThat(head().hasPending()).isFalse();
        assertThat(recordRepository.findByAccountAndSeq(account(), revocation.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
    }

    @Test
    void anOpposeTakesNoSlotSoTheChainDoesNotMoveOn() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        AccountAuthorityService.Submitted revocation = revokeSecondDevice();
        long seqWithThePendingRevocation = head().getHeadSeq();

        opposeAsSecondDevice(revocation.recordHash());

        // It cancels the record it names, or it is refused, and it is never appended: an objection that
        // consumed a position of its own would let one device cycle objections and walk the chain forward with
        // no transition ever happening. The chain therefore moves back to the position before the record that
        // was cancelled, which is the one the next transition is built against, and never forward.
        assertThat(head().getHeadSeq()).isEqualTo(seqWithThePendingRevocation - 1);
        assertThat(head().nextSeq()).isEqualTo(revocation.seq());
        assertThat(recordRepository.findByAccountOrderBySeqAsc(account()))
                .noneMatch(row -> AuthorityRecordType.OPPOSE.magic().equals(row.getMagic()));
    }

    @Test
    void anOpposeNamingSomethingElseIsRefused() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        revokeSecondDevice();

        String wrongHash = java.util.HexFormat.of().formatHex(new byte[]{ 9 }).repeat(64).substring(0, 64);

        assertThat(refusalFrom(() -> opposeAsSecondDevice(wrongHash)))
                .isEqualTo("authority_opposition_stale");
        assertThat(head().hasPending()).isTrue();
    }

    @Test
    void aDeviceTheChainDoesNotHoldCannotOppose() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        AccountAuthorityService.Submitted revocation = revokeSecondDevice();

        // A signature by a key nobody granted is not authority, whatever it says about itself. The key here
        // is a perfectly good Ed25519 key that this account's chain has never activated.
        assertThat(refusalFrom(() -> opposeAs(recoveryKey, revocation.recordHash())))
                .isEqualTo("authority_signer_refused");
        assertThat(head().hasPending()).isTrue();
    }

    @Test
    void aGrantOverAKeyNobodyOfferedIsRefused() {
        rootTheAccount();

        // No candidate step: the key arrived from somewhere the human fingerprint comparison never covered.
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));

        assertThat(refusalFrom(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge)))
                .isEqualTo("authority_unknown_candidate");
    }

    @Test
    void aCandidateExpiresAndIsThenNoLongerGrantable() {
        rootTheAccount();
        service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad");

        clock.advance(Duration.ofMinutes(11));

        assertThat(service.candidates(USER)).isEmpty();
        // Same refusal as a key nobody offered: telling the caller which would let a grant probe whether some
        // key was ever a candidate of this account.
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        assertThat(refusalFrom(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge)))
                .isEqualTo("authority_unknown_candidate");
    }

    @Test
    void aCandidateCarriesTheFingerprintBothDevicesComputeAndIsSpentByItsGrant() {
        rootTheAccount();

        AccountAuthorityService.Candidate candidate =
                service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad");

        // Derived from the key, so the other phone computes the same eight characters without asking anyone.
        assertThat(candidate.fingerprint())
                .isEqualTo(me.sarahlacerda.gua.identityservice.account.authority.AuthorityFingerprint
                        .of(secondDevice.rawPublicKey()));
        assertThat(candidate.fingerprint()).hasSize(8).matches("[ABCDEFGHJKLMNPQRSTUVWXYZ2346789]+");
        assertThat(service.candidates(USER)).hasSize(1);

        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge);

        // Spent. A candidate that outlived its grant would let a second grant be signed over the same key
        // without anybody comparing a fingerprint again.
        assertThat(service.candidates(USER)).isEmpty();
    }

    // --- Helpers ------------------------------------------------------------

    private AccountAuthorityService.Submitted adopt() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = adoptRootBytes();
        return service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true);
    }

    private void rootTheAccount() {
        adopt();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
    }

    private AccountAuthorityService.Submitted grantSecondDevice() {
        // A grant may only name a key a device of this account offered, so the candidate step of revision 4
        // comes first, exactly as it does on a real pair of phones.
        service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad");
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge);
    }

    private AccountAuthorityService.Submitted revokeSecondDevice() {
        String challenge = mint(Purpose.REVOKE);
        byte[] bytes = AuthorityRecords.revokeFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), AuthorityRecord.REASON_UNSPECIFIED, head().nextSeq(),
                hexToBytes(head().getHeadHash()));
        return service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, bytes), challenge);
    }

    /**
     * A pending revocation of the first device, signed by the second, so the first device may object to it:
     * the named device may veto its own removal where accepting it would leave the signer alone.
     */
    private AccountAuthorityService.Submitted revokeFirstDeviceWithTheSecondGranted() {
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        String challenge = mint(Purpose.REVOKE);
        byte[] bytes = AuthorityRecords.revokeFor(reference, firstDevice.rawPublicKey(),
                secondDevice.rawPublicKey(), AuthorityRecord.REASON_LOST, head().nextSeq(),
                hexToBytes(head().getHeadHash()));
        return service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(secondDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, bytes), challenge);
    }

    /** The rank-0 record: an {@code AuthorityRecovery} authorized through account recovery. */
    private AccountAuthorityService.Submitted recoverThroughAccountRecovery() {
        String challenge = mint(Purpose.RECOVER);
        byte[] bytes = AuthorityRecords.recoveryFor(reference, secondDevice.rawPublicKey(),
                replacementRecoveryKey.rawPublicKey(), "iPad", AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY,
                new byte[AuthorityRecord.KEY_LENGTH], head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.recoverAuthority(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(secondDevice, AuthorityRecordType.AUTHORITY_RECOVERY, challenge, bytes), challenge);
    }

    /**
     * The rank-2 record: an {@code AuthorityRecovery} signed by the key the chain committed for exactly this,
     * which no pending record and no device may block.
     */
    private AccountAuthorityService.Submitted recoverWithTheCommittedKey() {
        String challenge = mint(Purpose.RECOVER);
        byte[] bytes = AuthorityRecords.recoveryFor(reference, thirdDevice.rawPublicKey(),
                replacementRecoveryKey.rawPublicKey(), "iPhone", AuthorityRecord.AUTHORIZATION_RECOVERY_KEY,
                recoveryKey.rawPublicKey(), head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.recoverAuthority(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(recoveryKey, AuthorityRecordType.AUTHORITY_RECOVERY, challenge, bytes), challenge);
    }

    /**
     * An Oppose stands at the same position as the record it cancels, because it takes no slot: its seq and
     * prevHash are the pending record's own.
     */
    private void opposeAsSecondDevice(String opposedRecordHash) {
        opposeAs(secondDevice, opposedRecordHash);
    }

    /**
     * An Oppose naming a grant, which holds no pending slot: its seq and prevHash are the grant record's own,
     * exactly as they are the pending record's own in the other case.
     */
    private void opposeTheGrantAs(TestEd25519.Pair signer, String grantRecordHash) {
        String challenge = mint(Purpose.OPPOSE);
        AuthorityChainRecord grant = recordRepository.findByAccountAndRecordHash(account(), grantRecordHash)
                .orElseThrow();
        byte[] bytes = AuthorityRecords.opposeFor(reference, hexToBytes(grantRecordHash), signer.rawPublicKey(),
                grant.getSeq(), hexToBytes(grant.getPrevHash()));
        service.opposeWithRecord(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(signer, AuthorityRecordType.OPPOSE, challenge, bytes), challenge);
    }

    private void opposeAs(TestEd25519.Pair signer, String opposedRecordHash) {
        String challenge = mint(Purpose.OPPOSE);
        AuthorityChainRecord pending = recordRepository.findByAccountAndSeq(account(), head().getPendingSeq())
                .orElseThrow();
        byte[] bytes = AuthorityRecords.opposeFor(reference, hexToBytes(opposedRecordHash),
                signer.rawPublicKey(), pending.getSeq(), hexToBytes(pending.getPrevHash()));
        service.opposeWithRecord(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(signer, AuthorityRecordType.OPPOSE, challenge, bytes), challenge);
    }

    private byte[] adoptRootBytes() {
        return AuthorityRecords.adoptRootFor(reference, firstDevice.rawPublicKey(), recoveryKey.rawPublicKey(),
                "iPhone", 1, AuthorityRecord.emptyPrevHash());
    }

    private String mint(Purpose purpose) {
        return challenges.mint(account(), SESSION, purpose, AuthFactor.PASSKEY,
                clock.instant().minus(Duration.ofDays(30)), clock.instant()).challenge();
    }

    private String account() {
        return genesisRepository.findByUserId(USER).orElseThrow().getAccountId();
    }

    private me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead head() {
        return headRepository.findByAccount(account()).orElseThrow();
    }

    private AuthorityDevice device(byte[] key) {
        return deviceRepository.findByAccountAndDeviceKeyB64(account(), encode(key)).orElseThrow();
    }

    private static String sign(TestEd25519.Pair pair, AuthorityRecordType type, String challengeB64, byte[] bytes) {
        byte[] challenge = Base64.getUrlDecoder().decode(challengeB64);
        return encode(TestEd25519.sign(pair.privateKey(),
                AuthorityProofs.recordPreimage(type, challenge, bytes)));
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] hexToBytes(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    private static String refusalFrom(Runnable action) {
        RuntimeException refusal = catchThrowableOfType(action::run, RuntimeException.class);
        assertThat(refusal).as("expected a refusal").isNotNull();
        if (refusal instanceof AuthorityTransitionException transition) {
            return transition.getCode();
        }
        if (refusal instanceof me.sarahlacerda.gua.identityservice.account.authority
                .InvalidAuthorityRecordException) {
            return "invalid_authority_record";
        }
        throw new AssertionError("unexpected refusal", refusal);
    }

    /** A clock a test can walk forward, so a 72-hour window does not need 72 hours. */
    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /**
     * A channel that says it reaches the holder, because every windowed transition now refuses when nothing
     * does (ADM-009 gate 2). The transport and the registration table have their own tests; what this class is
     * about is what the chain rows say.
     */
    private static final class StubChannel implements AuthorityNotifier {

        private boolean reaches = true;
        private final List<String> sent = new java.util.ArrayList<>();

        @Override
        public boolean isOutOfBand() {
            return true;
        }

        @Override
        public boolean reachesOutOfBand(String userId) {
            return reaches;
        }

        @Override
        public void notifyTransitionPending(String userId, String transition, String deviceLabel,
                Instant effectiveAt) {
            sent.add("PENDING " + transition + " " + userId);
        }

        @Override
        public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
            sent.add("CANCELLED " + transition + " " + userId);
        }

        @Override
        public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
            sent.add("COMPLETED " + transition + " " + userId);
        }
    }

    /**
     * No Redis here, and the doubling backoff has its own unit test. What this one records is <em>who</em> was
     * charged and whether anybody was, because the real counter commits outside this transaction and a charge
     * made before a later refusal is not undone by it.
     */
    private static final class NoBackoff extends AuthorityBackoff {

        private final List<String> charged = new java.util.ArrayList<>();

        private NoBackoff(AuthorityPolicy policy) {
            super(null, policy);
        }

        @Override
        public Optional<Instant> until(String account, String authorizingKeyB64) {
            return Optional.empty();
        }

        @Override
        public Instant recordCancellation(String account, String authorizingKeyB64, Instant now) {
            charged.add(authorizingKeyB64);
            return now;
        }
    }
}
