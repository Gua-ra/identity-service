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

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        // H2 does not parse Postgres's FOR NO KEY UPDATE; under its own dialect the head lock is emitted as FOR UPDATE.
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
    private me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger auditLogger;
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
        properties.getAuthority().setAdoptionPermitted(true);
        properties.getAuthority().getNativeClientIds().add(NATIVE_CLIENT);

        UserSecurityService userSecurityService = org.mockito.Mockito.mock(UserSecurityService.class);
        policy = new AuthorityPolicy(properties, userSecurityService);
        accounts = new AuthorityAccounts(genesisRepository);
        challenges = new AuthorityChallengeService(challengeRepository, policy,
                new AuthorityChallengeBurn(challengeRepository));
        stepUps = org.mockito.Mockito.mock(AuthorityStepUpService.class);
        auditLogger = org.mockito.Mockito.spy(new LoggingSecurityAuditLogger());
        channel = new StubChannel();
        backoff = new NoBackoff(policy);
        service = new AccountAuthorityService(policy, accounts, challenges, stepUps, headRepository, recordRepository,
                deviceRepository, candidateRepository, new AuthorityNotifications(List.of(channel)),
                backoff, AuthorityHeadPublisherFixtures.off(properties), auditLogger,
                clock);

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), clock.instant()));
        reference = genesis.accountId().rawBytes();
    }

    @Test
    void anAdoptionTakesSeqOneAndHoldsItForTheWholeWindow() {
        AccountAuthorityService.Submitted submitted = adopt();

        assertThat(submitted.seq()).isEqualTo(1);
        assertThat(submitted.pending()).isTrue();
        assertThat(submitted.effectiveAtEpochSeconds())
                .isEqualTo(clock.instant().plus(Duration.ofHours(72)).getEpochSecond());

        assertThat(head().getPendingSeq()).isEqualTo(1L);
        assertThat(head().getHeadSeq()).isEqualTo(1L);
        assertThat(head().getPendingRank()).isEqualTo((short) 1);
        assertThat(deviceRepository.findByAccount(account())).isEmpty();
        assertThat(recordRepository.findByAccountAndSeq(account(), 1L).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.PENDING);
    }

    @Test
    void theAccountIdDoesNotChangeAndTheGenesisRowIsUntouched() {
        String before = genesisRepository.findByUserId(USER).orElseThrow().getAccountId();
        AccountGenesisRecord.Origin origin = genesisRepository.findByUserId(USER).orElseThrow().getOrigin();

        adopt();

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
        assertThat(head().getCooldownUntil()).isEqualTo(clock.instant().plus(Duration.ofHours(72)));
    }

    @Test
    void theCancelledRecordGivesItsSlotBackSoARetryLandsWhereBothClientsBuildIt() {
        adopt();
        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");

        assertThat(head().getHeadSeq()).isEqualTo(0L);
        assertThat(head().nextSeq()).isEqualTo(1L);
        assertThat(head().getHeadHash())
                .isEqualTo(java.util.HexFormat.of().formatHex(AuthorityRecord.emptyPrevHash()));
        assertThat(service.state(USER).state()).isEqualTo("BOOTSTRAP");

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

        org.mockito.Mockito.verify(stepUps).accept(USER, policy.oppositionStepUp(), "AUTHORITY_OPPOSE", null,
                null, null, "127.0.0.1");
    }

    @Test
    void opposingWithNothingPendingIsAnswredTheSameWayAsOpposingSomething() {
        service.oppose(USER, "whatever", null, null, null, "127.0.0.1");
    }

    @Test
    void aSecondAdoptionIsRefusedOnceTheFirstIsInTheChain() {
        adopt();
        clock.advance(Duration.ofHours(73));
        service.state(USER);
        clock.advance(Duration.ofHours(73));

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

    @Test
    void aGrantTakesEffectAtOnceAndQuarantinesTheDeviceItNames() {
        rootTheAccount();

        AccountAuthorityService.Submitted granted = grantSecondDevice();

        assertThat(granted.pending()).isFalse();
        assertThat(head().hasPending()).isFalse();
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

        assertThat(refusalFrom(() -> service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1")))
                .isEqualTo("authority_opposition_device_required");
    }

    @Test
    void theRankTwoRecordTakesAnOccupiedSlotRatherThanRefusingItself() {
        rootTheAccount();
        AccountAuthorityService.Submitted weaker = recoverThroughAccountRecovery();
        assertThat(weaker.pending()).isTrue();
        assertThat(head().getPendingRank()).isEqualTo((short) 0);

        AccountAuthorityService.Submitted stronger = recoverWithTheCommittedKey();

        assertThat(stronger.pending()).isTrue();
        assertThat(head().getPendingRank()).isEqualTo((short) 2);
        assertThat(recordRepository.findByAccountAndSeq(account(), weaker.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(head().getCooldownMagic()).isEqualTo(AuthorityRecordType.AUTHORITY_RECOVERY.magic());
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

        opposeAs(firstDevice, recovery.recordHash());
        Instant extended = head().getPendingEffectiveAt();
        assertThat(extended).isEqualTo(firstEffectiveAt.plus(Duration.ofHours(72)));
        assertThat(head().hasPending()).isTrue();
        assertThat(head().isPendingExtended()).isTrue();

        assertThat(refusalFrom(() -> opposeAs(firstDevice, recovery.recordHash())))
                .isEqualTo("authority_extension_spent");
        assertThat(head().getPendingEffectiveAt()).isEqualTo(extended);
    }

    @Test
    void aRefusedSubmissionChargesNobodysBackoff() {
        rootTheAccount();
        AccountAuthorityService.Submitted weaker = recoverThroughAccountRecovery();

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

        assertThat(refusalFrom(this::revokeSecondDevice)).isEqualTo("authority_cooldown");

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
        channel.reaches = false;

        assertThat(refusalFrom(this::adopt)).isEqualTo("authority_no_notification_channel");
        assertThat(recordRepository.findByAccountOrderBySeqAsc(account())).isEmpty();
    }

    @Test
    void objectingToAGrantRevokesTheGrantedDeviceAtOnce() {
        rootTheAccount();
        AccountAuthorityService.Submitted grant = grantSecondDevice();
        channel.sent.clear();

        opposeTheGrantAs(firstDevice, grant.recordHash());

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.REVOKED);
        assertThat(channel.sent).containsExactly("CANCELLED DEVICE_GRANT " + USER);
        assertThat(recordRepository.findByAccountAndSeq(account(), grant.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.ACTIVE);
        assertThat(head().getCooldownMagic()).isEqualTo(AuthorityRecordType.DEVICE_GRANT.magic());
    }

    @Test
    void theGrantedDeviceCannotObjectToItsOwnGrant() {
        rootTheAccount();
        AccountAuthorityService.Submitted grant = grantSecondDevice();

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

        opposeTheGrantAs(firstDevice, grant.recordHash());

        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
    }

    @Test
    void aGrantIsRefusedWhileNothingCanTellTheAccountHolderAboutIt() {
        rootTheAccount();
        service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad");
        channel.reaches = false;

        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        assertThat(refusalFrom(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge)))
                .isEqualTo("authority_no_notification_channel");
        assertThat(deviceRepository.findByAccountAndDeviceKeyB64(account(), encode(secondDevice.rawPublicKey())))
                .isEmpty();
    }

    @Test
    void everyNotificationNamesTheAccountHolderAndNotNobody() {
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

        assertThatThrownBy(() -> notifier.notifyTransitionCompleted(null, "ADOPT_ROOT", "iPhone"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no account holder");
    }

    @Test
    void anActiveDeviceCancelsAPendingRevocationWithASignedOppose() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        AccountAuthorityService.Submitted revocation = revokeSecondDevice();
        assertThat(revocation.pending()).isTrue();

        opposeAsSecondDevice(revocation.recordHash());

        assertThat(head().hasPending()).isFalse();
        assertThat(recordRepository.findByAccountAndSeq(account(), revocation.seq()).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(device(secondDevice.rawPublicKey()).getState()).isEqualTo(AuthorityDevice.State.ACTIVE);
    }

    @Test
    void aSecondDeviceCanBuildItsObjectionFromTheReadEndpointAlone() {
        rootTheAccount();
        grantSecondDevice();
        clock.advance(Duration.ofHours(73));
        service.state(USER);

        AccountAuthorityService.Submitted revocation = revokeSecondDevice();

        AuthorityAccounts.AuthorityStateResponse state = service.state(USER);
        AuthorityAccounts.PendingView pending = state.pending();
        assertThat(pending).isNotNull();
        assertThat(pending.recordHash()).isEqualTo(revocation.recordHash());
        assertThat(pending.prevHash()).isNotNull();

        String challenge = mint(Purpose.OPPOSE);
        byte[] bytes = AuthorityRecords.opposeFor(reference, hexToBytes(pending.recordHash()),
                secondDevice.rawPublicKey(), pending.seq(), hexToBytes(pending.prevHash()));
        service.opposeWithRecord(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(secondDevice, AuthorityRecordType.OPPOSE, challenge, bytes), challenge);

        assertThat(head().hasPending()).isFalse();
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

        assertThat(refusalFrom(() -> opposeAs(recoveryKey, revocation.recordHash())))
                .isEqualTo("authority_signer_refused");
        assertThat(head().hasPending()).isTrue();
    }

    @Test
    void aGrantOverAKeyNobodyOfferedIsRefused() {
        rootTheAccount();

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

        assertThat(service.candidates(USER)).isEmpty();
    }

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

    private AccountAuthorityService.Submitted recoverThroughAccountRecovery() {
        String challenge = mint(Purpose.RECOVER);
        byte[] bytes = AuthorityRecords.recoveryFor(reference, secondDevice.rawPublicKey(),
                replacementRecoveryKey.rawPublicKey(), "iPad", AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY,
                new byte[AuthorityRecord.KEY_LENGTH], head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.recoverAuthority(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(secondDevice, AuthorityRecordType.AUTHORITY_RECOVERY, challenge, bytes), challenge);
    }

    private AccountAuthorityService.Submitted recoverWithTheCommittedKey() {
        String challenge = mint(Purpose.RECOVER);
        byte[] bytes = AuthorityRecords.recoveryFor(reference, thirdDevice.rawPublicKey(),
                replacementRecoveryKey.rawPublicKey(), "iPhone", AuthorityRecord.AUTHORIZATION_RECOVERY_KEY,
                recoveryKey.rawPublicKey(), head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.recoverAuthority(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(recoveryKey, AuthorityRecordType.AUTHORITY_RECOVERY, challenge, bytes), challenge);
    }

    private void opposeAsSecondDevice(String opposedRecordHash) {
        opposeAs(secondDevice, opposedRecordHash);
    }

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

    @Test
    void anAcceptedAdoptionIsAuditedAsAcceptedRatherThanAsAFailedStepUp() {
        AccountAuthorityService.Submitted submitted = adopt();

        org.mockito.Mockito.verify(auditLogger).authorityTransitionAccepted(
                org.mockito.ArgumentMatchers.eq(USER),
                org.mockito.ArgumentMatchers.eq("ADOPT_ROOT"),
                org.mockito.ArgumentMatchers.eq(submitted.seq()),
                org.mockito.ArgumentMatchers.eq(true),
                org.mockito.ArgumentMatchers.any());
        org.mockito.Mockito.verify(auditLogger, org.mockito.Mockito.never())
                .reauthFailed(org.mockito.ArgumentMatchers.any(),
                        org.mockito.ArgumentMatchers.contains("_ACCEPTED"),
                        org.mockito.ArgumentMatchers.any());
    }
}
