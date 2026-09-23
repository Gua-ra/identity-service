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

    private final TestEd25519.Pair firstDevice = TestEd25519.generate();
    private final TestEd25519.Pair secondDevice = TestEd25519.generate();
    private final TestEd25519.Pair recoveryKey = TestEd25519.generate();

    private IdentityServiceProperties properties;
    private AuthorityPolicy policy;
    private AuthorityChallengeService challenges;
    private AccountAuthorityService service;
    private AuthorityAccounts accounts;
    private MutableClock clock;
    private StubChannel channel;
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
        challenges = new AuthorityChallengeService(challengeRepository, policy);
        channel = new StubChannel();
        service = new AccountAuthorityService(policy, accounts, challenges, null, headRepository, recordRepository,
                deviceRepository, new AuthorityNotifications(List.of(channel)), new NoBackoff(policy),
                new LoggingSecurityAuditLogger(), clock);

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
    void theCancelledRecordKeepsItsSlotSoTheChainHasNoGapAndNoBranch() {
        adopt();
        service.oppose(USER, head().getPendingHash(), null, null, null, "127.0.0.1");

        assertThat(head().getHeadSeq()).isEqualTo(1L);
        assertThat(head().nextSeq()).isEqualTo(2L);
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
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        return service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge);
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
        }

        @Override
        public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
        }

        @Override
        public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
        }
    }

    /** No Redis here, and the doubling backoff has its own unit test. */
    private static final class NoBackoff extends AuthorityBackoff {

        private NoBackoff(AuthorityPolicy policy) {
            super(null, policy);
        }

        @Override
        public Optional<Instant> until(String account, String authorizingKeyB64) {
            return Optional.empty();
        }

        @Override
        public Instant recordCancellation(String account, String authorizingKeyB64, Instant now) {
            return now;
        }
    }
}
