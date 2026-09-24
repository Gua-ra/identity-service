// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityDevice;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityNotificationRegistrationRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.EndOtherSessionsService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinPolicy;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;

/**
 * The property ADM-009 gate 2 is actually about, driven rather than asserted about a mock: a security
 * notification registration survives a completed account recovery, and the passkeys do not.
 *
 * <p><b>Why the negative control is in the same test.</b> A test that only asserts the row is still there
 * passes just as well when the recovery did nothing at all, which is the failure mode worth catching: a
 * misconfigured fixture, a status that never reached READY, a swallowed refusal. So the same test asserts
 * that every passkey is gone and that the PIN the recovery chose is now the account's PIN. The row surviving
 * only means something beside a recovery that demonstrably happened.
 *
 * <p>The recovery is the shipped {@link AccountRecoveryService} over the real
 * {@link UserSecurityService} and the real {@link PasskeyService}, against real repositories. Two things are
 * mocked and neither is the subject: {@link EndOtherSessionsService}, because the session sign-out it records
 * is performed by another service against another database and is exactly the reason a pusher could not carry
 * this channel, and the directory and phone collaborators the user service takes, which this path never calls.
 *
 * <p>The removal tiers are then exercised against the state the recovery left behind, which is the only state
 * they are interesting in: the caller holds a PIN minted seconds ago and nothing else.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
class AuthorityNotificationSurvivesRecoveryTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "b".repeat(64);
    private static final String OWN_INSTALL = "install-phone";
    private static final String OTHER_INSTALL = "install-tablet";
    /** The hold every authority transition and every tier-2 removal is weighed against. */
    private static final Duration HOLD = Duration.ofDays(7);

    @Autowired
    private IdentityUserRepository userRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyRepository;

    @Autowired
    private AuthorityNotificationRegistrationRepository registrationRepository;

    @Autowired
    private AuthorityDeviceRepository deviceRepository;

    @Autowired
    private AuthorityChallengeRepository challengeRepository;

    @Autowired
    private AccountGenesisRepository genesisRepository;

    private final TestEd25519.Pair device = TestEd25519.generate();

    private IdentityServiceProperties properties;
    private UserSecurityService userSecurityService;
    private PasskeyService passkeyService;
    private AccountRecoveryService recovery;
    private AuthorityNotificationRegistry registry;
    private AuthorityPolicy policy;
    private AuthorityChallengeService challenges;
    private AuthorityAccounts accounts;
    private StubClock clock;
    private String accountReference;

    @BeforeEach
    void setUp() {
        clock = new StubClock(Instant.now());
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().getNotifications().setEnabled(true);
        // The hold the fresh-factor rules are measured against, and the two recovery waits shortened to a
        // second so the shipped path can be driven end to end. Not to zero: the episode's own life is derived
        // from the wait, so a zero wait makes every episode dead on arrival and the recovery would refuse for
        // a reason that has nothing to do with what is being tested.
        properties.getSecurity().setPinResetCooldown(HOLD);
        properties.getSecurity().setAccountRecoveryDormancy(Duration.ofSeconds(1));
        properties.getSecurity().setAccountRecoveryWait(Duration.ofSeconds(1));

        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        LoggingSecurityAuditLogger audit = new LoggingSecurityAuditLogger();
        userSecurityService = new UserSecurityService(userRepository, encoder, properties,
                mock(DirectoryService.class), mock(PhoneNumberHasher.class), mock(OtpService.class), audit,
                mock(StringRedisTemplate.class), new PinPolicy());
        passkeyService = new PasskeyService(passkeyRepository, new LoginFlowProperties(),
                mock(StringRedisTemplate.class), new ObjectMapper());
        recovery = new AccountRecoveryService(userSecurityService, passkeyService,
                mock(EndOtherSessionsService.class), properties, audit, clock);

        policy = new AuthorityPolicy(properties, userSecurityService);
        accounts = new AuthorityAccounts(genesisRepository);
        challenges = new AuthorityChallengeService(challengeRepository, policy);
        // The web-sheet step-up is a real service over a mocked repository: this test never opens a sheet, so
        // it has nothing to consume, and the native path is the one under test here.
        AuthorityStepUpService stepUps = new AuthorityStepUpService(passkeyService, userSecurityService, policy,
                new AuthorityWebStepUpService(mock(AuthorityWebStepUpRepository.class), policy, clock), audit);
        registry = new AuthorityNotificationRegistry(registrationRepository, deviceRepository, accounts, challenges,
                stepUps, policy);

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), clock.instant()));
        accountReference = genesis.accountId().value();

        userSecurityService.setInitialPin(USER, "481937");
        givenTwoPasskeys();
    }

    // --- The property, and the control that keeps it from being vacuous ------

    @Test
    void theRegistrationSurvivesACompletedRecoveryAndThePasskeysDoNot() {
        registerOwnInstall();
        assertThat(registrationRepository.findByUserId(USER)).hasSize(1);
        String tokenFingerprint = registrationRepository.findByUserId(USER).getFirst().getTokenFingerprint();

        int removedPasskeys = driveARecovery("902184");

        // The control. A recovery that did nothing would leave these standing, and the survival below would
        // then be a statement about an inert fixture rather than about this table.
        assertThat(removedPasskeys).isEqualTo(2);
        assertThat(passkeyRepository.findByUserId(USER)).isEmpty();
        IdentityUser after = userRepository.findByUserId(USER).orElseThrow();
        assertThat(after.getRecoveryCompletedAt()).isNotNull();
        assertThat(after.getPinResetRequestedAt()).isNull();

        // The property.
        List<AuthorityNotificationRegistration> rows = registrationRepository.findByUserId(USER);
        assertThat(rows).hasSize(1);
        assertThat(rows.getFirst().getInstallationId()).isEqualTo(OWN_INSTALL);
        assertThat(rows.getFirst().getTokenFingerprint()).isEqualTo(tokenFingerprint);
        assertThat(rows.getFirst().isLive(clock.instant(), policy.registrationLife(),
                policy.registrationFailureLimit())).isTrue();
    }

    @Test
    void theChannelStillReachesTheHolderAfterTheRecovery() {
        registerOwnInstall();
        driveARecovery("902184");

        // The same question the chain asks before it starts a window, answered through the notifier rather
        // than by reading the table: gate 2 is a claim about reaching the holder, not about a row existing.
        AuthorityPushNotifier notifier = new AuthorityPushNotifier(registry,
                List.of(new ConfiguredTransport()), policy, clock);
        assertThat(notifier.isOutOfBand()).isTrue();
        assertThat(notifier.reachesOutOfBand(USER)).isTrue();
    }

    @Test
    void aTransitionIsStillRefusedWhileTheRecoveryIsInsideTheHold() {
        registerOwnInstall();
        driveARecovery("902184");

        // The other half of decision 9 rule 3, and the reason the surviving channel is worth having: the
        // attacker cannot use the window either, because the stamp the recovery just wrote refuses them.
        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> policy.enforceRecoveryOutsideHold(USER), AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_recovery_too_recent");
    }

    // --- The three removal tiers, against the post-recovery state ------------

    @Test
    void theInstallItselfRemovesItsOwnRegistrationWithNoExtraFactor() {
        registerOwnInstall();

        registry.remove(USER, removal(OWN_INSTALL, null), OWN_INSTALL, SESSION, "127.0.0.1", clock.instant());

        // Conceded by ADM-009 decision 5 already: whoever holds that unlocked phone can do this, and it
        // reaches no other install.
        assertThat(registrationRepository.findByUserId(USER)).isEmpty();
    }

    @Test
    void aCallerWhoseOnlyFactorIsTheJustMintedPinCannotRemoveAnotherInstall() {
        registerOwnInstall();
        registerOtherInstall();
        String attackerPin = "902184";
        driveARecovery(attackerPin);

        // The whole attack, in one call: the PIN was chosen seconds ago by whoever completed the recovery, and
        // it is the only factor they hold. The hold is measured on the credential itself, so it is refused.
        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.remove(USER, removal(OWN_INSTALL, attackerPin), OTHER_INSTALL, SESSION,
                        "127.0.0.1", clock.instant()),
                AuthorityTransitionException.class);

        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_factor_too_fresh");
        assertThat(registrationRepository.findByUserId(USER)).hasSize(2);
    }

    @Test
    void removingAnotherInstallNeedsADeviceSignatureWhenTheRowCarriesOne() {
        givenAnActiveAuthorityDevice();
        registerOwnInstallBoundToTheDevice();
        registerOtherInstall();
        agePinPastTheHold();

        // Tier 2 with a factor past the hold, and nothing else: refused, because the row names a device key.
        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.remove(USER, removal(OWN_INSTALL, "481937"), OTHER_INSTALL, SESSION,
                        "127.0.0.1", clock.instant()),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_challenge_invalid");
        assertThat(registrationRepository.findByUserId(USER)).hasSize(2);

        // The same call with the signature the row's own device key produces.
        agePinPastTheHold();
        String challenge = mintNotifyChallenge();
        String signature = signBinding(OWN_INSTALL, challenge);
        registry.remove(USER, removal(OWN_INSTALL, "481937", challenge, signature), OTHER_INSTALL, SESSION,
                "127.0.0.1", clock.instant());

        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OWN_INSTALL)).isEmpty();
        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OTHER_INSTALL)).isPresent();
    }

    // --- Fixtures -----------------------------------------------------------

    private void givenTwoPasskeys() {
        passkeyRepository.saveAndFlush(passkey("cred-one"));
        passkeyRepository.saveAndFlush(passkey("cred-two"));
    }

    private PasskeyCredential passkey(String credentialId) {
        PasskeyCredential credential = PasskeyCredential.builder()
                .userId(USER)
                .userHandle("handle")
                .credentialId(credentialId)
                .publicKeyCose("cose")
                .signatureCount(0)
                .backupEligible(false)
                .backupState(false)
                .build();
        credential.setCreatedAt(clock.instant());
        return credential;
    }

    private void givenAnActiveAuthorityDevice() {
        deviceRepository.saveAndFlush(AuthorityDevice.granted(accountReference,
                Base64.getUrlEncoder().withoutPadding().encodeToString(device.rawPublicKey()), "iPhone", 1L, null,
                AuthorityDevice.State.ACTIVE, clock.instant()));
    }

    private void registerOwnInstall() {
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                "apns-token-one", "global.gua", "iPhone", null, null, null), SESSION, clock.instant());
    }

    private void registerOtherInstall() {
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OTHER_INSTALL, "APNS",
                "apns-token-two", "global.gua", "iPad", null, null, null), SESSION, clock.instant());
    }

    private void registerOwnInstallBoundToTheDevice() {
        String challenge = mintNotifyChallenge();
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                "apns-token-one", "global.gua", "iPhone",
                Base64.getUrlEncoder().withoutPadding().encodeToString(device.rawPublicKey()), challenge,
                signBinding(OWN_INSTALL, challenge)), SESSION, clock.instant());
    }

    private String mintNotifyChallenge() {
        return challenges.mint(accountReference, SESSION, Purpose.NOTIFY, null, null, clock.instant()).challenge();
    }

    private String signBinding(String installationId, String challengeB64) {
        byte[] preimage = AuthorityProofs.notificationPreimage(accounts.require(USER).bytes(),
                AuthorityNotificationRegistry.sha256(installationId), device.rawPublicKey(),
                Base64.getUrlDecoder().decode(challengeB64));
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(TestEd25519.sign(device.privateKey(), preimage));
    }

    /**
     * Starts and completes a recovery through the shipped service, and returns how many passkeys it removed.
     *
     * <p>The dormancy and the wait are configured to zero rather than skipped, so start and complete both run
     * their real status rules; a fixture that wrote {@code pin_reset_requested_at} by hand would be testing
     * this test.
     */
    private int driveARecovery(String attackerChosenPin) {
        userRepository.findByUserId(USER).ifPresent(user -> {
            user.setLastLoginAt(clock.instant().minus(Duration.ofDays(60)));
            userRepository.saveAndFlush(user);
        });
        recovery.start(USER, "+55 11 ****-**89", "127.0.0.1");
        // Past the wait and still inside the episode's life, which is where a real caller completes one.
        clock.advance(Duration.ofSeconds(1));
        return recovery.complete(USER, attackerChosenPin);
    }

    /**
     * Puts the account's PIN outside the fresh-factor hold.
     *
     * <p>The hold is measured against the wall clock inside {@code UserSecurityService}, so the stamp is
     * backdated rather than the test clock advanced. What is being set up is an owner whose factor is
     * established, which is the only caller tier 2 is meant to admit.
     */
    private void agePinPastTheHold() {
        IdentityUser user = userRepository.findByUserId(USER).orElseThrow();
        user.setPinSetAt(Instant.now().minus(HOLD).minus(Duration.ofDays(1)));
        user.setRecoveryCompletedAt(null);
        userRepository.saveAndFlush(user);
    }

    private static AuthorityNotificationRegistry.Removal removal(String installationId, String pin) {
        return removal(installationId, pin, null, null);
    }

    private static AuthorityNotificationRegistry.Removal removal(String installationId, String pin,
            String challenge, String signature) {
        return new AuthorityNotificationRegistry.Removal(installationId, null, null, pin, challenge, signature);
    }

    /** A transport that reports itself configured, so the notifier can answer the gate-2 question. */
    private static final class ConfiguredTransport implements AuthorityPushTransport {

        @Override
        public Platform platform() {
            return Platform.APNS;
        }

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public Outcome send(String token, String appId, String title, String body) {
            return Outcome.DELIVERED;
        }
    }

    /** Walked forward by seconds, because the recovery's two waits are the only durations the test needs. */
    private static final class StubClock extends Clock {

        private Instant now;

        private StubClock(Instant now) {
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
}
