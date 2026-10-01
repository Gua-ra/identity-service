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
import me.sarahlacerda.gua.identityservice.service.security.PasskeyPrincipals;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinPolicy;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;

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
    private static final Duration HOLD = Duration.ofDays(7);
    private static final String TOKEN_ONE = "a1".repeat(32);
    private static final String TOKEN_TWO = "b2".repeat(32);
    private static final String ROTATED_TOKEN = "c3".repeat(32);
    private static final String ATTACKER_TOKEN = "d4".repeat(32);

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
        properties.getSecurity().setPinResetCooldown(HOLD);
        // Not zero: an episode's life is derived from the wait, so a zero wait makes every episode dead on arrival.
        properties.getSecurity().setAccountRecoveryDormancy(Duration.ofSeconds(1));
        properties.getSecurity().setAccountRecoveryWait(Duration.ofSeconds(1));

        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        LoggingSecurityAuditLogger audit = new LoggingSecurityAuditLogger();
        userSecurityService = new UserSecurityService(userRepository, encoder, properties,
                mock(DirectoryService.class), mock(PhoneNumberHasher.class), mock(OtpService.class), audit,
                mock(StringRedisTemplate.class), new PinPolicy());
        passkeyService = new PasskeyService(passkeyRepository, new PasskeyPrincipals(genesisRepository),
                new LoginFlowProperties(), mock(StringRedisTemplate.class), new ObjectMapper());
        recovery = new AccountRecoveryService(userSecurityService, passkeyService,
                mock(EndOtherSessionsService.class), properties, audit, clock);

        policy = new AuthorityPolicy(properties, userSecurityService);
        accounts = new AuthorityAccounts(genesisRepository);
        challenges = new AuthorityChallengeService(challengeRepository, policy,
                new AuthorityChallengeBurn(challengeRepository));
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

    @Test
    void theRegistrationSurvivesACompletedRecoveryAndThePasskeysDoNot() {
        registerOwnInstall();
        assertThat(registrationRepository.findByUserId(USER)).hasSize(1);
        String tokenFingerprint = registrationRepository.findByUserId(USER).getFirst().getTokenFingerprint();

        int removedPasskeys = driveARecovery("902184");

        assertThat(removedPasskeys).isEqualTo(2);
        assertThat(passkeyRepository.findByAccountPrincipal(accountReference)).isEmpty();
        IdentityUser after = userRepository.findByUserId(USER).orElseThrow();
        assertThat(after.getRecoveryCompletedAt()).isNotNull();
        assertThat(after.getPinResetRequestedAt()).isNull();

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

        AuthorityPushNotifier notifier = new AuthorityPushNotifier(registry,
                List.of(new ConfiguredTransport()), policy, clock);
        assertThat(notifier.isOutOfBand()).isTrue();
        assertThat(notifier.reachesOutOfBand(USER)).isTrue();
    }

    @Test
    void aTransitionIsStillRefusedWhileTheRecoveryIsInsideTheHold() {
        registerOwnInstall();
        driveARecovery("902184");

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> policy.enforceRecoveryOutsideHold(USER), AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_recovery_too_recent");
    }

    @Test
    void aRemovalThatNamesTheCallersOwnInstallPaysWhatEveryRemovalPays() {
        registerOwnInstall();
        agePinPastTheHold();

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.remove(USER, removal(OWN_INSTALL, null), SESSION, "127.0.0.1", clock.instant()),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_step_up_required");
        assertThat(registrationRepository.findByUserId(USER)).hasSize(1);

        registry.remove(USER, removal(OWN_INSTALL, "481937"), SESSION, "127.0.0.1", clock.instant());
        assertThat(registrationRepository.findByUserId(USER)).isEmpty();
    }

    @Test
    void aCallerWhoseOnlyFactorIsTheJustMintedPinCannotRemoveAnyInstall() {
        registerOwnInstall();
        registerOtherInstall();
        String attackerPin = "902184";
        driveARecovery(attackerPin);

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.remove(USER, removal(OWN_INSTALL, attackerPin), SESSION, "127.0.0.1",
                        clock.instant()),
                AuthorityTransitionException.class);

        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_factor_too_fresh");
        assertThat(registrationRepository.findByUserId(USER)).hasSize(2);
    }

    @Test
    void removingAnInstallNeedsADeviceSignatureWhenTheRowCarriesOne() {
        givenAnActiveAuthorityDevice();
        registerOwnInstallBoundToTheDevice();
        registerOtherInstall();
        agePinPastTheHold();

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.remove(USER, removal(OWN_INSTALL, "481937"), SESSION, "127.0.0.1",
                        clock.instant()),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_challenge_invalid");
        assertThat(registrationRepository.findByUserId(USER)).hasSize(2);

        agePinPastTheHold();
        String challenge = mintNotifyChallenge();
        String signature = signBinding(OWN_INSTALL, challenge);
        registry.remove(USER, removal(OWN_INSTALL, "481937", challenge, signature), SESSION, "127.0.0.1",
                clock.instant());

        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OWN_INSTALL)).isEmpty();
        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OTHER_INSTALL)).isPresent();
    }

    @Test
    void anUpsertCannotRepointAnExistingRowAtAnotherDestination() {
        registerOwnInstall();
        String fingerprintBefore = registrationRepository.findByUserIdAndInstallationId(USER, OWN_INSTALL)
                .orElseThrow().getTokenFingerprint();

        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                        ATTACKER_TOKEN, "global.gua", "iPhone", null, null, null), SESSION, clock.instant()),
                AuthorityTransitionException.class);

        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_notification_destination_refused");
        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OWN_INSTALL).orElseThrow()
                .getTokenFingerprint()).isEqualTo(fingerprintBefore);
    }

    @Test
    void theSameDestinationStillRefreshesAndASignedOneStillMoves() {
        givenAnActiveAuthorityDevice();
        registerOwnInstall();

        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                TOKEN_ONE, "global.gua", "iPhone", null, null, null), SESSION, clock.instant());
        assertThat(registrationRepository.findByUserId(USER)).hasSize(1);

        String challenge = mintNotifyChallenge();
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                ROTATED_TOKEN, "global.gua", "iPhone",
                Base64.getUrlEncoder().withoutPadding().encodeToString(device.rawPublicKey()), challenge,
                signBinding(OWN_INSTALL, challenge)), SESSION, clock.instant());

        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, OWN_INSTALL).orElseThrow()
                .getTokenFingerprint())
                .isEqualTo(AuthorityNotificationRegistry.fingerprint(ROTATED_TOKEN));
    }

    @Test
    void anApnsTokenThatIsNotHexIsRefused() {
        for (String token : new String[] { "not a token", "../../3/device/" + TOKEN_ONE, "apns-token" }) {
            AuthorityTransitionException refusal = catchThrowableOfType(
                    () -> registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL,
                            "APNS", token, "global.gua", "iPhone", null, null, null), SESSION, clock.instant()),
                    AuthorityTransitionException.class);

            assertThat(refusal).as(token).isNotNull();
            assertThat(refusal.getCode()).isEqualTo("authority_notification_invalid");
        }
        assertThat(registrationRepository.findByUserId(USER)).isEmpty();
    }

    @Test
    void anFcmTokenWithWhitespaceIsRefusedAndARealOneIsStored() {
        AuthorityTransitionException refusal = catchThrowableOfType(
                () -> registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "FCM",
                        "fMEP0vJqS0 APA91b", "global.gua", "Pixel", null, null, null), SESSION, clock.instant()),
                AuthorityTransitionException.class);
        assertThat(refusal).isNotNull();
        assertThat(refusal.getCode()).isEqualTo("authority_notification_invalid");

        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "FCM",
                "fMEP0vJqS0:APA91bH_x-Y", "global.gua", "Pixel", null, null, null), SESSION, clock.instant());
        assertThat(registrationRepository.findByUserId(USER)).hasSize(1);
    }

    private void givenTwoPasskeys() {
        passkeyRepository.saveAndFlush(passkey("cred-one"));
        passkeyRepository.saveAndFlush(passkey("cred-two"));
    }

    private PasskeyCredential passkey(String credentialId) {
        PasskeyCredential credential = PasskeyCredential.builder()
                .accountPrincipal(accountReference)
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
                TOKEN_ONE, "global.gua", "iPhone", null, null, null), SESSION, clock.instant());
    }

    private void registerOtherInstall() {
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OTHER_INSTALL, "APNS",
                TOKEN_TWO, "global.gua", "iPad", null, null, null), SESSION, clock.instant());
    }

    private void registerOwnInstallBoundToTheDevice() {
        String challenge = mintNotifyChallenge();
        registry.register(USER, new AuthorityNotificationRegistry.Registration(OWN_INSTALL, "APNS",
                TOKEN_ONE, "global.gua", "iPhone",
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

    private int driveARecovery(String attackerChosenPin) {
        userRepository.findByUserId(USER).ifPresent(user -> {
            user.setLastLoginAt(clock.instant().minus(Duration.ofDays(60)));
            userRepository.saveAndFlush(user);
        });
        recovery.start(USER, "+55 11 ****-**89", "127.0.0.1");
        clock.advance(Duration.ofSeconds(1));
        return recovery.complete(USER, attackerChosenPin);
    }

    /** Backdates the stamp: {@code UserSecurityService} measures the hold against the wall clock. */
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
