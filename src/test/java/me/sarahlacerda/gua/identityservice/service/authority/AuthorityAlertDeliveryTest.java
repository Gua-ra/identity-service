// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecords;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityNotificationRegistrationRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@Import(AuthorityAlertDeliveryTest.Wiring.class)
class AuthorityAlertDeliveryTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final String NATIVE_CLIENT = "gua-ios";
    private static final Instant NOW = Instant.parse("2026-09-30T12:00:00Z");

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
    private AuthorityDeviceCandidateRepository candidateRepository;

    @Autowired
    private AuthorityNotificationRegistrationRepository registrationRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private AuthorityNotificationRegistry registry;

    @Autowired
    private SwitchablePolicy policy;

    private final TestEd25519.Pair device = TestEd25519.generate();
    private final TestEd25519.Pair recoveryKey = TestEd25519.generate();
    private final Clock clock = Clock.fixed(NOW, java.time.ZoneOffset.UTC);
    private final RecordingTransport transport = new RecordingTransport();

    private TransactionTemplate transactions;
    private TransactionTemplate separateTransaction;
    private AuthorityChallengeService challenges;
    private AccountAuthorityService service;
    private byte[] reference;

    @BeforeEach
    void setUp() {
        transactions = new TransactionTemplate(transactionManager);
        separateTransaction = new TransactionTemplate(transactionManager);
        separateTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        policy.bookkeepingFails = false;

        challenges = new AuthorityChallengeService(challengeRepository, policy,
                new AuthorityChallengeBurn(challengeRepository));
        AuthorityNotifications notifications = new AuthorityNotifications(
                List.of(new AuthorityPushNotifier(registry, List.of(transport), policy, clock)));
        service = new AccountAuthorityService(policy, new AuthorityAccounts(genesisRepository), challenges,
                mock(AuthorityStepUpService.class), headRepository, recordRepository, deviceRepository,
                candidateRepository, notifications, new NoBackoff(policy),
                AuthorityHeadPublisherFixtures.off(policy.properties), new LoggingSecurityAuditLogger(), clock);

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), NOW));
        reference = genesis.accountId().rawBytes();

        registrationRepository.saveAndFlush(AuthorityNotificationRegistration.registered(USER, "install-phone",
                Platform.APNS, "global.gua", "apns-token", "fingerprint", "iPhone", null, NOW));
    }

    @AfterEach
    void tearDown() {
        registrationRepository.deleteAll();
        headRepository.deleteAll();
        recordRepository.deleteAll();
        deviceRepository.deleteAll();
        challengeRepository.deleteAll();
        candidateRepository.deleteAll();
        genesisRepository.deleteAll();
    }

    @Test
    void anAlertIsSentOnlyAfterTheTransitionHasCommitted() {
        List<Boolean> committedWhenSent = new ArrayList<>();
        transport.onSend = () -> committedWhenSent.add(separateTransaction.execute(status -> pendingHead()));

        adopt();

        assertThat(committedWhenSent).containsExactly(true);
    }

    @Test
    void aTransitionThatRollsBackSendsNoAlert() {
        String challenge = mint();

        transactions.execute(status -> {
            submitAdoption(challenge);
            status.setRollbackOnly();
            return null;
        });

        assertThat(pendingHead()).isFalse();
        assertThat(transport.sent).isZero();
    }

    @Test
    void aFailureRecordingTheDeliveryOutcomeDoesNotUndoTheTransition() {
        transport.outcome = AuthorityPushTransport.Outcome.UNREGISTERED;
        transport.onSend = () -> policy.bookkeepingFails = true;

        adopt();

        assertThat(transport.sent).isEqualTo(1);
        assertThat(pendingHead()).isTrue();
    }

    @Test
    void aRegistrationRemovedWhileItsAlertIsInFlightDoesNotUndoTheTransition() {
        transport.outcome = AuthorityPushTransport.Outcome.RETRYABLE;
        transport.onSend = () -> separateTransaction.executeWithoutResult(
                status -> registrationRepository.deleteAll());

        adopt();

        assertThat(transport.sent).isEqualTo(1);
        assertThat(pendingHead()).isTrue();
    }

    @Test
    void theDeliveryOutcomeIsStoredAlthoughItIsRecordedAfterTheCommit() {
        transport.outcome = AuthorityPushTransport.Outcome.RETRYABLE;

        adopt();

        assertThat(registrationRepository.findByUserId(USER))
                .singleElement()
                .satisfies(row -> assertThat(row.getConsecutiveFailures()).isEqualTo(1));
    }

    private void adopt() {
        String challenge = mint();
        transactions.executeWithoutResult(status -> submitAdoption(challenge));
    }

    private void submitAdoption(String challenge) {
        byte[] bytes = AuthorityRecords.adoptRootFor(reference, device.rawPublicKey(),
                recoveryKey.rawPublicKey(), "iPhone", 1, AuthorityRecord.emptyPrevHash());
        byte[] preimage = AuthorityProofs.recordPreimage(AuthorityRecordType.ADOPT_ROOT,
                Base64.getUrlDecoder().decode(challenge), bytes);
        service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                encode(TestEd25519.sign(device.privateKey(), preimage)), challenge, true);
    }

    private String mint() {
        return transactions.execute(status -> challenges.mint(account(), SESSION, Purpose.ADOPT,
                AuthFactor.PASSKEY, NOW.minus(Duration.ofDays(30)), NOW).challenge());
    }

    private boolean pendingHead() {
        return headRepository.findByAccount(account()).map(AuthorityChainHead::hasPending).orElse(false);
    }

    private String account() {
        return genesisRepository.findByUserId(USER).orElseThrow().getAccountId();
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    @TestConfiguration
    static class Wiring {

        @Bean
        SwitchablePolicy policy() {
            IdentityServiceProperties properties = new IdentityServiceProperties();
            properties.getAuthority().setEnabled(true);
            properties.getAuthority().setAdoptionPermitted(true);
            properties.getAuthority().getNativeClientIds().add(NATIVE_CLIENT);
            properties.getAuthority().getNotifications().setEnabled(true);
            return new SwitchablePolicy(properties);
        }

        /** A bean so that its transactional methods run through the container's proxy. */
        @Bean
        AuthorityNotificationRegistry registry(AuthorityNotificationRegistrationRepository repository,
                AuthorityDeviceRepository deviceRepository, AccountGenesisRepository genesisRepository,
                SwitchablePolicy policy) {
            return new AuthorityNotificationRegistry(repository, deviceRepository,
                    new AuthorityAccounts(genesisRepository), mock(AuthorityChallengeService.class),
                    mock(AuthorityStepUpService.class), policy);
        }
    }

    static class SwitchablePolicy extends AuthorityPolicy {

        private final IdentityServiceProperties properties;
        private volatile boolean bookkeepingFails;

        SwitchablePolicy(IdentityServiceProperties properties) {
            super(properties, mock(UserSecurityService.class));
            this.properties = properties;
        }

        @Override
        public int registrationFailureLimit() {
            if (bookkeepingFails) {
                throw new IllegalStateException("bookkeeping failed");
            }
            return super.registrationFailureLimit();
        }
    }

    private static final class RecordingTransport implements AuthorityPushTransport {

        private Outcome outcome = Outcome.DELIVERED;
        private Runnable onSend = () -> { };
        private int sent;

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
            sent++;
            onSend.run();
            return outcome;
        }
    }

    private static final class NoBackoff extends AuthorityBackoff {

        private NoBackoff(AuthorityPolicy policy) {
            super(null, policy);
        }

        @Override
        public Optional<Instant> until(String account, String keyB64) {
            return Optional.empty();
        }

        @Override
        public Instant recordCancellation(String account, String keyB64, Instant now) {
            return now;
        }
    }
}
