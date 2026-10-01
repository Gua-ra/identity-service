// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityNotificationRegistrationRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityWebStepUpRepository;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyPrincipals;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyService;
import me.sarahlacerda.gua.identityservice.service.security.PinPolicy;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Import(AuthorityStepUpLockoutTest.Beans.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuthorityStepUpLockoutTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final String PIN = "481937";
    private static final String WRONG_PIN = "000000";
    private static final String INSTALL = "install-phone";

    @Autowired
    private UserSecurityService userSecurityService;

    @Autowired
    private AccountAuthorityService service;

    @Autowired
    private AuthorityNotificationRegistry registry;

    @Autowired
    private IdentityUserRepository userRepository;

    @Autowired
    private AccountGenesisRepository genesisRepository;

    @Autowired
    private AuthorityChainHeadRepository headRepository;

    @Autowired
    private AuthorityNotificationRegistrationRepository registrationRepository;

    private String account;

    @BeforeEach
    void anAccountWithAPin() {
        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        account = genesis.accountId().value();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(account, USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), Instant.now()));
        userSecurityService.setInitialPin(USER, PIN);
    }

    @AfterEach
    void clear() {
        registrationRepository.deleteAll();
        headRepository.deleteAll();
        genesisRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void wrongPinsAtAChallengeLockThePin() {
        assertLocksThePin(pin -> service.challenge(USER, Optional.empty(), SESSION, Purpose.ADOPT, null, null, pin,
                "127.0.0.1"));
    }

    @Test
    void wrongPinsAtARepeatedObjectionLockThePin() {
        AuthorityChainHead head = AuthorityChainHead.empty(account, Instant.now());
        head.setCancelledCount(1);
        headRepository.saveAndFlush(head);

        assertLocksThePin(pin -> service.oppose(USER, "0".repeat(64), null, null, pin, "127.0.0.1"));
    }

    @Test
    void wrongPinsAtANotificationRemovalLockThePin() {
        Instant now = Instant.now();
        registrationRepository.saveAndFlush(AuthorityNotificationRegistration.registered(USER, INSTALL,
                Platform.FCM, "global.gua", "token", AuthorityNotificationRegistry.fingerprint("token"), "Pixel",
                null, now));

        assertLocksThePin(pin -> registry.remove(USER,
                new AuthorityNotificationRegistry.Removal(INSTALL, null, null, pin, null, null), SESSION,
                "127.0.0.1", now));

        assertThat(registrationRepository.findByUserIdAndInstallationId(USER, INSTALL)).isPresent();
    }

    private void assertLocksThePin(StepUp stepUp) {
        for (int attempt = 0; attempt < Beans.PROPERTIES.getSecurity().getMaxPinAttempts(); attempt++) {
            assertThatThrownBy(attempt(stepUp, WRONG_PIN)).isInstanceOf(InvalidPinException.class);
        }

        assertThat(userRepository.findByUserId(USER).orElseThrow().getPinLockedUntil()).isNotNull();
        assertThatThrownBy(attempt(stepUp, PIN)).isInstanceOf(PinLockedException.class);
    }

    private static ThrowingCallable attempt(StepUp stepUp, String pin) {
        return () -> stepUp.with(pin);
    }

    @FunctionalInterface
    private interface StepUp {
        void with(String pin);
    }

    @TestConfiguration
    static class Beans {

        static final IdentityServiceProperties PROPERTIES = properties();

        private static IdentityServiceProperties properties() {
            IdentityServiceProperties properties = new IdentityServiceProperties();
            properties.getAuthority().setEnabled(true);
            properties.getAuthority().getNotifications().setEnabled(true);
            properties.getSecurity().setPinResetCooldown(Duration.ZERO);
            return properties;
        }

        @Bean
        UserSecurityService userSecurityService(IdentityUserRepository userRepository) {
            return new UserSecurityService(userRepository, new BCryptPasswordEncoder(4), PROPERTIES,
                    mock(DirectoryService.class), mock(PhoneNumberHasher.class), mock(OtpService.class),
                    new LoggingSecurityAuditLogger(), mock(StringRedisTemplate.class), new PinPolicy());
        }

        @Bean
        AuthorityPolicy authorityPolicy(UserSecurityService userSecurityService) {
            return new AuthorityPolicy(PROPERTIES, userSecurityService);
        }

        @Bean
        AuthorityAccounts authorityAccounts(AccountGenesisRepository genesisRepository) {
            return new AuthorityAccounts(genesisRepository);
        }

        @Bean
        AuthorityChallengeBurn authorityChallengeBurn(AuthorityChallengeRepository repository) {
            return new AuthorityChallengeBurn(repository);
        }

        @Bean
        AuthorityChallengeService authorityChallengeService(AuthorityChallengeRepository repository,
                AuthorityPolicy policy, AuthorityChallengeBurn burn) {
            return new AuthorityChallengeService(repository, policy, burn);
        }

        @Bean
        AuthorityStepUpService authorityStepUpService(PasskeyCredentialRepository passkeyRepository,
                AccountGenesisRepository genesisRepository, AuthorityWebStepUpRepository webStepUpRepository,
                UserSecurityService userSecurityService, AuthorityPolicy policy) {
            PasskeyService passkeyService = new PasskeyService(passkeyRepository,
                    new PasskeyPrincipals(genesisRepository), new LoginFlowProperties(),
                    mock(StringRedisTemplate.class), new ObjectMapper());
            return new AuthorityStepUpService(passkeyService, userSecurityService, policy,
                    new AuthorityWebStepUpService(webStepUpRepository, policy, Clock.systemUTC()),
                    new LoggingSecurityAuditLogger());
        }

        @Bean
        AccountAuthorityService accountAuthorityService(AuthorityPolicy policy, AuthorityAccounts accounts,
                AuthorityChallengeService challenges, AuthorityStepUpService stepUps,
                AuthorityChainHeadRepository headRepository, AuthorityChainRecordRepository recordRepository,
                AuthorityDeviceRepository deviceRepository, AuthorityDeviceCandidateRepository candidateRepository) {
            return new AccountAuthorityService(policy, accounts, challenges, stepUps, headRepository,
                    recordRepository, deviceRepository, candidateRepository, mock(AuthorityNotifications.class),
                    mock(AuthorityBackoff.class), AuthorityHeadPublisherFixtures.off(PROPERTIES),
                    new LoggingSecurityAuditLogger(), Clock.systemUTC());
        }

        @Bean
        AuthorityNotificationRegistry authorityNotificationRegistry(
                AuthorityNotificationRegistrationRepository repository, AuthorityDeviceRepository deviceRepository,
                AuthorityAccounts accounts, AuthorityChallengeService challenges, AuthorityStepUpService stepUps,
                AuthorityPolicy policy) {
            return new AuthorityNotificationRegistry(repository, deviceRepository, accounts, challenges, stepUps,
                    policy);
        }
    }
}
