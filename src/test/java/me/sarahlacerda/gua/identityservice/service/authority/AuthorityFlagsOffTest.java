// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthorityFlagsOffTest {

    @Mock
    private AuthorityAccounts accounts;

    @Mock
    private AuthorityChallengeService challenges;

    @Mock
    private AuthorityStepUpService stepUps;

    @Mock
    private AuthorityChainHeadRepository headRepository;

    @Mock
    private AuthorityChainRecordRepository recordRepository;

    @Mock
    private AuthorityDeviceRepository deviceRepository;

    @Mock
    private AuthorityChallengeRepository challengeRepository;

    @Mock
    private me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository candidateRepository;

    @Mock
    private AuthorityNotifications notifications;

    @Mock
    private AuthorityBackoff backoff;

    @Mock
    private SecurityAuditLogger auditLogger;

    @Mock
    private UserSecurityService userSecurityService;

    private IdentityServiceProperties properties;
    private AccountAuthorityService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        assertThat(properties.getAuthority().isEnabled()).isFalse();
        AuthorityPolicy policy = new AuthorityPolicy(properties, userSecurityService);
        service = new AccountAuthorityService(policy, accounts, challenges, stepUps, headRepository,
                recordRepository, deviceRepository, candidateRepository, notifications, backoff,
                AuthorityHeadPublisherFixtures.off(properties), auditLogger, java.time.Clock.systemUTC());
    }

    @Test
    void theDefaultsAreOffWithA72HourOppositionWindowAndA7DayRecoveryWindow() {
        assertThat(properties.getAuthority().isEnabled()).isFalse();
        assertThat(properties.getAuthority().isAdoptionPermitted()).isFalse();
        assertThat(properties.getAuthority().isAllowShortWindowsForTesting()).isFalse();
        assertThat(properties.getAuthority().getNativeClientIds()).isEmpty();
        assertThat(properties.getAuthority().getOppositionWindow()).hasHours(72);
        assertThat(properties.getAuthority().getRecoveryWindow()).hasDays(7);
        assertThat(properties.getAuthority().getChallengeTtl()).hasMinutes(15);
    }

    @Test
    void mintingAChallengeIsRefusedBeforeAnyStepUpIsWeighed() {
        assertThat(refusalFrom(() -> service.challenge("@a:gua", Optional.of("gua-ios"), "s", Purpose.ADOPT,
                null, null, "1234", "127.0.0.1"))).isEqualTo("authority_disabled");

        verifyNoInteractions(stepUps, challenges, accounts, headRepository, recordRepository, deviceRepository);
    }

    @Test
    void adoptionIsRefusedBeforeTheRecordIsEvenDecoded() {
        assertThat(refusalFrom(() -> service.adopt("@a:gua", Optional.of("gua-ios"), "s", "nonsense", "nonsense",
                "nonsense", true))).isEqualTo("authority_disabled");

        verifyNoInteractions(accounts, challenges, headRepository, recordRepository, deviceRepository);
    }

    @Test
    void everyDeviceTransitionIsRefusedAndTouchesNothing() {
        assertThat(refusalFrom(() -> service.grantDevice("@a:gua", Optional.of("gua-ios"), "s", "r", "sig", "c")))
                .isEqualTo("authority_disabled");
        assertThat(refusalFrom(() -> service.revokeDevice("@a:gua", Optional.of("gua-ios"), "s", "r", "sig", "c")))
                .isEqualTo("authority_disabled");
        assertThat(refusalFrom(() -> service.recoverAuthority("@a:gua", Optional.of("gua-ios"), "s", "r", "sig",
                "c"))).isEqualTo("authority_disabled");

        verifyNoInteractions(accounts, challenges, headRepository, recordRepository, deviceRepository, backoff,
                notifications);
    }

    @Test
    void opposingIsRefusedAndTakesNoLock() {
        assertThat(refusalFrom(() -> service.oppose("@a:gua", "hash", null, null, null, "127.0.0.1")))
                .isEqualTo("authority_disabled");
        assertThat(refusalFrom(() -> service.opposeWithRecord("@a:gua", Optional.of("gua-ios"), "s", "r", "sig",
                "c"))).isEqualTo("authority_disabled");

        verifyNoInteractions(headRepository, recordRepository, accounts, stepUps);
    }

    @Test
    void theCandidateStepIsRefusedAndStoresNothing() {
        assertThat(refusalFrom(() -> service.registerCandidate("@a:gua", "key", "iPad")))
                .isEqualTo("authority_disabled");
        assertThat(refusalFrom(() -> service.candidates("@a:gua"))).isEqualTo("authority_disabled");

        verifyNoInteractions(accounts, candidateRepository);
    }

    @Test
    void readingTheChainIsRefusedSoNoAccountIdEverLeavesThisDeployment() {
        assertThat(refusalFrom(() -> service.state("@a:gua"))).isEqualTo("authority_disabled");

        verifyNoInteractions(accounts, headRepository, deviceRepository);
    }

    private static String refusalFrom(Runnable action) {
        AuthorityTransitionException refusal =
                catchThrowableOfType(action::run, AuthorityTransitionException.class);
        assertThat(refusal).as("expected a refusal").isNotNull();
        return refusal.getCode();
    }
}
