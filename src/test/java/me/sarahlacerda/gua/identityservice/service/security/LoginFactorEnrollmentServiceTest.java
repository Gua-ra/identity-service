package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession.SessionFactor;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * The ENROLLED decision: a session that has only proved the phone may finish by creating the
 * account's first factor, and the "first" is decided under the row lock at the moment of writing.
 */
class LoginFactorEnrollmentServiceTest {

    private static final String USER = "@alice:gua.global";

    private IdentityUserRepository repository;
    private PasskeyService passkeyService;
    private PasswordEncoder passwordEncoder;
    private LoginFactorEnrollmentService service;
    private IdentityUser user;

    @BeforeEach
    void setUp() {
        repository = mock(IdentityUserRepository.class);
        passkeyService = mock(PasskeyService.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        UserSecurityService userSecurityService = new UserSecurityService(repository, passwordEncoder,
                new IdentityServiceProperties(), mock(DirectoryService.class), mock(PhoneNumberHasher.class),
                mock(OtpService.class), mock(SecurityAuditLogger.class), mock(StringRedisTemplate.class),
                new PinPolicy());
        service = new LoginFactorEnrollmentService(userSecurityService, passkeyService);
        user = IdentityUser.builder().userId(USER).build();
        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.of(user));
    }

    private LoginSession sessionWith(SessionFactor factor) {
        LoginSession session = new LoginSession();
        session.setUserId(USER);
        session.setAuthenticatedFactor(factor);
        return session;
    }

    @Test
    void theFirstPinOfAFactorlessAccountIsSet() {
        service.setUpFirstPin(USER, "284917");

        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        verify(repository, never()).findByUserId(USER);
    }

    /**
     * The PIN added from settings, after the enrollment step-up. A passkey on the account is no
     * obstacle here, unlike at first-factor setup: producing it is what authorized this, and
     * adding the PIN underneath it is the point.
     *
     * <p>
     * And it starts its fresh-factor hold like any other PIN. A PIN added minutes ago from a
     * session an attacker holds must not be spendable straight away as the step-up that
     * re-points the phone number, so the stamp is asserted here rather than left to fall out of
     * the write path this happens to share with the others.
     */
    @Test
    void anEnrolledPinIsSetOnAnAccountThatHoldsAPasskey() {
        when(passkeyService.hasPasskey(USER)).thenReturn(true);

        service.setUpEnrolledPin(USER, "284917");

        assertThat(passwordEncoder.matches("284917", user.getPinHash())).isTrue();
        assertThat(user.getPinSetAt()).isNotNull().isAfter(Instant.now().minusSeconds(60));
    }

    @Test
    void anEnrolledPinIsRefusedWhenTheAccountAlreadyHasOne() {
        user.setPinHash(passwordEncoder.encode("111213"));

        assertThatThrownBy(() -> service.setUpEnrolledPin(USER, "284917"))
                .isInstanceOf(LoginFlowException.class)
                .hasMessageContaining("already has a PIN");

        assertThat(passwordEncoder.matches("111213", user.getPinHash())).isTrue();
    }

    @Test
    void aPinIsNotSetOnAnAccountThatGainedAPasskeyInTheMeantime() {
        when(passkeyService.hasPasskey(USER)).thenReturn(true);

        assertThatThrownBy(() -> service.setUpFirstPin(USER, "284917"))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "factor_required");

        assertThat(user.hasPin()).isFalse();
    }

    @Test
    void aPinIsNotReplacedOnAnAccountThatGainedAPinInTheMeantime() {
        user.setPinHash(passwordEncoder.encode("739164"));

        assertThatThrownBy(() -> service.setUpFirstPin(USER, "284917"))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "factor_required");

        assertThat(passwordEncoder.matches("739164", user.getPinHash())).isTrue();
    }

    @Test
    void theFirstPasskeyOfAFactorlessAccountIsItsFirstFactor() {
        LoginSession session = sessionWith(null);

        assertThat(service.registerPasskey("sid", session, JsonNodeFactory.instance.objectNode())).isTrue();

        verify(passkeyService).finishRegistration(any(), any(), any());
    }

    @Test
    void anUnauthenticatedSessionCannotAddAPasskeyToAnAccountThatAlreadyHoldsAFactor() {
        user.setPinHash(passwordEncoder.encode("739164"));

        assertThatThrownBy(() -> service.registerPasskey("sid", sessionWith(null),
                JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "factor_required");

        when(passkeyService.hasPasskey(USER)).thenReturn(true);
        user.setPinHash(null);
        assertThatThrownBy(() -> service.registerPasskey("sid", sessionWith(null),
                JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class);

        // Refused before the credential is stored.
        verify(passkeyService, never()).finishRegistration(any(), any(), any());
    }

    @Test
    void aSessionThatSignedInWithItsPinMayAddAPasskeyButItIsNotAFirstFactor() {
        user.setPinHash(passwordEncoder.encode("739164"));

        assertThat(service.registerPasskey("sid", sessionWith(SessionFactor.PIN),
                JsonNodeFactory.instance.objectNode())).isFalse();

        verify(passkeyService).finishRegistration(any(), any(), any());
    }

    /**
     * Two sessions for an account with no row both find nothing to lock. The one that loses the
     * insert gets the same answer as one that found a factor, not a server error, and stores nothing.
     */
    @Test
    void losingTheRaceToCreateTheRowIsFactorRequired() {
        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.empty());
        when(repository.saveAndFlush(any(IdentityUser.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate key value violates unique constraint"));

        assertThatThrownBy(() -> service.setUpFirstPin(USER, "284917"))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "factor_required");
        assertThatThrownBy(() -> service.registerPasskey("sid", sessionWith(null),
                JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "factor_required");

        verify(passkeyService, never()).finishRegistration(any(), any(), any());
    }

    @Test
    void aSessionWithNoSubjectIsRefusedBeforeAnyRowIsTouched() {
        LoginSession session = new LoginSession();

        assertThatThrownBy(() -> service.registerPasskey("sid", session, JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class)
                .hasFieldOrPropertyWithValue("code", "passkey_user_unknown");

        verify(repository, never()).findByUserIdForUpdate(any());
    }
}
