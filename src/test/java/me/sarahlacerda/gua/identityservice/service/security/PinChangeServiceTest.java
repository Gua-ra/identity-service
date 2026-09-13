package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinOperationException;
import me.sarahlacerda.gua.identityservice.exception.PinChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpScope;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * The PIN change start over a real {@link UserSecurityService}, so the cooldown, the number
 * ownership check, the PIN attempt accounting and the scoped send are the application's own.
 */
class PinChangeServiceTest {

    private static final String USER = "@user:gua.global";
    private static final String PHONE = "+12025550123";
    private static final String IP = "127.0.0.1";

    private IdentityUserRepository repository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private DirectoryService directoryService;
    private PhoneNumberHasher phoneNumberHasher;
    private OtpService otpService;
    private SecurityAuditLogger auditLogger;
    private ValueOperations<String, String> valueOps;
    private PasskeyService passkeyService;
    private PinChangeService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        repository = mock(IdentityUserRepository.class);
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getSecurity().setPinResetCooldown(Duration.ofDays(7));
        properties.getSecurity().setPinLockDuration(Duration.ofMinutes(5));
        properties.getSecurity().setMaxPinAttempts(3);
        properties.getSecurity().setPinChangeCooldown(Duration.ofHours(24));
        properties.getSecurity().setPinChangeChallengeTtl(Duration.ofMinutes(5));
        directoryService = mock(DirectoryService.class);
        phoneNumberHasher = mock(PhoneNumberHasher.class);
        otpService = mock(OtpService.class);
        auditLogger = mock(SecurityAuditLogger.class);
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        passkeyService = mock(PasskeyService.class);
        UserSecurityService userSecurityService = new UserSecurityService(repository, passwordEncoder, properties,
                directoryService, phoneNumberHasher, otpService, auditLogger, redisTemplate, new PinPolicy());
        service = new PinChangeService(userSecurityService, passkeyService, auditLogger);
    }

    @Test
    void anAcceptedPasskeyStartsTheChangeWithoutConsultingThePin() {
        IdentityUser user = userWithPin();
        JsonNode credential = credential();
        when(passkeyService.finishStepUpAssertion("step-1", credential)).thenReturn(
                new PasskeyService.PasskeyAuthentication(USER, Instant.now().minus(Duration.ofDays(30))));

        // A wrong PIN rides along: if the PIN were consulted this would be invalid_pin.
        String challengeId = service.start(USER, PHONE, "000000", "step-1", credential, IP);

        assertThat(challengeId).isNotBlank();
        verify(repository, never()).findByUserIdForUpdate(any());
        verify(auditLogger, never()).pinValidationFailed(any(), anyInt());
        assertThat(user.getPinFailureCount()).isZero();
        verify(otpService).sendScopedOtp(OtpScope.PIN_CHANGE, challengeId, PHONE, IP, null);
        verify(valueOps).set(eq("pin:change:" + challengeId), eq(USER + "|" + PHONE), eq(Duration.ofMinutes(5)));
        verify(auditLogger).pinChangeStarted(eq(USER), any(String.class), eq(IP));
    }

    @Test
    void withoutAnAssertionTheCurrentPinIsStillRequired() {
        userWithPin();

        assertThatThrownBy(() -> service.start(USER, PHONE, null, null, null, IP))
                .isInstanceOf(InvalidPinException.class);
        // A step-up id with no credential, or with an explicit JSON null, is not an assertion.
        assertThatThrownBy(() -> service.start(USER, PHONE, null, "step-1", null, IP))
                .isInstanceOf(InvalidPinException.class);
        assertThatThrownBy(() -> service.start(USER, PHONE, null, "step-1", JsonNodeFactory.instance.nullNode(), IP))
                .isInstanceOf(InvalidPinException.class);
        verify(passkeyService, never()).finishStepUpAssertion(any(), any());
        verify(otpService, never()).sendScopedOtp(any(), any(), any(), any(), any());
    }

    @Test
    void theCurrentPinStillStartsTheChange() {
        userWithPin();

        String challengeId = service.start(USER, PHONE, "123456", null, null, IP);

        assertThat(challengeId).isNotBlank();
        verify(passkeyService, never()).finishStepUpAssertion(any(), any());
        verify(otpService).sendScopedOtp(OtpScope.PIN_CHANGE, challengeId, PHONE, IP, null);
    }

    @Test
    void aPasskeyBelongingToAnotherAccountIsRefusedAndNothingIsSent() {
        userWithPin();
        JsonNode credential = credential();
        when(passkeyService.finishStepUpAssertion("step-1", credential)).thenReturn(
                new PasskeyService.PasskeyAuthentication("@other:gua.global", Instant.now().minus(Duration.ofDays(30))));

        assertThatThrownBy(() -> service.start(USER, PHONE, "123456", "step-1", credential, IP))
                .isInstanceOf(InvalidPinException.class);
        verify(auditLogger).reauthFailed(USER, "PIN_CHANGE", IP);
        verify(otpService, never()).sendScopedOtp(any(), any(), any(), any(), any());
        verify(valueOps, never()).set(any(), any(), any(Duration.class));
    }

    @Test
    void aFreshlyRegisteredPasskeyIsHeld() {
        userWithPin();
        JsonNode credential = credential();
        when(passkeyService.finishStepUpAssertion("step-1", credential)).thenReturn(
                new PasskeyService.PasskeyAuthentication(USER, Instant.now().minus(Duration.ofMinutes(5))));

        assertThatThrownBy(() -> service.start(USER, PHONE, null, "step-1", credential, IP))
                .isInstanceOf(TwoFactorCooldownException.class);
        verify(otpService, never()).sendScopedOtp(any(), any(), any(), any(), any());
    }

    @Test
    void theCooldownAndNumberOwnershipAreCheckedBeforeTheCeremonyIsSpent() {
        IdentityUser user = userWithPin();
        user.setLastPinChangeAt(Instant.now().minus(Duration.ofHours(1)));
        JsonNode credential = credential();

        assertThatThrownBy(() -> service.start(USER, PHONE, null, "step-1", credential, IP))
                .isInstanceOf(PinChangeCooldownException.class);

        user.setLastPinChangeAt(null);
        when(phoneNumberHasher.digest("+12025550199")).thenReturn("other-digest");
        when(directoryService.findByDigest("other-digest")).thenReturn(Optional.of(directoryEntry("@other:gua.global")));
        assertThatThrownBy(() -> service.start(USER, "+12025550199", null, "step-1", credential, IP))
                .isInstanceOf(InvalidPinOperationException.class);

        verify(passkeyService, never()).finishStepUpAssertion(any(), any());
        verify(otpService, never()).sendScopedOtp(any(), any(), any(), any(), any());
    }

    @Test
    void anAccountWithoutAPinHasNothingToChangeEvenWithAPasskey() {
        IdentityUser user = IdentityUser.builder().userId(USER).build();
        when(repository.findByUserId(USER)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.start(USER, PHONE, null, "step-1", credential(), IP))
                .isInstanceOf(InvalidPinOperationException.class);
        verify(passkeyService, never()).finishStepUpAssertion(any(), any());
    }

    private IdentityUser userWithPin() {
        IdentityUser user = IdentityUser.builder().userId(USER).build();
        user.setPinHash(passwordEncoder.encode("123456"));
        when(repository.findByUserId(USER)).thenReturn(Optional.of(user));
        when(repository.findByUserIdForUpdate(USER)).thenReturn(Optional.of(user));
        when(phoneNumberHasher.digest(PHONE)).thenReturn("digest");
        when(directoryService.findByDigest("digest")).thenReturn(Optional.of(directoryEntry(USER)));
        return user;
    }

    private static JsonNode credential() {
        return JsonNodeFactory.instance.objectNode().put("id", "cred-1");
    }

    private static DirectoryEntry directoryEntry(String userId) {
        return DirectoryEntry.builder().phoneDigest("digest").userId(userId).displayName("User").build();
    }
}
