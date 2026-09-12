package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;

/**
 * The bar an assertion has to clear before it may stand in for a knowledge factor.
 *
 * <p>
 * A sign-in assertion proves possession of an unlocked device. The account PIN it
 * would replace on a privileged operation proves knowledge, counts its failures and
 * locks out. So the step-up ceremony demands user verification, and it is a separate
 * ceremony from sign-in: raising sign-in to the same bar would refuse an authenticator
 * that cannot do user verification and silently move those accounts onto another
 * factor, which is a cost login does not need to pay.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyServiceStepUpTest {

    private static final String USER = "@alice:gua.global";
    // base64url of 32 bytes, the shape a stored credential id has.
    private static final String CREDENTIAL_ID = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    @Mock
    private PasskeyCredentialRepository repository;
    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private LoginFlowProperties properties;
    private PasskeyService service;

    @BeforeEach
    void setUp() {
        properties = new LoginFlowProperties();
        service = new PasskeyService(repository, properties, redisTemplate, new ObjectMapper());
    }

    @Test
    void theStepUpCeremonyDemandsUserVerification() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(repository.existsByUserId(USER)).thenReturn(true);
        when(repository.findByUserId(USER)).thenReturn(List.of(credential()));

        service.startStepUpAssertion("step-1", USER);

        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq("passkey:stepup:step-1"), stored.capture(), any());
        assertThat(stored.getValue()).contains("\"userVerification\":\"required\"");
        // Pinned to the account that asked for it, so the assertion cannot resolve elsewhere.
        assertThat(stored.getValue()).contains(USER);
    }

    @Test
    void signInKeepsItsOwnCeremonyAndItsOwnBar() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        service.startAuthentication("login-1");

        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq("passkey:assertion:login-1"), stored.capture(), any());
        // Deliberately still preferred. A credential registered without user verification can
        // still sign in; it just cannot be spent as a step-up factor.
        assertThat(stored.getValue()).contains("\"userVerification\":\"preferred\"");
        verify(valueOperations, never()).set(eq("passkey:stepup:login-1"), anyString(), any());
    }

    @Test
    void aStepUpChallengeAndASignInChallengeAreNotInterchangeable() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("passkey:stepup:login-1")).thenReturn(null);

        // A sign-in challenge lives under a different key, so presenting its id to the step-up
        // path finds nothing rather than redeeming a ceremony that never asked for user
        // verification.
        assertThatThrownBy(() -> service.finishStepUpAssertion("login-1", JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class)
                .extracting(ex -> ((LoginFlowException) ex).getStatus())
                .isEqualTo(HttpStatus.GONE);
    }

    @Test
    void anAccountWithNoCredentialGetsAClearRefusalAndNoChallenge() {
        when(repository.existsByUserId(USER)).thenReturn(false);

        assertThatThrownBy(() -> service.startStepUpAssertion("step-1", USER))
                .isInstanceOf(LoginFlowException.class)
                .extracting(ex -> ((LoginFlowException) ex).getCode())
                .isEqualTo("passkey_not_registered");

        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    void theStepUpCeremonyIsUnavailableWhenPasskeysAreOff() {
        properties.getPasskeys().setEnabled(false);

        assertThatThrownBy(() -> service.startStepUpAssertion("step-1", USER))
                .isInstanceOf(LoginFlowException.class)
                .extracting(ex -> ((LoginFlowException) ex).getStatus())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    private PasskeyCredential credential() {
        return PasskeyCredential.builder()
                .userId(USER)
                .userHandle("dXNlcg")
                .credentialId(CREDENTIAL_ID)
                .publicKeyCose(CREDENTIAL_ID)
                .signatureCount(0)
                .backupEligible(false)
                .backupState(false)
                .build();
    }
}
