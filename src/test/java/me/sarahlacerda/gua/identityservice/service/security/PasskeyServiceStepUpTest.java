package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

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
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.Base64UrlException;

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
    // Stands in for the ceremony Redis is holding. The tests that use it replace the ceremony
    // itself, so this is never parsed; it only has to be non-blank, because a blank one is the
    // expired-challenge path.
    private static final String STORED_CEREMONY = "{\"stored\":\"ceremony\"}";

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
    void aRefusedStepUpAssertionBurnsItsChallenge() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(repository.existsByUserId(USER)).thenReturn(true);
        when(repository.findByUserId(USER)).thenReturn(List.of(credential()));
        service.startStepUpAssertion("step-1", USER);
        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq("passkey:stepup:step-1"), stored.capture(), any());
        when(valueOperations.get("passkey:stepup:step-1")).thenReturn(stored.getValue());

        // A response the ceremony will not accept.
        assertThatThrownBy(() -> service.finishStepUpAssertion("step-1", JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class);

        // One challenge, one attempt. A challenge that outlived a refusal could be presented
        // again until its TTL ran out, which turns the short single-use window into a retry
        // window and makes a failed attempt free.
        verify(redisTemplate).delete("passkey:stepup:step-1");
    }

    @Test
    void aRefusedSignInAssertionBurnsItsChallengeToo() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        service.startAuthentication("login-1");
        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq("passkey:assertion:login-1"), stored.capture(), any());
        when(valueOperations.get("passkey:assertion:login-1")).thenReturn(stored.getValue());

        assertThatThrownBy(() -> service.finishAuthentication("login-1", JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class);

        // Sign-in keeps the lower user-verification bar, but single use is not a bar, it is
        // what a challenge is. Both ceremonies redeem through the same method and neither can
        // return or throw past the burn.
        verify(redisTemplate).delete("passkey:assertion:login-1");
    }

    @Test
    void theStepUpCeremonyIsUnavailableWhenPasskeysAreOff() {
        properties.getPasskeys().setEnabled(false);

        assertThatThrownBy(() -> service.startStepUpAssertion("step-1", USER))
                .isInstanceOf(LoginFlowException.class)
                .extracting(ex -> ((LoginFlowException) ex).getStatus())
                .isEqualTo(HttpStatus.NOT_FOUND);
    }

    // -------------------- the user-verification bar, on the assertion presented --------------------

    /**
     * The bar itself. It is the whole of what separates a step-up from a sign-in, and since
     * the reorder that lets a passkey settle a phone change alone it is also the only thing
     * standing between a bare possession assertion and a number that moves without the PIN
     * ever being asked for.
     */
    @Test
    void anAssertionThatOnlyProvedTheDeviceCannotSettleAStepUp() throws Exception {
        PasskeyService spy = spy(service);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("passkey:stepup:step-1")).thenReturn(STORED_CEREMONY);
        doReturn(assertion(false)).when(spy).runAssertion(anyString(), any());

        assertThatThrownBy(() -> spy.finishStepUpAssertion("step-1", JsonNodeFactory.instance.objectNode()))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    assertThat(((LoginFlowException) ex).getStatus()).isEqualTo(HttpStatus.FORBIDDEN);
                    assertThat(((LoginFlowException) ex).getCode()).isEqualTo("passkey_user_verification_required");
                });

        // Refused before the credential behind it is even looked up, so nothing downstream
        // gets the chance to treat a possession-only assertion as an accepted one.
        verify(repository, never()).findByCredentialId(anyString());
        verify(redisTemplate).delete("passkey:stepup:step-1");
    }

    /**
     * The same response, the opposite answer. Read together with the test above, this is what
     * says the bar is the step-up's and not the library's: one boolean on one assertion
     * decides it, and sign-in deliberately does not ask.
     */
    @Test
    void signInStillAcceptsTheVeryAssertionAStepUpRefuses() throws Exception {
        PasskeyService spy = spy(service);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("passkey:assertion:login-1")).thenReturn(STORED_CEREMONY);
        when(repository.findByCredentialId(CREDENTIAL_ID)).thenReturn(Optional.of(credential()));
        doReturn(assertion(false)).when(spy).runAssertion(anyString(), any());

        PasskeyService.PasskeyAuthentication auth =
                spy.finishAuthentication("login-1", JsonNodeFactory.instance.objectNode());

        assertThat(auth.userId()).isEqualTo(USER);
    }

    @Test
    void aUserVerifyingAssertionSettlesTheStepUpAndSaysHowOldItsCredentialIs() throws Exception {
        PasskeyService spy = spy(service);
        Instant registeredAt = Instant.now().minus(Duration.ofDays(30));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.get("passkey:stepup:step-1")).thenReturn(STORED_CEREMONY);
        when(repository.findByCredentialId(CREDENTIAL_ID)).thenReturn(Optional.of(credential(registeredAt)));
        doReturn(assertion(true)).when(spy).runAssertion(anyString(), any());

        PasskeyService.PasskeyAuthentication auth =
                spy.finishStepUpAssertion("step-1", JsonNodeFactory.instance.objectNode());

        assertThat(auth.userId()).isEqualTo(USER);
        // Carried out of the ceremony so a phone change can refuse a credential enrolled
        // minutes ago by whoever holds the session, the way it refuses a PIN of that age.
        assertThat(auth.credentialRegisteredAt()).isEqualTo(registeredAt);
    }

    /**
     * An assertion result with the user-verified flag set or clear. Lenient throughout: the
     * refusal path reads two of these and stops, the accepted path reads them all.
     */
    private AssertionResult assertion(boolean userVerified) {
        AssertionResult result = mock(AssertionResult.class);
        lenient().when(result.isSuccess()).thenReturn(true);
        lenient().when(result.isUserVerified()).thenReturn(userVerified);
        lenient().when(result.getCredentialId()).thenReturn(credentialIdBytes());
        lenient().when(result.getSignatureCount()).thenReturn(9L);
        lenient().when(result.isBackupEligible()).thenReturn(false);
        lenient().when(result.isBackedUp()).thenReturn(false);
        return result;
    }

    private ByteArray credentialIdBytes() {
        try {
            return ByteArray.fromBase64Url(CREDENTIAL_ID);
        } catch (Base64UrlException ex) {
            throw new IllegalStateException("Test credential id is not base64url", ex);
        }
    }

    private PasskeyCredential credential(Instant registeredAt) {
        PasskeyCredential credential = credential();
        credential.setCreatedAt(registeredAt);
        return credential;
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
