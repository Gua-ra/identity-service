package me.sarahlacerda.gua.identityservice.service.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;

/**
 * The login session is stored as JSON in Redis and survives deployments, so a
 * field added to it must read back sensibly from payloads written before it
 * existed, and payloads written by a newer build must not break an older one.
 */
@ExtendWith(MockitoExtension.class)
class LoginSessionServiceTest {

    private static final String KEY = "oidc:login:sid-1";

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private LoginFlowProperties properties;

    private LoginSessionService service;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        service = new LoginSessionService(redisTemplate, new ObjectMapper(), properties);
    }

    @Test
    void sessionPersistedBeforeIntentExistedReadsBackAsPhoneLogin() {
        when(valueOperations.get(KEY)).thenReturn(
                "{\"clientId\":\"mas\",\"phase\":\"OTP_SENT\",\"phoneNumber\":\"+15551234567\",\"csrfToken\":\"c\"}");

        LoginSession session = service.find("sid-1").orElseThrow();

        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PHONE);
        assertThat(session.getPhase()).isEqualTo(LoginSession.Phase.OTP_SENT);
        assertThat(session.getPhoneNumber()).isEqualTo("+15551234567");
    }

    @Test
    void explicitNullIntentReadsBackAsPhoneLogin() {
        when(valueOperations.get(KEY)).thenReturn("{\"phase\":\"PHONE\",\"intent\":null}");

        assertThat(service.find("sid-1").orElseThrow().getIntent()).isEqualTo(LoginSession.Intent.PHONE);
    }

    @Test
    void unknownFieldsFromANewerBuildAreIgnored() {
        when(valueOperations.get(KEY)).thenReturn("{\"phase\":\"PHONE\",\"intent\":\"PASSKEY\",\"futureField\":1}");

        LoginSession session = service.find("sid-1").orElseThrow();

        assertThat(session.getIntent()).isEqualTo(LoginSession.Intent.PASSKEY);
        assertThat(session.getPhase()).isEqualTo(LoginSession.Phase.PHONE);
    }

    @Test
    void passkeyIntentRoundTripsThroughRedis() {
        when(properties.getSessionTtl()).thenReturn(Duration.ofMinutes(10));
        LoginSession session = new LoginSession();
        session.setPhase(LoginSession.Phase.PHONE);
        session.setIntent(LoginSession.Intent.PASSKEY);

        service.save("sid-1", session);

        ArgumentCaptor<String> payload = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq(KEY), payload.capture(), eq(Duration.ofMinutes(10)));
        assertThat(payload.getValue()).contains("\"intent\":\"PASSKEY\"");

        when(valueOperations.get(KEY)).thenReturn(payload.getValue());
        assertThat(service.find("sid-1").orElseThrow().getIntent()).isEqualTo(LoginSession.Intent.PASSKEY);
    }
}
