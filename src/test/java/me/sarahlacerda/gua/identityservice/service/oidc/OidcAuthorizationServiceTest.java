package me.sarahlacerda.gua.identityservice.service.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

/** The recovery marker survives the trip through the stored authorization code. */
class OidcAuthorizationServiceTest {

    private final Map<String, String> redis = new HashMap<>();
    private OidcAuthorizationService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        StringRedisTemplate template = mock(StringRedisTemplate.class);
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(template.opsForValue()).thenReturn(values);
        doAnswer(call -> redis.put(call.getArgument(0), call.getArgument(1)))
                .when(values).set(anyString(), anyString(), any(java.time.Duration.class));
        when(values.get(anyString())).thenAnswer(call -> redis.get(call.<String>getArgument(0)));
        when(template.delete(anyString())).thenAnswer(call -> redis.remove(call.<String>getArgument(0)) != null);
        service = new OidcAuthorizationService(template, new ObjectMapper(), new OidcProperties());
    }

    private OidcAuthorization authorization(boolean endOtherSessions) {
        return new OidcAuthorization("@alice:gua.global", "+15551234567", "Alice", "alice", Set.of("openid"),
                "mas", "nonce-1", endOtherSessions);
    }

    @Test
    void aRecoveryAuthorizationKeepsItsMarkerThroughTheCode() {
        String code = service.issueCode(authorization(true), "https://mas.example/callback", null).code();

        assertThat(service.consumeAuthorizationCode(code)).get()
                .extracting(stored -> stored.authorization().endOtherSessions())
                .isEqualTo(true);
    }

    @Test
    void anOrdinaryAuthorizationComesBackWithoutIt() {
        String code = service.issueCode(authorization(false), "https://mas.example/callback", null).code();

        assertThat(service.consumeAuthorizationCode(code)).get()
                .extracting(stored -> stored.authorization().endOtherSessions())
                .isEqualTo(false);
    }

    /** A code stored by the previous release has no such field, and is never a recovery. */
    @Test
    void aCodeStoredBeforeTheFieldExistedIsNotARecovery() {
        redis.put("oidc:code:legacy", "{\"userId\":\"@alice:gua.global\",\"phoneNumber\":\"+15551234567\","
                + "\"displayName\":\"Alice\",\"preferredUsername\":\"alice\",\"scope\":[\"openid\"],"
                + "\"clientId\":\"mas\",\"nonce\":\"nonce-1\",\"redirectUri\":\"https://mas.example/callback\","
                + "\"codeChallenge\":null}");

        assertThat(service.consumeAuthorizationCode("legacy")).get()
                .extracting(stored -> stored.authorization().endOtherSessions())
                .isEqualTo(false);
    }
}
