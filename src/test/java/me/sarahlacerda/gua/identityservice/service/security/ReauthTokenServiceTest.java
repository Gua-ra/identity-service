package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.exception.InvalidReauthTokenException;

@ExtendWith(MockitoExtension.class)
class ReauthTokenServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    private ReauthTokenService service;

    @BeforeEach
    void setUp() {
        service = new ReauthTokenService(redisTemplate);
    }

    @Test
    void issueStoresUserIdUnderTokenKey() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        String token = service.issue("@alice:server");

        assertThat(token).isNotBlank();
    }

    @Test
    void consumeReturnsBoundUserIdAndDeletesToken() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.getAndDelete("reauth:token:abc")).thenReturn("@alice:server");

        String userId = service.consume("abc", "@alice:server");

        assertThat(userId).isEqualTo("@alice:server");
    }

    @Test
    void consumeRejectsBlankToken() {
        assertThatThrownBy(() -> service.consume("", "@alice:server"))
                .isInstanceOf(InvalidReauthTokenException.class);
    }

    @Test
    void consumeRejectsExpiredToken() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.getAndDelete("reauth:token:abc")).thenReturn(null);

        assertThatThrownBy(() -> service.consume("abc", "@alice:server"))
                .isInstanceOf(InvalidReauthTokenException.class);
    }

    @Test
    void consumeRejectsMismatchedUser() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.getAndDelete("reauth:token:abc")).thenReturn("@bob:server");

        assertThatThrownBy(() -> service.consume("abc", "@alice:server"))
                .isInstanceOf(InvalidReauthTokenException.class);
    }
}
