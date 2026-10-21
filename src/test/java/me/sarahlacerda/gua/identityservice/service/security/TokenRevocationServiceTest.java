package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.config.OidcProperties;

/** The revoke-before cutoff expires, and never before the last token it can refuse has expired. */
class TokenRevocationServiceTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> values;
    private OidcProperties properties;
    private TokenRevocationService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        values = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(values);
        properties = new OidcProperties();
        service = new TokenRevocationService(redisTemplate, properties);
    }

    @Test
    void theCutoffIsWrittenWithAnHourToLiveForTheDefaultTokenLifetime() {
        long before = Instant.now().getEpochSecond();

        service.revokeAllTokens("@alice:example.com");

        ArgumentCaptor<String> cutoff = ArgumentCaptor.forClass(String.class);
        verify(values).set(eq("oidc:revoke-before:@alice:example.com"), cutoff.capture(), eq(Duration.ofHours(1)));
        assertThat(Long.parseLong(cutoff.getValue())).isBetween(before, Instant.now().getEpochSecond());
    }

    @Test
    void theCutoffOutlivesALongerAccessTokenLifetime() {
        properties.setAccessTokenTtl(Duration.ofHours(2));

        service.revokeAllTokens("@alice:example.com");

        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(values).set(anyString(), anyString(), ttl.capture());
        assertThat(ttl.getValue()).isGreaterThan(Duration.ofHours(2));
    }

    /** A token minted in the same second as the deletion must not survive it. */
    @Test
    void aDeletedAccountLosesEvenATokenIssuedInTheCurrentSecond() {
        long now = Instant.now().getEpochSecond();

        service.revokeAllTokensOfDeletedAccount("@alice:example.com");

        ArgumentCaptor<String> cutoff = ArgumentCaptor.forClass(String.class);
        verify(values).set(eq("oidc:revoke-before:@alice:example.com"), cutoff.capture(), eq(Duration.ofHours(1)));
        when(values.get("oidc:revoke-before:@alice:example.com")).thenReturn(cutoff.getValue());
        assertThat(service.isRevoked("@alice:example.com", Instant.ofEpochSecond(now))).isTrue();
    }

    @Test
    void aTokenIssuedBeforeTheCutoffIsRevokedAndOneIssuedAfterIsNot() {
        when(values.get("oidc:revoke-before:@alice:example.com")).thenReturn("1000");

        assertThat(service.isRevoked("@alice:example.com", Instant.ofEpochSecond(999))).isTrue();
        assertThat(service.isRevoked("@alice:example.com", Instant.ofEpochSecond(1000))).isFalse();
        assertThat(service.isRevoked("@bob:example.com", Instant.ofEpochSecond(1))).isFalse();
    }
}
