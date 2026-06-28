package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

@ExtendWith(MockitoExtension.class)
class ChangeNumberSecurityNotifierTest {

    private static final String USER_ID = "@alice:gua.global";
    private static final String NEW_PHONE = "+12025550199";
    private static final String MASKED_NEW_PHONE = "••••0199";
    private static final String IP = "1.2.3.4";
    private static final long COOLDOWN = 3600L;
    private static final String DEDUP_KEY = "change:phone:cooldown:notify:" + USER_ID;

    @Mock
    private MatrixAdminClient matrixAdminClient;
    @Mock
    private SecurityAuditLogger auditLogger;
    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOps;

    private ChangeNumberSecurityNotifier notifier;

    @BeforeEach
    void setUp() {
        notifier = new ChangeNumberSecurityNotifier(matrixAdminClient, auditLogger, redisTemplate,
                new PhoneNumberMasker());
    }

    @Test
    void auditsAndSendsNoticeOnFirstBlockWithinWindow() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(eq(DEDUP_KEY), eq("1"), eq(Duration.ofHours(1)))).thenReturn(Boolean.TRUE);

        notifier.onChangeBlockedByCooldown(USER_ID, NEW_PHONE, COOLDOWN, IP);

        verify(auditLogger).phoneChangeCooldownBlocked(USER_ID, MASKED_NEW_PHONE, COOLDOWN, IP);

        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(matrixAdminClient).sendServerNotice(eq(USER_ID), body.capture());
        // The device notice must carry only the masked number — never the plaintext E.164.
        assertThat(body.getValue()).contains(MASKED_NEW_PHONE);
        assertThat(body.getValue()).doesNotContain(NEW_PHONE);
    }

    @Test
    void auditsEveryCallButDedupesDeviceNoticeWithinWindow() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(eq(DEDUP_KEY), eq("1"), eq(Duration.ofHours(1))))
                .thenReturn(Boolean.TRUE)
                .thenReturn(Boolean.FALSE);

        notifier.onChangeBlockedByCooldown(USER_ID, NEW_PHONE, COOLDOWN, IP);
        notifier.onChangeBlockedByCooldown(USER_ID, NEW_PHONE, COOLDOWN, IP);

        // Audit fires on EVERY blocked retry...
        verify(auditLogger, org.mockito.Mockito.times(2))
                .phoneChangeCooldownBlocked(USER_ID, MASKED_NEW_PHONE, COOLDOWN, IP);
        // ...but the device notice is sent only once within the dedup window.
        verify(matrixAdminClient, org.mockito.Mockito.times(1)).sendServerNotice(eq(USER_ID), anyString());
    }

    @Test
    void failsSafeWhenAdminClientThrows() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(eq(DEDUP_KEY), eq("1"), eq(Duration.ofHours(1)))).thenReturn(Boolean.TRUE);
        doThrow(new RuntimeException("synapse down")).when(matrixAdminClient)
                .sendServerNotice(anyString(), anyString());

        // Must not propagate — the cooldown block must never be broken by a notify failure.
        assertThatCode(() -> notifier.onChangeBlockedByCooldown(USER_ID, NEW_PHONE, COOLDOWN, IP))
                .doesNotThrowAnyException();

        // The audit still happened before the throw.
        verify(auditLogger).phoneChangeCooldownBlocked(USER_ID, MASKED_NEW_PHONE, COOLDOWN, IP);
    }

    @Test
    void failsSafeWhenRedisThrows() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("redis down"));

        assertThatCode(() -> notifier.onChangeBlockedByCooldown(USER_ID, NEW_PHONE, COOLDOWN, IP))
                .doesNotThrowAnyException();

        verify(matrixAdminClient, never()).sendServerNotice(anyString(), anyString());
    }
}
