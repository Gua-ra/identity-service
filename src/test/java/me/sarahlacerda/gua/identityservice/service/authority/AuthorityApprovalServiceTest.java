// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.exception.AuthorityTransitionException;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts.Resolved;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The approval a browser session starts, and the one thing it may not choose about it.
 *
 * <p>The device shows the reader what the action is, from the action id, and signs over the action digest. Two
 * caller-chosen values related the sentence and the signed bytes by nothing at all, so the digest is derived
 * here from the named action. Nothing can spend such a signature today, which is exactly why this is the
 * cheapest moment to hold the invariant.
 */
class AuthorityApprovalServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-23T12:00:00Z");

    private StringRedisTemplate redis;
    private ValueOperations<String, String> values;
    private SetOperations<String, String> sets;
    private AuthorityApprovalService approvals;
    private Resolved account;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redis = mock(StringRedisTemplate.class);
        values = mock(ValueOperations.class);
        sets = mock(SetOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(redis.opsForSet()).thenReturn(sets);
        when(sets.members(anyString())).thenReturn(null);

        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        AuthorityPolicy policy = new AuthorityPolicy(properties, mock(UserSecurityService.class));
        approvals = new AuthorityApprovalService(redis, policy, mock(AuthorityDeviceRepository.class));

        AccountId id = AccountId.derive(AccountId.CLASS_BOOTSTRAP, "entropy".getBytes(StandardCharsets.UTF_8));
        account = new Resolved("@sarah:gua.global", id.value(), id.rawBytes(), id.rootClass(),
                id.isGenesisRooted(), null, null);
    }

    @Test
    void theDigestTheDeviceSignsIsDerivedFromTheActionRatherThanChosenBesideIt() {
        AuthorityApprovalService.Started started = approvals.start(account, "revoke-device:iPad", NOW);

        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(values).set(anyString(), stored.capture(), any(Duration.class));
        String[] parts = stored.getValue().split("\\|", 7);

        assertThat(parts[3]).isEqualTo("revoke-device:iPad");
        assertThat(parts[4]).isEqualTo(canonicalDigest("revoke-device:iPad"));
        assertThat(started.approvalId()).isNotBlank();
        assertThat(started.code()).hasSize(4);
    }

    @Test
    void anApprovalWithNoActionIsRefusedRatherThanCarryingADigestOfNothing() {
        // The device's sentence comes from the action id. An approval with none has nothing to describe, and a
        // digest beside it would be a signature over bytes with no stated meaning.
        for (String action : new String[] { null, "", "   " }) {
            AuthorityTransitionException refusal = catchThrowableOfType(
                    () -> approvals.start(account, action, NOW), AuthorityTransitionException.class);
            assertThat(refusal).as("action [%s]", action).isNotNull();
            assertThat(refusal.getCode()).isEqualTo("authority_approval_invalid");
        }
    }

    private static String canonicalDigest(String action) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(action.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new AssertionError(ex);
        }
    }
}
