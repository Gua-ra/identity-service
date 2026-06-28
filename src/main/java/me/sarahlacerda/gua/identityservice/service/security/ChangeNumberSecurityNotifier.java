package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.security.audit.SecurityAuditLogger;

/**
 * Security response for change-number requests that are blocked by the
 * fresh-2FA (post-PIN-write) cooldown.
 *
 * <p>
 * Two channels, deliberately decoupled:
 * <ul>
 * <li><b>Audit</b> — fires on <em>every</em> blocked attempt so support sees the
 * full retry trail in Loki. Phones are always masked; the userId is safe to
 * log.</li>
 * <li><b>Device server notice</b> — a Synapse server notice that syncs to all of
 * the user's connected clients ("notify every device"). De-duplicated per user
 * for an hour so a retry loop can't spam the user's devices.</li>
 * </ul>
 *
 * <p>
 * The whole entry point is fail-safe: a notification problem must never break
 * the security control (the cooldown block) that triggered it. We never recover,
 * store, or send the user's <em>old</em> number (it is hash-only) and we never put
 * a plaintext E.164 into an audit field or a device notice — only the masked new
 * number.
 */
@Service
@RequiredArgsConstructor
public class ChangeNumberSecurityNotifier {

    private static final Logger log = LoggerFactory.getLogger(ChangeNumberSecurityNotifier.class);

    /** Per-user dedup key for the device server notice; value is meaningless, TTL is the dedup window. */
    private static final String NOTICE_DEDUP_KEY_PREFIX = "change:phone:cooldown:notify:";
    private static final Duration NOTICE_DEDUP_TTL = Duration.ofHours(1);

    private final MatrixAdminClient matrixAdminClient;
    private final SecurityAuditLogger auditLogger;
    private final StringRedisTemplate redisTemplate;
    private final PhoneNumberMasker phoneNumberMasker;

    /**
     * Records and (once per dedup window) notifies on a change-number request that
     * was rejected by the fresh-2FA cooldown.
     *
     * @param userId           the account whose number a change was requested for
     * @param newPhone         the requested new number in E.164 (masked before use; never logged/sent raw)
     * @param cooldownSeconds  seconds remaining on the cooldown
     * @param ip               requester IP, for the audit trail
     */
    public void onChangeBlockedByCooldown(String userId, String newPhone, long cooldownSeconds, String ip) {
        // Fail-safe: notification is a side-channel and must never break the cooldown block.
        try {
            String maskedNewPhone = phoneNumberMasker.mask(newPhone);

            // Always audit — support needs to see every blocked retry.
            auditLogger.phoneChangeCooldownBlocked(userId, maskedNewPhone, cooldownSeconds, ip);

            // Dedup the device-facing notice so a retry loop doesn't spam every device.
            Boolean firstThisWindow = redisTemplate.opsForValue()
                    .setIfAbsent(NOTICE_DEDUP_KEY_PREFIX + userId, "1", NOTICE_DEDUP_TTL);
            if (Boolean.TRUE.equals(firstThisWindow)) {
                String body = "Security alert: someone asked to change your Gua number to " + maskedNewPhone
                        + ". For your protection this is on hold because your PIN was changed recently."
                        + " If this wasn't you, secure your account now.";
                matrixAdminClient.sendServerNotice(userId, body);
            }
        } catch (Exception ex) {
            log.warn("Change-number cooldown notification failed for user {}: {}", userId, ex.getMessage());
        }
    }
}
