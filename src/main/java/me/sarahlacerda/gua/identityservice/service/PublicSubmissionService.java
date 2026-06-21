package me.sarahlacerda.gua.identityservice.service;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.PublicSubmission;
import me.sarahlacerda.gua.identityservice.repository.PublicSubmissionRepository;

/**
 * Persists public web-form submissions (support requests + beta sign-ups) and
 * notifies the operator out-of-band via a GitHub issue. Persistence is the source
 * of truth: the GitHub notification is best-effort and never blocks or rolls back
 * a stored submission.
 */
@Service
public class PublicSubmissionService {

    private static final Logger log = LoggerFactory.getLogger(PublicSubmissionService.class);
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final PublicSubmissionRepository repository;
    private final GitHubIssueNotifier gitHubIssueNotifier;
    private final ThreadLocal<Mac> macSupplier;

    public PublicSubmissionService(PublicSubmissionRepository repository,
            GitHubIssueNotifier gitHubIssueNotifier,
            IdentityServiceProperties properties) {
        this.repository = repository;
        this.gitHubIssueNotifier = gitHubIssueNotifier;
        // Reuse the directory pepper as the HMAC key so the IP digest is non-reversible
        // and consistent with the rest of the service. The raw IP is never stored.
        this.macSupplier = ThreadLocal.withInitial(() -> createMac(properties.getDirectory().getPepper()));
    }

    /** Records a support request, then opens a GitHub issue (best-effort). */
    public void recordSupport(String name, String email, String message, String sourceIp) {
        String normalizedEmail = normalizeEmail(email);
        PublicSubmission submission = PublicSubmission.builder()
                .type(PublicSubmission.Type.SUPPORT)
                .name(normalizeText(name))
                .email(normalizedEmail)
                .message(normalizeText(message))
                .sourceIpHash(hashIp(sourceIp))
                .build();
        repository.save(submission);

        String title = "[support] from " + normalizedEmail;
        String body = "**Name:** " + nullSafe(submission.getName()) + "\n"
                + "**Email:** " + normalizedEmail + "\n\n"
                + "**Message:**\n\n" + nullSafe(submission.getMessage());
        notify(title, body);
    }

    /** Records a beta-access sign-up, then opens a GitHub issue (best-effort). */
    public void recordBetaSignup(String email, String platform, String sourceIp) {
        String normalizedEmail = normalizeEmail(email);
        String normalizedPlatform = normalizePlatform(platform);
        PublicSubmission submission = PublicSubmission.builder()
                .type(PublicSubmission.Type.BETA)
                .email(normalizedEmail)
                .platform(normalizedPlatform)
                .sourceIpHash(hashIp(sourceIp))
                .build();
        repository.save(submission);

        String title = "[beta] " + normalizedEmail + " (" + normalizedPlatform + ")";
        String body = "**Email:** " + normalizedEmail + "\n"
                + "**Platform:** " + normalizedPlatform;
        notify(title, body);
    }

    private void notify(String title, String body) {
        try {
            gitHubIssueNotifier.createIssue(title, body);
        } catch (Exception e) {
            // GitHubIssueNotifier already swallows its own errors; this is belt-and-suspenders
            // so a notification problem can never undo the persisted submission.
            log.error("GitHub notification failed after persisting submission: {}", e.getMessage());
        }
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizePlatform(String platform) {
        return platform == null ? null : platform.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeText(String value) {
        return value == null ? null : value.trim();
    }

    private static String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private String hashIp(String sourceIp) {
        if (!StringUtils.hasText(sourceIp)) {
            return null;
        }
        Mac mac = macSupplier.get();
        mac.reset();
        mac.update(sourceIp.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(mac.doFinal());
    }

    private static Mac createMac(String pepper) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            return mac;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to initialize submission IP hasher", ex);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
