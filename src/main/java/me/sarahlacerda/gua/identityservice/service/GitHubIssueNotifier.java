package me.sarahlacerda.gua.identityservice.service;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.PublicProperties.GitHubProperties;

/**
 * Notifies the operator of a new public submission by opening an issue in a
 * configured private GitHub inbox repo (free, no email provider needed). The
 * operator triages the submission directly on GitHub.
 *
 * <p>Best-effort by design: a GitHub outage or misconfiguration must never lose
 * a submission. The caller persists first; this notifier never throws — failures
 * are logged and swallowed. Disabled cleanly when the repo/token are unconfigured.
 */
@Component
public class GitHubIssueNotifier {

    private static final Logger log = LoggerFactory.getLogger(GitHubIssueNotifier.class);

    private final boolean enabled;
    private final String inboxRepo;
    private final String token;
    private final RestClient http;

    public GitHubIssueNotifier(IdentityServiceProperties properties) {
        GitHubProperties gh = properties.getPublicForms().getGithub();
        this.enabled = StringUtils.hasText(gh.getInboxRepo()) && StringUtils.hasText(gh.getToken());
        this.inboxRepo = gh.getInboxRepo();
        this.token = gh.getToken();
        this.http = enabled ? RestClient.builder().baseUrl(gh.getApiBaseUrl()).build() : null;
        log.info("GitHub inbox notification {}", enabled ? "enabled (repo=" + inboxRepo + ")" : "disabled");
    }

    /**
     * Opens an issue with the given title/body. Never throws.
     *
     * @return true when an issue was created, false when disabled or the call failed
     */
    public boolean createIssue(String title, String body) {
        if (!enabled) {
            log.debug("GitHub notification disabled; skipping issue creation");
            return false;
        }
        try {
            http.post()
                    .uri("/repos/{repo}/issues", inboxRepo)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("title", title, "body", body))
                    .retrieve()
                    .toBodilessEntity();
            return true;
        } catch (Exception e) {
            // Non-fatal: the submission is already persisted; this is only the notification.
            log.error("Could not open GitHub inbox issue (submission already persisted): {}", e.getMessage());
            return false;
        }
    }
}
