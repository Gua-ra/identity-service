package me.sarahlacerda.gua.identityservice.service.routing;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.crypto.Ed25519;

/**
 * Publishes this homeserver's accounts into the gua-resolver shared directory (POST /directory/entries).
 *
 * <p><b>Scheduled for removal: this is the mechanism <a href="https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md">ADM-001</a> L1b removes.</b> The
 * resolver endpoint it targets is being deleted, not deprecated, and the verifier-attested identifier binding
 * of ADM-001 (L7, L8) replaces it. Do not add callers. The class stays until the resolver deletion lands so
 * the existing wiring keeps compiling.
 *
 * <p>Current behaviour: the write is signed with this homeserver's Ed25519 roster signing key, which
 * identifies the writing member and nothing more; the resolver does not check that the account is hosted
 * here. Best-effort: a resolver outage never blocks sign-up/sign-in, and this service reads its own local
 * directory for its own users. Disabled cleanly when unconfigured.
 */
@Component
public class ResolverDirectoryClient {

    private static final Logger log = LoggerFactory.getLogger(ResolverDirectoryClient.class);

    private final boolean enabled;
    private final String homeserverId;
    private final PrivateKey signingKey;
    private final RestClient http;

    public ResolverDirectoryClient(IdentityServiceProperties props) {
        IdentityServiceProperties.ResolverProperties r = props.getResolver();
        this.enabled = r != null
                && StringUtils.hasText(r.getBaseUrl())
                && StringUtils.hasText(r.getHomeserverId())
                && StringUtils.hasText(r.getSigningPrivateKey());
        this.homeserverId = enabled ? r.getHomeserverId() : null;
        this.signingKey = enabled ? Ed25519.privateKey(r.getSigningPrivateKey()) : null;
        this.http = enabled ? RestClient.builder().baseUrl(r.getBaseUrl()).build() : null;
        log.info("Resolver shared-directory publishing {}", enabled ? "enabled (hs=" + homeserverId + ")" : "disabled");
    }

    /** Register (or refresh) phone (E.164) -&gt; this homeserver in the shared directory. Never throws. */
    public void registerPhone(String e164Phone) {
        if (!enabled) {
            return;
        }
        try {
            // Canonical string MUST match the resolver's DirectoryController (username omitted -> trailing "|").
            String canonical = "directory-write.v1|" + homeserverId + "|" + e164Phone + "|";
            String signature = Ed25519.sign(signingKey, canonical.getBytes(StandardCharsets.UTF_8));
            http.post().uri("/directory/entries")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("homeserverId", homeserverId, "e164Phone", e164Phone, "signature", signature))
                    .retrieve()
                    .toBodilessEntity();
            log.debug("Published phone -> {} in the shared resolver directory", homeserverId);
        } catch (Exception e) {
            // Non-fatal: the account is already created locally; resolver will catch up on the next write.
            log.warn("Could not publish to the shared resolver directory (continuing): {}", e.getMessage());
        }
    }

    /**
     * Sends DELETE /directory/entries for a phone (E.164) -&gt; this homeserver mapping
     * when an account's number changes. The resolver does not implement that mapping
     * today, so the old number is not unpublished at the federation layer; the failure
     * is logged and swallowed. Best-effort and never throws, like
     * {@link #registerPhone(String)}. Part of the path ADM-001 L1b removes.
     */
    public void unregisterPhone(String e164Phone) {
        if (!enabled) {
            return;
        }
        try {
            // Same canonical-string + signing scheme as registerPhone so the resolver
            // can authenticate the delete as coming from the hosting homeserver.
            String canonical = "directory-delete.v1|" + homeserverId + "|" + e164Phone + "|";
            String signature = Ed25519.sign(signingKey, canonical.getBytes(StandardCharsets.UTF_8));
            http.method(org.springframework.http.HttpMethod.DELETE).uri("/directory/entries")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("homeserverId", homeserverId, "e164Phone", e164Phone, "signature", signature))
                    .retrieve()
                    .toBodilessEntity();
            log.debug("Unpublished phone (old number) from the shared resolver directory for hs={}", homeserverId);
        } catch (Exception e) {
            // Non-fatal: never block the local swap on a resolver failure.
            log.warn("Could not unpublish from the shared resolver directory (continuing): {}", e.getMessage());
        }
    }
}
