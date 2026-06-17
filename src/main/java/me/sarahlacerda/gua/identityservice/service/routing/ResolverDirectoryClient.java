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
 * Publishes this homeserver's accounts into the gua-resolver's <b>shared</b> phone-&gt;homeserver directory
 * (POST /directory/entries), so the global federation front door can route an existing phone to us. The
 * write is authenticated with this homeserver's membership credential (its Ed25519 roster signing key), so
 * the resolver only accepts entries for accounts we host.
 *
 * <p>Best-effort by design: a resolver outage must never block sign-up/sign-in (the local directory remains
 * the source of truth for our own users). Disabled cleanly when unconfigured.
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
}
