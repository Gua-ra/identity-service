package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration for the interactive, browser-based OIDC login flow that MAS
 * redirects into. The login UI itself is served by the {@code gua-idp-web}
 * single-page app; this service drives the flow and issues the authorization
 * code once the user has been authenticated.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "idp.login")
public class LoginFlowProperties {

    /**
     * Where the browser is redirected to render the interactive login UI. A
     * same-origin path (default {@code /signin}) keeps the login-session cookie
     * first-party; an absolute URL is also accepted. Must not collide with the
     * {@code /login/*} API prefix.
     */
    @NotBlank
    private String uiUrl = "/signin";

    /** How long an in-progress login session lives before it must be restarted. */
    @NotNull
    private Duration sessionTtl = Duration.ofMinutes(10);

    /** Name of the opaque, HttpOnly login-session cookie. */
    @NotBlank
    private String cookieName = "gua_login";

    /**
     * Whether the session cookie carries the {@code Secure} attribute. Keep this
     * {@code true} everywhere except plain-HTTP local development.
     */
    private boolean cookieSecure = true;

    /**
     * Passkey / WebAuthn settings for the browser login flow.
     */
    @NotNull
    private Passkeys passkeys = new Passkeys();

    @Getter
    @Setter
    public static class Passkeys {
        /**
         * Enables the passkey ceremony endpoints. The UI still feature-detects browser
         * support before showing passkey actions.
         */
        private boolean enabled = true;

        /**
         * WebAuthn relying-party id. Local development uses {@code localhost}; prod
         * should use the registrable Gua auth domain.
         */
        @NotBlank
        private String rpId = "localhost";

        @NotBlank
        private String rpName = "Gua";

        /**
         * Browser origins allowed to complete WebAuthn ceremonies. Include the Vite
         * dev origin and identity-service origin locally; set this to the HTTPS auth
         * origin in production.
         */
        private List<String> origins = new ArrayList<>(List.of("http://localhost:5173", "http://localhost:8080"));

        @NotNull
        private Duration challengeTtl = Duration.ofMinutes(5);

        /**
         * Browser-side operation timeout in milliseconds.
         */
        private long timeoutMillis = 60_000L;
    }
}
