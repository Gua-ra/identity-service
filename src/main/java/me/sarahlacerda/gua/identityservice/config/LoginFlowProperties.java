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
     * Settings for the in-app passkey enrollment handoff: an already-signed-in
     * client opens an authenticated web view at a one-time enroll URL, which drops
     * the first-party login cookie and redirects into the same {@code /signin} SPA
     * onboarding uses to render the passkey setup step.
     */
    @NotNull
    private Enroll enroll = new Enroll();

    @Getter
    @Setter
    public static class Enroll {
        /**
         * App redirect URI the enrollment {@link LoginSession} echoes back when the
         * passkey ceremony completes (the OIDC app scheme, e.g. {@code global.gua:/oidc}).
         * It is never reached as an open login because the session is pinned to the
         * authenticated subject via {@code reauthUserId}.
         */
        @NotBlank
        private String redirectUri = "global.gua:/oidc";

        /**
         * How long a one-time enroll token (mapping to the login session) stays
         * redeemable. Kept short: it is consumed immediately when the web view opens.
         */
        @NotNull
        private Duration tokenTtl = Duration.ofMinutes(2);
    }

    /**
     * New-account registration controls. Used to gate web signups behind an
     * allowlist during a limited/invite-only rollout; native (app) signups and
     * existing-user logins are never affected.
     */
    @NotNull
    private Registration registration = new Registration();

    @Getter
    @Setter
    public static class Registration {
        /**
         * When {@code true}, a brand-new account created through the web client may
         * only be provisioned if its phone number is in {@link #webAllowlist}. Kept
         * {@code false} by default so the guard is inert until deliberately enabled.
         */
        private boolean webAllowlistEnabled = false;

        /**
         * Phone numbers (E.164) permitted to create a new web account while
         * {@link #webAllowlistEnabled} is on. Normalized before comparison, so entries
         * lacking a country code are interpreted against the default region.
         */
        private List<String> webAllowlist = new ArrayList<>();

        /**
         * Value of the forwarded downstream-client marker that identifies the web
         * client. A session whose downstream marker equals this (or is absent, which
         * fails closed) is treated as a web signup and subject to the allowlist.
         */
        @NotBlank
        private String webClientMarker = "web";
    }

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
