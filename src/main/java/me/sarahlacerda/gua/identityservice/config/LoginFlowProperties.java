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
     * Beta-rollout gate for the web login surface (see {@code RegistrationGuard}).
     * Used to stop an internet-exposed deployment from being used to burn SMS credits
     * or self-register open accounts; native (app) flows and every returning user are
     * never affected. The whole gate is one flag flip ({@link Registration#webAllowlistEnabled})
     * away from the fully-open behaviour.
     */
    @NotNull
    private Registration registration = new Registration();

    @Getter
    @Setter
    public static class Registration {
        /**
         * Master switch for the beta gate. When {@code true}, a web flow may only (a)
         * trigger an OTP and (b) create a brand-new account for a phone that already
         * has an account or is listed in {@link #webAllowlist}; unknown web numbers are
         * refused before any SMS is sent. Kept {@code false} by default so the gate is
         * inert until deliberately enabled, and flipping it back off restores the fully
         * open flow with no code change.
         */
        private boolean webAllowlistEnabled = false;

        /**
         * Phone numbers (E.164) permitted to start a new web signup while
         * {@link #webAllowlistEnabled} is on. Numbers that already have an account do
         * not need to be listed — they are recognised automatically, which is how an
         * app-registered number can also log in on the web. Normalized before
         * comparison, so entries lacking a country code use the default region.
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
