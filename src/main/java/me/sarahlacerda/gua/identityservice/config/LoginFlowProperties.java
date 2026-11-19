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
     * Where the browser is sent to render the login UI. A same-origin path (default {@code /signin})
     * keeps the login-session cookie first-party; an absolute URL is also accepted. Must not collide
     * with the {@code /login/*} API prefix.
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
     * In-app passkey enrollment handoff: a signed-in client opens a web view at a one-time enroll URL,
     * which drops the first-party login cookie and redirects into the {@code /signin} app.
     */
    @NotNull
    private Enroll enroll = new Enroll();

    @Getter
    @Setter
    public static class Enroll {
        /**
         * Default app redirect URI the enrollment session returns to when the caller names none
         * (the OIDC app scheme, e.g. {@code global.gua:/oidc}).
         */
        @NotBlank
        private String redirectUri = "global.gua:/oidc";

        /**
         * Enrollment redirects a caller may name ({@code IDP_LOGIN_ENROLL_REDIRECT_URIS}, comma
         * separated). Each app build answers its own scheme and the bearer token does not identify
         * the build, so the caller supplies the value and this list bounds it. Values are compared
         * exactly; anything else is refused with {@code invalid_redirect_uri}. Unset means the
         * allowlist is exactly {@link #redirectUri}.
         */
        private List<String> redirectUris = new ArrayList<>();

        /**
         * How long a one-time enroll token (mapping to the login session) stays
         * redeemable. Kept short: it is consumed immediately when the web view opens.
         */
        @NotNull
        private Duration tokenTtl = Duration.ofMinutes(2);

        /**
         * The redirects a caller may name: {@link #redirectUris} when configured, otherwise the
         * single {@link #redirectUri}. Blank entries are dropped, so an empty environment variable
         * equals an absent one.
         */
        public List<String> allowedRedirectUris() {
            List<String> configured = redirectUris.stream()
                    .map(String::trim)
                    .filter(entry -> !entry.isEmpty())
                    .toList();
            return configured.isEmpty() ? List.of(redirectUri) : configured;
        }
    }

    /**
     * Gate for the web login surface (see {@code RegistrationGuard}). It stops an internet-exposed
     * deployment from being used to burn SMS credits or self-register accounts. Native app flows and
     * returning users are never affected.
     */
    @NotNull
    private Registration registration = new Registration();

    @Getter
    @Setter
    public static class Registration {
        /**
         * Master switch. When {@code true}, a web flow may trigger an OTP or create an account only
         * for a phone that already has an account or is listed in {@link #webAllowlist}. Unknown web
         * numbers are refused before any SMS is sent. Off by default.
         */
        private boolean webAllowlistEnabled = false;

        /**
         * E.164 numbers permitted to start a new web signup while {@link #webAllowlistEnabled} is on.
         * Numbers that already have an account need no entry. Entries are normalized before
         * comparison, so one lacking a country code uses the default region.
         */
        private List<String> webAllowlist = new ArrayList<>();

        /**
         * Value of the forwarded client marker that identifies a native app flow. Only an exact match
         * is exempt from the gate; an absent or different value is treated as web. The marker is
         * client-asserted, so the exemption is a convenience, not a security boundary.
         */
        @NotBlank
        private String nativeClientMarker = "native";
    }

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

        /** Browser-side operation timeout in milliseconds. */
        private long timeoutMillis = 60_000L;
    }
}
