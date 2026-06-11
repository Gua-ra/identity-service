package me.sarahlacerda.gua.identityservice.config;

import java.time.Duration;

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
     * same-origin path (default {@code /login}) keeps the login-session cookie
     * first-party; an absolute URL is also accepted.
     */
    @NotBlank
    private String uiUrl = "/login";

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
}
