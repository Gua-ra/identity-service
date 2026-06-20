package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Server-side state for one in-progress interactive OIDC login. Created when
 * MAS
 * redirects the browser to {@code GET /oauth2/authorize}, advanced as the user
 * moves through the phone / OTP / PIN / profile steps in {@code gua-idp-web},
 * and
 * consumed when the authorization code is issued. Persisted as JSON in Redis
 * and
 * referenced by an opaque cookie, so no server affinity is required.
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginSession {

    /** Steps the browser UI walks through. */
    public enum Phase {
        /** Awaiting the phone number. */
        PHONE,
        /** OTP dispatched; awaiting the code. */
        OTP_SENT,
        /** Returning user with two-step verification; awaiting the PIN. */
        PIN_REQUIRED,
        /** New user; awaiting username + display name. */
        PROFILE_REQUIRED,
        /** New user; offered to set an account PIN (two-step verification). */
        PIN_SETUP,
        /** Phone verification and any PIN step are complete; optional passkey setup. */
        PASSKEY_SETUP,
        /** Authenticated; an authorization code has been issued. */
        COMPLETED
    }

    // --- Original OIDC authorization request (echoed back to MAS at the end) ---
    private String clientId;
    private String redirectUri;
    private List<String> scope = new ArrayList<>();
    private String state;
    private String nonce;
    private String codeChallenge;
    private String codeChallengeMethod;

    // --- Progressive authentication state ---
    private Phase phase = Phase.PHONE;
    private String phoneNumber;
    /**
     * Phone (E.164) pre-filled from the OIDC login_hint, shown on the phone step.
     */
    private String phoneHint;
    private String locale;
    /**
     * Resolved opaque subject (the OIDC {@code sub}); set once the user is known.
     */
    private String userId;
    private boolean newUser;
    /** Resolved display name (existing entry, or chosen at the profile step). */
    private String displayName;
    /** Chosen username/localpart for new users; null for returning users. */
    private String preferredUsername;

    /**
     * Set only on a re-authentication request (an authorize with an already
     * authenticated session: {@code prompt=login} / {@code id_token_hint}), where a
     * logged-in user must re-verify (e.g. to view account settings). Carries the
     * subject of the existing session. When present the flow is LOGIN-ONLY: the phone
     * must already be registered AND belong to this user; it must never reach the
     * new-account / username-creation phase. {@code null} for normal signup/login and
     * for the change-phone flow.
     */
    private String reauthUserId;

    /**
     * Double-submit CSRF token bound to this session and required on state-changing
     * calls.
     */
    private String csrfToken;
}
