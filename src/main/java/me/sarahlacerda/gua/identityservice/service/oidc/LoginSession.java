package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Server-side state for one in-progress interactive OIDC login. Created when MAS redirects the
 * browser to {@code GET /oauth2/authorize}, advanced through the phone, OTP, PIN and profile steps,
 * and consumed when the authorization code is issued. Persisted as JSON in Redis and referenced by
 * an opaque cookie, so no server affinity is required.
 */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginSession {

    public enum Phase {
        /** Awaiting the phone number. */
        PHONE,
        /** OTP dispatched; awaiting the code. */
        OTP_SENT,
        /** Returning user with two-step verification; awaiting the PIN. */
        PIN_REQUIRED,
        /**
         * Returning user whose only factor is a passkey; awaiting the assertion. The PIN step is
         * refused here, and the delayed account recovery is the way back for a user who cannot
         * present the passkey.
         */
        PASSKEY_REQUIRED,
        /** New user; awaiting username + display name. */
        PROFILE_REQUIRED,
        /**
         * A signed-in user adding a factor from settings, before anything is stored: the session must
         * first prove the account (a user-verifying passkey assertion, else the account PIN, else the
         * account's own number and an OTP). Only enrollment sessions reach it, and it never issues an
         * authorization code.
         */
        ENROLL_STEP_UP,
        /** An account holding no factor, after declining the passkey offer; must set a PIN. */
        PIN_SETUP,
        /**
         * Passkey offer: the first factor of an account holding none, or an optional extra after a
         * PIN sign-in.
         */
        PASSKEY_SETUP,
        /** Authenticated; an authorization code has been issued. */
        COMPLETED
    }

    /**
     * Which factor this session actually authenticated with. Separate from the wire enum
     * {@code AuthFactor}: these are outcomes of this login, not factors an account holds. A login is
     * never completed without one; a session lacking it is refused at completion with
     * {@code factor_required}.
     */
    public enum SessionFactor {
        /** A passkey assertion resolved to this session's account. */
        PASSKEY,
        /** The account PIN was validated. */
        PIN,
        /**
         * This session created the account's first factor: at the moment of enrollment, under the
         * account's row lock, it held no other.
         */
        ENROLLED,
        /** A delayed account recovery was completed in this session. */
        RECOVERY
    }

    /** Which factor an enrollment session was opened to add. */
    public enum EnrollTarget {
        PASSKEY,
        PIN
    }

    /**
     * What the user set out to do when the login started, taken from the OIDC {@code login_hint}. The
     * native apps send the reserved value {@code passkey} and MAS forwards it verbatim; every other
     * hint, or none, is a phone login. UI guidance only: the passkey assertion endpoints stay reachable
     * from the phone step whatever the intent.
     */
    public enum Intent {
        /** Phone number first, then OTP (the default). */
        PHONE,
        /** The user asked to sign in with a passkey; the UI opens the assertion straight away. */
        PASSKEY
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
    private Intent intent = Intent.PHONE;
    private String phoneNumber;
    /**
     * Set only by a successful {@code POST /login/otp}. A passkey sign-in never sets it, and the
     * delayed account recovery is offered only to a session that has it.
     */
    private boolean otpVerified;
    /** Null until this session has authenticated with a factor. */
    private SessionFactor authenticatedFactor;
    /** Phone (E.164) pre-filled from the OIDC login_hint, shown on the phone step. */
    private String phoneHint;
    private String locale;
    /** Resolved opaque subject (the OIDC {@code sub}); set once the user is known. */
    private String userId;
    private boolean newUser;
    /** Resolved display name (existing entry, or chosen at the profile step). */
    private String displayName;
    /** Chosen username/localpart for new users; null for returning users. */
    private String preferredUsername;

    /**
     * Set only on a re-authentication request ({@code prompt=login} / {@code id_token_hint}). Carries
     * the subject of the existing session. When present the flow is login-only: the phone must belong
     * to this user and account creation is unreachable. {@code null} for normal signup and login.
     */
    private String reauthUserId;

    /**
     * The downstream client MAS is authenticating for, forwarded as {@code gua_downstream}
     * ({@code web} or {@code native}). Gates OTP send and new-account signup behind the web
     * allowlist. {@code null} when MAS did not forward it, which the guard treats as web.
     */
    private String downstreamClient;

    /**
     * Set when this session is an in-app enrollment handoff for a signed-in user, not an OIDC login.
     * It carries no {@code clientId}, scope or PKCE, so completion issues no authorization code and
     * only redirects the web view back to the app scheme.
     */
    private boolean enroll;

    /** Which factor this enrollment session is adding. Null for every session that is not an enrollment. */
    private EnrollTarget enrollTarget;

    /**
     * What an enrollment session proved at {@link Phase#ENROLL_STEP_UP}. Null until it has proved a
     * factor. Deliberately not {@link #authenticatedFactor}, which is what lets a session finish a
     * sign-in: an enrollment session must never finish one.
     */
    private AuthFactor enrollStepUpFactor;

    /**
     * Single-use attach handle taken from a {@code gua:} login hint, naming an account genesis this
     * client registered at {@code POST /account/genesis}. Null when the hint carried none. The value is
     * attacker-controlled: it only names which pending registration to look up, and the attach must
     * still be proved against {@link #genesisAttachChallenge}.
     */
    private String genesisAttachHandle;

    /**
     * The 32 server-chosen CSPRNG bytes, base64url, the client must sign to attach the genesis above.
     * Issued once when the session enters the profile step, held server-side and never accepted from
     * the client as a lookup key. Cleared only by a successful attach.
     */
    private String genesisAttachChallenge;

    /** Double-submit CSRF token bound to this session and required on state-changing calls. */
    private String csrfToken;

    /** Never null: a session with no recorded intent is a phone login. */
    public Intent getIntent() {
        return intent == null ? Intent.PHONE : intent;
    }
}
