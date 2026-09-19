package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

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
        /**
         * Returning user whose only factor is a passkey; awaiting the assertion. The PIN step is
         * refused here, and the delayed account recovery is the way back for a user who cannot
         * present the passkey.
         */
        PASSKEY_REQUIRED,
        /** New user; awaiting username + display name. */
        PROFILE_REQUIRED,
        /**
         * An already-signed-in user adding a factor from settings, before anything is stored:
         * the session must first prove the account with the strongest thing it can produce (a
         * user-verifying passkey assertion, else the account PIN, else the account's own number
         * and an OTP sent to it). Only the enrollment sessions created by
         * {@code POST /security/passkey/enroll/start} and {@code POST /security/pin/enroll/start}
         * ever reach it, and it never issues an authorization code.
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
     * Which factor this session actually authenticated with. Deliberately separate from the wire
     * enum {@code AuthFactor}: these are outcomes of this login, not factors an account holds, and
     * two of them ({@link #ENROLLED}, {@link #RECOVERY}) are not factors at all.
     *
     * <p>
     * A login is never completed without one. A session persisted before this field existed reads
     * back without it and is refused at completion with {@code factor_required}; the user starts
     * the login again.
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
     * What the user set out to do when the login started, taken from the OIDC
     * {@code login_hint}. The native apps send the reserved value {@code passkey}
     * when the user taps "Sign in with a passkey" and MAS forwards it verbatim;
     * every other hint, or none, is a phone login. This is guidance for the UI
     * only: the passkey assertion endpoints stay reachable from the phone step
     * whatever the intent, and a session written before this field existed reads
     * back as {@link #PHONE}.
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
    /** See {@link Intent}. Absent from sessions persisted before it existed. */
    private Intent intent = Intent.PHONE;
    private String phoneNumber;
    /**
     * Set only by a successful {@code POST /login/otp}. A passkey sign-in never sets it, and the
     * delayed account recovery is only offered to a session that has it, so recovery always starts
     * from a proved phone number.
     */
    private boolean otpVerified;
    /** See {@link SessionFactor}. Null until this session has authenticated with a factor. */
    private SessionFactor authenticatedFactor;
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
     * The downstream client MAS is authenticating on behalf of, forwarded on the
     * upstream authorize request as {@code gua_downstream} (e.g. {@code web} for the
     * web client, {@code native} for the mobile apps). Used to gate both OTP send
     * and new-account signup behind the web registration allowlist; {@code null}
     * when MAS did not forward the signal, which the guard treats as a web signup
     * (fail closed).
     */
    private String downstreamClient;

    /**
     * Set when this session is an in-app passkey enrollment handoff for an
     * already-signed-in user (created by {@code POST /security/passkey/enroll/start}),
     * rather than an OIDC authorization login. Such a session carries no
     * {@code clientId} / scope / PKCE, so its passkey-setup completion must NOT issue an
     * authorization code; it only redirects the web view back to the app scheme. Kept
     * distinct from {@link #reauthUserId} (also set here) because a re-authentication is
     * still a real OIDC authorize with a client, whereas an enrollment is not.
     */
    private boolean enroll;

    /**
     * Which factor this enrollment session is adding, so the step it moves to after the step-up
     * is the setup step for that factor. Null for every session that is not an enrollment.
     */
    private EnrollTarget enrollTarget;

    /**
     * What an enrollment session proved at {@link Phase#ENROLL_STEP_UP}: a passkey assertion,
     * the account PIN, or the account's number and an OTP sent to it. Null until it has proved
     * one, which is what keeps a bearer session on its own from adding a durable factor.
     *
     * <p>
     * Deliberately not {@link #authenticatedFactor}. That field is what lets a session finish a
     * sign-in, and an enrollment session must never finish one: keeping the two apart means
     * that even a route which wrongly sent an enrollment session to completion would still be
     * refused there for having authenticated with nothing.
     */
    private AuthFactor enrollStepUpFactor;

    /**
     * Single-use attach handle taken from a {@code gua:} login hint, naming an {@code AccountGenesis}
     * this client registered at {@code POST /account/genesis} (ADM-008 decision 6). Null when the hint
     * carried none, which is the bootstrap branch and not a failure.
     *
     * <p>A handle alone attaches nothing. Anyone can compose an authorize URL, so this value is
     * attacker-controlled in both directions; it only names which pending registration the attach step
     * should look up, and the attach still has to be proved by {@link #genesisAttachChallenge}.
     */
    private String genesisAttachHandle;

    /**
     * The 32 server-chosen CSPRNG bytes, base64url, that the client must sign to attach the genesis
     * above. Issued once when this session enters the profile step, held here on the server side, and
     * never accepted from the client as a lookup key. Burned only by a successful attach, and gone when
     * the session expires, which is at or under the handle's own 30-minute TTL.
     */
    private String genesisAttachChallenge;

    /**
     * Double-submit CSRF token bound to this session and required on state-changing
     * calls.
     */
    private String csrfToken;

    /** Never {@code null}: a session with no recorded intent is a phone login. */
    public Intent getIntent() {
        return intent == null ? Intent.PHONE : intent;
    }
}
