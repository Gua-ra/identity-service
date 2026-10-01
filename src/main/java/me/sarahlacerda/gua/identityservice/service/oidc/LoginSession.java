package me.sarahlacerda.gua.identityservice.service.oidc;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Persisted as JSON in Redis and referenced by an opaque cookie. */
@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginSession {

    public enum Phase {
        PHONE,
        OTP_SENT,
        PIN_REQUIRED,
        PASSKEY_REQUIRED,
        PROFILE_REQUIRED,
        /** Only enrollment sessions reach this step, and it never issues an authorization code. */
        ENROLL_STEP_UP,
        PIN_SETUP,
        PASSKEY_SETUP,
        COMPLETED
    }

    // Outcomes of this login, not factors an account holds.
    // A session without one is refused at completion with factor_required.
    public enum SessionFactor {
        PASSKEY,
        PIN,
        /** This session created the account's first factor. */
        ENROLLED,
        RECOVERY
    }

    public enum EnrollTarget {
        PASSKEY,
        PIN
    }

    /** UI guidance only, taken from the OIDC login_hint. */
    public enum Intent {
        PHONE,
        PASSKEY
    }

    private String clientId;
    private String redirectUri;
    private List<String> scope = new ArrayList<>();
    private String state;
    private String nonce;
    private String codeChallenge;
    private String codeChallengeMethod;

    private Phase phase = Phase.PHONE;
    private Intent intent = Intent.PHONE;
    private String phoneNumber;
    /** Set only by a successful POST /login/otp. Recovery requires it. */
    private boolean otpVerified;
    /** Null until this session has authenticated with a factor. */
    private SessionFactor authenticatedFactor;
    private String phoneHint;
    private String locale;
    private String userId;
    private boolean newUser;
    private String displayName;
    private String preferredUsername;

    /** When set, the flow is login-only: the phone must belong to this user and account creation is unreachable. */
    private String reauthUserId;

    /** The gua_downstream value MAS forwarded. Null is treated as web. */
    private String downstreamClient;

    /** An in-app enrollment handoff, not an OIDC login: completion issues no authorization code. */
    private boolean enroll;

    private EnrollTarget enrollTarget;

    /** Null until the enrollment session has proved a factor. */
    private AuthFactor enrollStepUpFactor;

    /** Attacker-controlled: it only names which pending registration to look up. Null when the hint carried none. */
    private String genesisAttachHandle;

    /** Server-side only. Never accepted from the client as a lookup key. */
    private String genesisAttachChallenge;

    private String csrfToken;

    /** Never null: a session with no recorded intent is a phone login. */
    public Intent getIntent() {
        return intent == null ? Intent.PHONE : intent;
    }
}
