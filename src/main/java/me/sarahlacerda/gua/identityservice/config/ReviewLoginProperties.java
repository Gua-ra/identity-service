package me.sarahlacerda.gua.identityservice.config;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The store review login: one project-owned number whose sign-in code is a fixed value, so an
 * app store reviewer, who cannot receive our SMS, can sign in. Off unless {@code enabled} is
 * true. {@code ReviewLogin} validates the rest at startup and refuses to start on anything
 * missing or malformed.
 *
 * <p>
 * No {@code toString}: the hash must never reach a log line.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "identity.review-login")
public class ReviewLoginProperties {

    /**
     * {@code GUA_REVIEW_LOGIN_ENABLED}. Only {@code true} turns the feature on; unset, empty or
     * false is off. A value that is none of these refuses startup.
     */
    private Boolean enabled;

    /** {@code GUA_REVIEW_LOGIN_PHONE}. The review number, in canonical E.164. */
    private String phone;

    /** {@code GUA_REVIEW_LOGIN_CODE_HASH}. A bcrypt hash of the review code, never the code itself. */
    private String codeHash;

    public boolean isEnabled() {
        return Boolean.TRUE.equals(enabled);
    }
}
