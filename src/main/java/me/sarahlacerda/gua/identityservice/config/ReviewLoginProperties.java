package me.sarahlacerda.gua.identityservice.config;

import java.util.Locale;
import java.util.Map;

import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;

/**
 * The store review login: one project-owned number whose sign-in code is a fixed value, so an
 * app store reviewer, who cannot receive our SMS, can sign in. {@code ReviewLogin} validates the
 * number and the hash at startup and refuses to start on anything missing or malformed.
 *
 * <p>
 * Read from exactly three process environment variables, {@value #ENABLED}, {@value #PHONE} and
 * {@value #CODE_HASH}, and from nothing else: not application.yml, system properties,
 * {@code SPRING_APPLICATION_JSON}, command line arguments or relaxed binding. Startup is refused
 * while any {@code identity.review-login} property, in any spelling relaxed binding accepts
 * (including {@code IDENTITY_REVIEW_LOGIN_*} and {@code IDENTITY_REVIEWLOGIN_*} variables), is
 * present in any property source, so no other source can switch the feature on, point it at
 * another number or replace its hash.
 *
 * <p>
 * {@value #ENABLED} is exactly {@code true} to turn the feature on. Exactly {@code false}, empty
 * or unset is off. Any other value refuses startup.
 *
 * <p>
 * No {@code toString}: the hash must never reach a log line.
 */
public final class ReviewLoginProperties {

    public static final String ENABLED = "GUA_REVIEW_LOGIN_ENABLED";
    public static final String PHONE = "GUA_REVIEW_LOGIN_PHONE";
    public static final String CODE_HASH = "GUA_REVIEW_LOGIN_CODE_HASH";

    /** {@code identity.review-login} with case and every separator removed, as relaxed binding compares names. */
    private static final String FOREIGN_PREFIX = "identityreviewlogin";

    private final boolean enabled;
    private final String phone;
    private final String codeHash;

    private ReviewLoginProperties(boolean enabled, String phone, String codeHash) {
        this.enabled = enabled;
        this.phone = phone;
        this.codeHash = codeHash;
    }

    /** The feature off, as on every deployment without the three variables. */
    public static ReviewLoginProperties off() {
        return new ReviewLoginProperties(false, null, null);
    }

    /**
     * The three values as the environment holds them, {@code null} for an unset one. Refuses an
     * {@code enabled} that is not exactly {@code true}, {@code false}, empty or unset.
     */
    public static ReviewLoginProperties of(String enabled, String phone, String codeHash) {
        return new ReviewLoginProperties(parseEnabled(enabled), phone, codeHash);
    }

    /**
     * Reads the three variables from the process environment, which Spring holds as the
     * {@value StandardEnvironment#SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME} property source, by
     * their exact names. Refuses startup first if any property source carries an
     * {@code identity.review-login} property.
     */
    public static ReviewLoginProperties fromEnvironment(ConfigurableEnvironment environment) {
        refuseForeignSpellings(environment);
        Map<String, Object> variables = processEnvironment(environment);
        return of(text(variables.get(ENABLED)), text(variables.get(PHONE)), text(variables.get(CODE_HASH)));
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getPhone() {
        return phone;
    }

    public String getCodeHash() {
        return codeHash;
    }

    private static boolean parseEnabled(String value) {
        if (value == null || value.isEmpty() || "false".equals(value)) {
            return false;
        }
        if ("true".equals(value)) {
            return true;
        }
        // The value is not echoed: a misplaced code or hash must not reach the startup log.
        throw new IllegalStateException(ENABLED + " must be exactly true or false, or unset."
                + " Refusing to start.");
    }

    /**
     * Names only the property and its source, never the value, since the message ends up in the
     * startup log.
     */
    private static void refuseForeignSpellings(ConfigurableEnvironment environment) {
        for (PropertySource<?> source : environment.getPropertySources()) {
            if (!(source instanceof EnumerablePropertySource<?> enumerable)) {
                continue;
            }
            for (String name : enumerable.getPropertyNames()) {
                if (canonical(name).startsWith(FOREIGN_PREFIX)) {
                    throw new IllegalStateException("Store review login: " + name + " is set in '" + source.getName()
                            + "'. The review login reads only the " + ENABLED + ", " + PHONE + " and " + CODE_HASH
                            + " environment variables; remove " + name + ". Refusing to start.");
                }
            }
        }
    }

    private static String canonical(String name) {
        StringBuilder out = new StringBuilder(name.length());
        for (char c : name.toLowerCase(Locale.ROOT).toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static Map<String, Object> processEnvironment(ConfigurableEnvironment environment) {
        PropertySource<?> source = environment.getPropertySources()
                .get(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        return source instanceof MapPropertySource variables ? variables.getSource() : Map.of();
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }
}
