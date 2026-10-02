package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;
import java.util.Map;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.OtpProperties;

/**
 * Picks the OTP text for the language a caller asked for.
 *
 * <p>
 * The language may be one tag in either spelling ({@code pt-BR}, {@code pt_BR}) or a whole
 * {@code Accept-Language} header; {@link LanguageTags} reduces it to one tag first. That tag is
 * matched against the lower-case keys of {@code identity.otp.localized-sms-templates} exactly,
 * then by its primary language, so {@code pt-PT} and {@code pt-CA} get the {@code pt} text. No
 * language, or one with no template, gets {@code identity.otp.sms-template}.
 */
public final class SmsTemplates {

    private SmsTemplates() {
    }

    public static String forLanguage(OtpProperties otp, String language) {
        String tag = LanguageTags.fromAcceptLanguage(language);
        if (tag == null) {
            return otp.getSmsTemplate();
        }
        Map<String, String> templates = otp.getLocalizedSmsTemplates();
        String normalized = tag.toLowerCase(Locale.ROOT);
        String template = templates.get(normalized);
        if (template == null && normalized.contains("-")) {
            template = templates.get(normalized.substring(0, normalized.indexOf('-')));
        }
        return template != null ? template : otp.getSmsTemplate();
    }
}
