package me.sarahlacerda.gua.identityservice.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Reduces what a client says about its language to one BCP 47 tag, or {@code null}.
 *
 * <p>
 * A tag comes out as its language, script, region and variant subtags, canonically cased
 * ({@code pt-BR}, {@code zh-Hant-TW}). The ICU spelling {@code pt_BR} is folded to a hyphen,
 * extensions and private use ({@code -u-...}, {@code -x-...}) are dropped, and anything
 * malformed is ignored rather than passed on. Mapping a tag to a language the UI supports is
 * the UI's job; this only guarantees the value is a clean tag that is safe in a URL.
 */
public final class LanguageTags {

    /** The OIDC authorize parameter, also read by the sign-in UI from its own URL. */
    public static final String UI_LOCALES = "ui_locales";

    private static final int MAX_LENGTH = 35;
    private static final Pattern LANGUAGE = Pattern.compile("[A-Za-z]{2,8}");
    private static final Pattern SUBTAG = Pattern.compile("[A-Za-z0-9]{1,8}");

    private LanguageTags() {
    }

    /**
     * The first usable tag of an OIDC {@code ui_locales} value (space separated, in preference
     * order). Commas are accepted too, which is how a repeated query parameter arrives.
     */
    public static String fromUiLocales(String uiLocales) {
        if (!StringUtils.hasText(uiLocales)) {
            return null;
        }
        for (String candidate : uiLocales.trim().split("[\\s,]+")) {
            String tag = normalize(candidate);
            if (tag != null) {
                return tag;
            }
        }
        return null;
    }

    /**
     * The highest weighted usable tag of an {@code Accept-Language} header, or of a single tag.
     * Ties keep header order; {@code *} and {@code q=0} entries never win.
     */
    public static String fromAcceptLanguage(String header) {
        if (!StringUtils.hasText(header)) {
            return null;
        }
        List<Weighted> ranges = new ArrayList<>();
        for (String entry : header.split(",")) {
            String[] parts = entry.split(";");
            double weight = weight(parts);
            String tag = normalize(parts[0]);
            if (tag != null && weight > 0) {
                ranges.add(new Weighted(tag, weight));
            }
        }
        return ranges.stream()
                .sorted(Comparator.comparingDouble(Weighted::weight).reversed())
                .map(Weighted::tag)
                .findFirst()
                .orElse(null);
    }

    /** {@code ui_locales} when it holds a usable tag, otherwise the {@code Accept-Language} header. */
    public static String resolve(String uiLocales, String acceptLanguage) {
        String tag = fromUiLocales(uiLocales);
        return tag != null ? tag : fromAcceptLanguage(acceptLanguage);
    }

    /** {@code url} with {@code ui_locales} set to {@code tag}; unchanged when there is no tag. */
    public static String withUiLocales(String url, String tag) {
        if (tag == null) {
            return url;
        }
        return UriComponentsBuilder.fromUriString(url)
                .replaceQueryParam(UI_LOCALES, tag)
                .build(true)
                .toUriString();
    }

    /** One tag in canonical case, or {@code null} when it is not a well-formed language tag. */
    public static String normalize(String raw) {
        if (!StringUtils.hasText(raw)) {
            return null;
        }
        String[] subtags = raw.trim().replace('_', '-').split("-", -1);
        if (!LANGUAGE.matcher(subtags[0]).matches()) {
            return null;
        }
        StringBuilder tag = new StringBuilder(subtags[0].toLowerCase(Locale.ROOT));
        for (int i = 1; i < subtags.length; i++) {
            String subtag = subtags[i];
            if (!SUBTAG.matcher(subtag).matches()) {
                return null;
            }
            if (subtag.length() == 1) {
                // An extension or private-use singleton: it and everything after it is dropped.
                break;
            }
            tag.append('-').append(canonicalCase(subtag));
        }
        return tag.length() <= MAX_LENGTH ? tag.toString() : null;
    }

    private static String canonicalCase(String subtag) {
        if (subtag.length() == 2) {
            return subtag.toUpperCase(Locale.ROOT);
        }
        if (subtag.length() == 4 && Character.isLetter(subtag.charAt(0))) {
            return subtag.substring(0, 1).toUpperCase(Locale.ROOT) + subtag.substring(1).toLowerCase(Locale.ROOT);
        }
        return subtag.toLowerCase(Locale.ROOT);
    }

    private static double weight(String[] parts) {
        for (int i = 1; i < parts.length; i++) {
            String parameter = parts[i].trim();
            if (parameter.regionMatches(true, 0, "q=", 0, 2)) {
                try {
                    double weight = Double.parseDouble(parameter.substring(2).trim());
                    return weight >= 0 && weight <= 1 ? weight : 0;
                } catch (NumberFormatException ex) {
                    return 0;
                }
            }
        }
        return 1;
    }

    private record Weighted(String tag, double weight) {
    }
}
