package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class LanguageTagsTest {

    @ParameterizedTest
    @CsvSource({
            "pt-BR, pt-BR",
            "pt_BR, pt-BR",
            "PT-br, pt-BR",
            "pt, pt",
            "fr-CA, fr-CA",
            "es-419, es-419",
            "zh-hant-tw, zh-Hant-TW",
            "en-US-u-ca-gregory, en-US",
            "pt-BR-x-gua, pt-BR",
            "' de-DE ', de-DE"
    })
    void normalizeYieldsOneCanonicalTag(String raw, String expected) {
        assertThat(LanguageTags.normalize(raw)).isEqualTo(expected);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { " ", "*", "x-private", "e", "pt-", "pt--BR", "pt BR", "\"><script>", "pt-BR;q=1",
            "toolonglanguage", "en-abcdefghi" })
    void normalizeRefusesAnythingThatIsNotATag(String raw) {
        assertThat(LanguageTags.normalize(raw)).isNull();
    }

    @Test
    void uiLocalesTakesTheFirstUsableTag() {
        assertThat(LanguageTags.fromUiLocales("pt-BR en")).isEqualTo("pt-BR");
        assertThat(LanguageTags.fromUiLocales("  *  es fr")).isEqualTo("es");
        // A repeated query parameter arrives comma joined.
        assertThat(LanguageTags.fromUiLocales("fr,fr")).isEqualTo("fr");
        assertThat(LanguageTags.fromUiLocales("<b>")).isNull();
        assertThat(LanguageTags.fromUiLocales(null)).isNull();
    }

    @Test
    void acceptLanguageTakesTheHighestWeightedTag() {
        assertThat(LanguageTags.fromAcceptLanguage("pt-BR,pt;q=0.9,en;q=0.8")).isEqualTo("pt-BR");
        assertThat(LanguageTags.fromAcceptLanguage("en;q=0.5, fr-CA;q=0.9")).isEqualTo("fr-CA");
        assertThat(LanguageTags.fromAcceptLanguage("pt-BR;q=1.0, en-CA;q=0.9")).isEqualTo("pt-BR");
        // Ties keep header order; wildcards and refused entries never win.
        assertThat(LanguageTags.fromAcceptLanguage("es, fr")).isEqualTo("es");
        assertThat(LanguageTags.fromAcceptLanguage("*, fr;q=0.1")).isEqualTo("fr");
        assertThat(LanguageTags.fromAcceptLanguage("de;q=0, it;q=0.2")).isEqualTo("it");
        assertThat(LanguageTags.fromAcceptLanguage("de;q=abc, it;q=7, nl;q=0.3")).isEqualTo("nl");
        // A single tag in either spelling is a header of one.
        assertThat(LanguageTags.fromAcceptLanguage("pt_BR")).isEqualTo("pt-BR");
        assertThat(LanguageTags.fromAcceptLanguage("*")).isNull();
        assertThat(LanguageTags.fromAcceptLanguage("")).isNull();
    }

    @Test
    void uiLocalesBeatsTheHeaderOnlyWhenItHoldsATag() {
        assertThat(LanguageTags.resolve("es", "fr")).isEqualTo("es");
        assertThat(LanguageTags.resolve("???", "fr")).isEqualTo("fr");
        assertThat(LanguageTags.resolve(null, null)).isNull();
    }

    @Test
    void withUiLocalesSetsOrReplacesTheParameter() {
        assertThat(LanguageTags.withUiLocales("/signin", "pt-BR")).isEqualTo("/signin?ui_locales=pt-BR");
        assertThat(LanguageTags.withUiLocales("/signin?ui_locales=en", "es")).isEqualTo("/signin?ui_locales=es");
        assertThat(LanguageTags.withUiLocales("/signin", null)).isEqualTo("/signin");
    }
}
