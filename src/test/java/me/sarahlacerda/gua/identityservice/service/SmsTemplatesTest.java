package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.bind.PropertySourcesPlaceholdersResolver;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.io.ClassPathResource;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.OtpProperties;

/**
 * The SMS texts as application.yml ships them, with no environment overrides, so the language
 * coverage of the live service is what is checked.
 */
class SmsTemplatesTest {

    private static final String PT_BR = "Seu código de verificação Gua é %s. Nunca compartilhe este código com "
            + "ninguém. O suporte Gua nunca vai pedir esse código.";

    private static OtpProperties shipped;

    @BeforeAll
    static void bindApplicationYml() throws IOException {
        MutablePropertySources sources = new MutablePropertySources();
        new YamlPropertySourceLoader().load("application.yml", new ClassPathResource("application.yml"))
                .forEach(sources::addLast);
        shipped = new Binder(ConfigurationPropertySources.from(sources), new PropertySourcesPlaceholdersResolver(sources))
                .bind("identity.otp", OtpProperties.class)
                .get();
    }

    @Test
    void everySupportedLanguageHasATemplate() {
        assertThat(shipped.getLocalizedSmsTemplates()).containsKeys("en", "pt", "pt-br", "es", "fr");
        assertThat(shipped.getLocalizedSmsTemplates()).allSatisfy((language, template) ->
                assertThat(template).as(language).contains("%s").doesNotContain("${"));
    }

    @Test
    void theDefaultIsTheEnglishText() {
        assertThat(shipped.getSmsTemplate()).isEqualTo(shipped.getLocalizedSmsTemplates().get("en"));
        assertThat(SmsTemplates.forLanguage(shipped, null)).isEqualTo(shipped.getLocalizedSmsTemplates().get("en"));
        assertThat(SmsTemplates.forLanguage(shipped, "de-DE")).isEqualTo(shipped.getLocalizedSmsTemplates().get("en"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "pt-BR", "pt_BR", "pt", "pt-PT", "pt-CA", "pt-BR,pt;q=0.9,en;q=0.8" })
    void everyPortugueseTagGetsTheBrazilianText(String language) {
        assertThat(SmsTemplates.forLanguage(shipped, language)).isEqualTo(PT_BR);
    }

    @Test
    void aRegionalTagFallsBackToItsLanguage() {
        assertThat(SmsTemplates.forLanguage(shipped, "fr-CA")).isEqualTo(shipped.getLocalizedSmsTemplates().get("fr"));
        assertThat(SmsTemplates.forLanguage(shipped, "es-419")).isEqualTo(shipped.getLocalizedSmsTemplates().get("es"));
        // A whole Accept-Language header is texted in its first choice.
        assertThat(SmsTemplates.forLanguage(shipped, "fr;q=1.0, en;q=0.9"))
                .isEqualTo(shipped.getLocalizedSmsTemplates().get("fr"));
    }
}
