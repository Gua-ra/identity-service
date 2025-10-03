package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

class PhoneNumberHasherTest {

    @Test
    void producesStableDigest() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getDirectory().setPepper("test-pepper");
        PhoneNumberHasher hasher = new PhoneNumberHasher(properties);

        String digest1 = hasher.digest("+5511988887777");
        String digest2 = hasher.digest("+5511988887777");
        String digest3 = hasher.digest("+5511988887778");

        assertThat(digest1).isEqualTo(digest2);
        assertThat(digest1).isNotEqualTo(digest3);
        assertThat(digest1).hasSize(64);
    }
}
