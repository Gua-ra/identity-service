package me.sarahlacerda.gua.identityservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.config.OidcProperties;
import me.sarahlacerda.gua.identityservice.config.ReviewLoginProperties;

@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@EnableConfigurationProperties({ IdentityServiceProperties.class, OidcProperties.class, LoginFlowProperties.class,
        ReviewLoginProperties.class })
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }

}
