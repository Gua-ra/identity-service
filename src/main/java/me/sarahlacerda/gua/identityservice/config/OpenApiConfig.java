package me.sarahlacerda.gua.identityservice.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI identityServiceOpenApi() {
        SecurityScheme oidcAccessTokenScheme = new SecurityScheme()
            .name("OIDC Access Token")
            .type(SecurityScheme.Type.HTTP)
            .scheme("bearer")
            .bearerFormat("JWT")
            .description("OIDC access token (JWT) issued by the identity service via MAS. Provide as 'Authorization: Bearer <token>'.");

        return new OpenAPI()
            .components(new Components().addSecuritySchemes("oidcAccessToken", oidcAccessTokenScheme))
            .addSecurityItem(new SecurityRequirement().addList("oidcAccessToken"))
            .info(new Info()
                .title("Gua Identity Service API")
                .description("Endpoints for OTP, PIN management, and contact discovery in the Gua ecosystem.")
                .version("1.0.0")
                .license(new License().name("Apache 2.0"))
            );
    }
}
