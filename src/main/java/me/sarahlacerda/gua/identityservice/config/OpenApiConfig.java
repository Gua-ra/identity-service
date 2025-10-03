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
        SecurityScheme matrixTokenScheme = new SecurityScheme()
            .name("Matrix Token")
            .type(SecurityScheme.Type.HTTP)
            .scheme("bearer")
            .bearerFormat("Matrix Access Token")
            .description("Matrix client access token issued by Synapse via the OTP login flow. Provide as 'Authorization: Bearer <token>'.");

        return new OpenAPI()
            .components(new Components().addSecuritySchemes("matrixToken", matrixTokenScheme))
            .addSecurityItem(new SecurityRequirement().addList("matrixToken"))
            .info(new Info()
                .title("Gua Identity Service API")
                .description("Endpoints for OTP, PIN management, and contact discovery in the Gua ecosystem.")
                .version("1.0.0")
                .license(new License().name("Apache 2.0"))
            );
    }
}
