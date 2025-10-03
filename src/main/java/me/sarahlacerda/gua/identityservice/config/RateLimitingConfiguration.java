package me.sarahlacerda.gua.identityservice.config;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import me.sarahlacerda.gua.identityservice.web.ratelimit.RateLimitingInterceptor;

@Configuration
@RequiredArgsConstructor
public class RateLimitingConfiguration implements WebMvcConfigurer {

    private final RateLimitingInterceptor rateLimitingInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitingInterceptor).order(0);
    }
}
