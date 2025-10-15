package me.sarahlacerda.gua.identityservice.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import me.sarahlacerda.gua.identityservice.security.MatrixTokenAuthenticationFilter;
import me.sarahlacerda.gua.identityservice.security.MatrixTokenValidator;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, MatrixTokenAuthenticationFilter matrixTokenAuthenticationFilter) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests(authorize -> authorize
            .requestMatchers(HttpMethod.POST, "/otp/send", "/otp/verify", "/security/pin/reset", "/security/pin/reset/complete").permitAll()
            .requestMatchers(HttpMethod.GET, "/.well-known/**", "/oauth2/authorize", "/userinfo").permitAll()
            .requestMatchers(HttpMethod.POST, "/oauth2/token").permitAll()
            .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/api-docs/**", "/v3/api-docs/**").permitAll()
            .anyRequest().authenticated()
        );
        http.addFilterBefore(matrixTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public MatrixTokenAuthenticationFilter matrixTokenAuthenticationFilter(MatrixTokenValidator tokenValidator, HandlerMappingIntrospector introspector) {
        MvcRequestMatcher.Builder mvc = new MvcRequestMatcher.Builder(introspector);
        List<RequestMatcher> openEndpoints = List.of(
            mvc.pattern(HttpMethod.POST, "/otp/send"),
            mvc.pattern(HttpMethod.POST, "/otp/verify"),
            mvc.pattern(HttpMethod.POST, "/security/pin/reset"),
            mvc.pattern(HttpMethod.POST, "/security/pin/reset/complete"),
            mvc.pattern(HttpMethod.GET, "/.well-known/**"),
            mvc.pattern(HttpMethod.GET, "/oauth2/authorize"),
            mvc.pattern(HttpMethod.GET, "/userinfo"),
            mvc.pattern(HttpMethod.POST, "/oauth2/token"),
            mvc.pattern("/swagger-ui/**"),
            mvc.pattern("/swagger-ui.html"),
            mvc.pattern("/api-docs/**"),
            mvc.pattern("/v3/api-docs/**")
        );
        return new MatrixTokenAuthenticationFilter(tokenValidator, openEndpoints);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
