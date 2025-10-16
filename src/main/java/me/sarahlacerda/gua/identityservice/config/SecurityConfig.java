package me.sarahlacerda.gua.identityservice.config;

import me.sarahlacerda.gua.identityservice.security.MatrixTokenAuthenticationFilter;
import me.sarahlacerda.gua.identityservice.security.MatrixTokenValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.stream.Stream;

@Configuration
public class SecurityConfig {

    private static final List<String> OPEN_POST_ENDPOINTS = List.of(
            "/otp/send",
            "/otp/verify",
            "/security/pin/reset",
            "/security/pin/reset/complete",
            "/oauth2/token"
    );

    private static final List<String> OPEN_GET_ENDPOINTS = List.of(
            "/.well-known/**",
            "/oauth2/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/api-docs/**",
            "/v3/api-docs/**"
    );

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, MatrixTokenAuthenticationFilter matrixTokenAuthenticationFilter) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.POST, OPEN_POST_ENDPOINTS.toArray(String[]::new)).permitAll()
                .requestMatchers(HttpMethod.GET, OPEN_GET_ENDPOINTS.toArray(String[]::new)).permitAll()
                .anyRequest().authenticated()
        );
        http.addFilterBefore(matrixTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public MatrixTokenAuthenticationFilter matrixTokenAuthenticationFilter(MatrixTokenValidator tokenValidator, HandlerMappingIntrospector introspector) {
        MvcRequestMatcher.Builder mvc = new MvcRequestMatcher.Builder(introspector);

        List<RequestMatcher> openEndpoints = Stream.concat(
                OPEN_GET_ENDPOINTS.stream().map(pattern -> (RequestMatcher) mvc.pattern(pattern)),
                OPEN_POST_ENDPOINTS.stream().map(pattern -> (RequestMatcher) mvc.pattern(HttpMethod.POST, pattern))
        ).toList();

        return new MatrixTokenAuthenticationFilter(tokenValidator, openEndpoints);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}