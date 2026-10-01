package me.sarahlacerda.gua.identityservice.config;

import me.sarahlacerda.gua.identityservice.security.OidcAccessTokenAuthenticationFilter;
import me.sarahlacerda.gua.identityservice.security.OidcAccessTokenValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.stream.Stream;

@Configuration
public class SecurityConfig {

        private static final List<String> OPEN_POST_ENDPOINTS = List.of(
                        "/otp/send",
                        "/otp/verify",
                        // Open by design: the body carries a possession proof under the key inside the genesis.
                        "/account/genesis",
                        "/signup/complete",
                        "/signin/verify-pin",
                        "/oauth2/token",
                        "/login/**");

        /** Retired endpoints take no input and answer 410, so they skip the bearer check. */
        private static final List<String> RETIRED_POST_ENDPOINTS = List.of(
                        "/security/pin/reset",
                        "/security/pin/reset/complete");

        private static final List<String> OPEN_GET_ENDPOINTS = List.of(
                        "/.well-known/**",
                        "/oauth2/**",
                        "/login/**",
                        "/swagger-ui/**",
                        "/swagger-ui.html",
                        "/api-docs/**",
                        "/v3/api-docs/**",
                        "/actuator/health",
                        "/actuator/health/**",
                        "/actuator/info",
                        "/actuator/prometheus", // blocked at the public edge
                        "/signup/check-username");

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http,
                        OidcAccessTokenAuthenticationFilter oidcAccessTokenAuthenticationFilter) throws Exception {
                // Bearer endpoints are stateless and /login/** enforces its own double-submit token, so
                // Spring's session CSRF is exempted.
                http.csrf(csrf -> csrf.ignoringRequestMatchers("/**"));
                http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                http.authorizeHttpRequests(authorize -> authorize
                                .requestMatchers(HttpMethod.POST, OPEN_POST_ENDPOINTS.toArray(String[]::new))
                                .permitAll()
                                .requestMatchers(HttpMethod.POST, RETIRED_POST_ENDPOINTS.toArray(String[]::new))
                                .permitAll()
                                .requestMatchers(HttpMethod.GET, OPEN_GET_ENDPOINTS.toArray(String[]::new)).permitAll()
                                .anyRequest().authenticated());
                http.addFilterBefore(oidcAccessTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
                return http.build();
        }

        @Bean
        public OidcAccessTokenAuthenticationFilter oidcAccessTokenAuthenticationFilter(
                        OidcAccessTokenValidator tokenValidator) {
                PathPatternRequestMatcher.Builder builder = PathPatternRequestMatcher.withDefaults();

                List<RequestMatcher> openEndpoints = Stream.concat(
                                OPEN_GET_ENDPOINTS.stream().map(
                                                pattern -> (RequestMatcher) builder.matcher(HttpMethod.GET, pattern)),
                                Stream.concat(OPEN_POST_ENDPOINTS.stream(), RETIRED_POST_ENDPOINTS.stream()).map(
                                                pattern -> (RequestMatcher) builder.matcher(HttpMethod.POST, pattern)))
                                .toList();

                return new OidcAccessTokenAuthenticationFilter(tokenValidator, openEndpoints);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}
