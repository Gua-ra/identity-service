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
                        // Genesis registration runs before any OIDC flow exists. It is self-authenticating: the body
                        // carries a possession proof under the key inside the genesis, and registering attaches
                        // nothing.
                        "/account/genesis",
                        "/signup/complete",
                        "/signin/verify-pin",
                        "/oauth2/token",
                        "/login/**");

        /**
         * Retired endpoints. Their handlers take no input and answer only 410 endpoint_retired. They skip
         * the bearer check so an unauthenticated caller is told the path is gone instead of getting a 401.
         */
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
                        "/actuator/prometheus",   // scraped by Prometheus in-cluster; blocked at the public edge
                        "/signup/check-username");

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http,
                        OidcAccessTokenAuthenticationFilter oidcAccessTokenAuthenticationFilter) throws Exception {
                // CSRF posture (deliberate, not a blanket disable):
                // - Authenticated endpoints are stateless and bearer-token based, so classic CSRF does not apply.
                // - The only cookie-bearing surface, /login/**, enforces its own double-submit token: GET
                //   /login/context issues a token bound to the Redis login session and every state-changing
                //   /login POST must echo it in X-CSRF-Token (see LoginFlowController).
                // Spring's session CSRF is therefore exempted; enabling it would 403 stateless clients.
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
