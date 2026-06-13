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
                        "/signup/complete",
                        "/signin/verify-pin",
                        "/security/pin/reset",
                        "/security/pin/reset/complete",
                        "/oauth2/token",
                        "/login/**");

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
                        "/signup/check-username");

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http,
                        OidcAccessTokenAuthenticationFilter oidcAccessTokenAuthenticationFilter) throws Exception {
                // CSRF posture (deliberate, not a blanket disable):
                // - Every authenticated endpoint is STATELESS and bearer-token based
                //   (OidcAccessTokenAuthenticationFilter reads the Authorization header,
                //   not an ambient session cookie), so a browser cannot be tricked into
                //   forging them — classic CSRF does not apply.
                // - The only cookie-bearing surface, /login/**, enforces its OWN
                //   double-submit token: GET /login/context issues a CSRF token bound to
                //   the Redis login session and every state-changing /login POST must echo
                //   it back in the X-CSRF-Token header (see LoginFlowController).
                // We therefore exempt the API from Spring's session-based CSRF rather than
                // calling disable(): turning Spring CSRF ON for the bearer endpoints would
                // 403 stateless clients (iOS / web) that hold no server CSRF token.
                http.csrf(csrf -> csrf.ignoringRequestMatchers("/**"));
                http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                http.authorizeHttpRequests(authorize -> authorize
                                .requestMatchers(HttpMethod.POST, OPEN_POST_ENDPOINTS.toArray(String[]::new))
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
                                OPEN_POST_ENDPOINTS.stream().map(
                                                pattern -> (RequestMatcher) builder.matcher(HttpMethod.POST, pattern)))
                                .toList();

                return new OidcAccessTokenAuthenticationFilter(tokenValidator, openEndpoints);
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}
