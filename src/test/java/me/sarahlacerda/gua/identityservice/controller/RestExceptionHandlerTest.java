package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import me.sarahlacerda.gua.identityservice.exception.PhoneChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(controllers = RestExceptionHandlerTest.FailingController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({RestExceptionHandler.class, RestExceptionHandlerTest.FailingController.class})
@ExtendWith(OutputCaptureExtension.class)
class RestExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private EndpointRateLimiter endpointRateLimiter;

    @Test
    void redisConnectionFailureBecomes503WithRetryAfter() throws Exception {
        mockMvc.perform(get("/_test/redis-down"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(header().string("Retry-After", "30"))
            .andExpect(jsonPath("$.code").value("service_unavailable"))
            .andExpect(jsonPath("$.message").value("Service temporarily unavailable"));
    }

    @Test
    void dataAccessResourceFailureBecomes503WithRetryAfter() throws Exception {
        mockMvc.perform(get("/_test/db-down"))
            .andExpect(status().isServiceUnavailable())
            .andExpect(header().string("Retry-After", "30"))
            .andExpect(jsonPath("$.code").value("service_unavailable"));
    }

    /**
     * The wire shape of the fresh-2FA refusal. Both clients already carry the
     * {@code twofa_cooldown_active} code and read {@code retryAfterSeconds} from the body
     * with the header as a fallback, so this is the contract they were written against
     * rather than a new one.
     */
    @Test
    void aFreshFactorRefusalCarriesTheCodeAndTheWaitBothClientsRead() throws Exception {
        mockMvc.perform(get("/_test/fresh-2fa"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("twofa_cooldown_active"))
            .andExpect(jsonPath("$.retryAfterSeconds").value(432000))
            .andExpect(header().string("Retry-After", "432000"));
    }

    /**
     * The separate minimum gap between two successful phone changes keeps its own status
     * and its own code. Collapsing the two would tell a client to wait out the wrong one.
     */
    @Test
    void theChangeCooldownKeepsItsOwnStatusAndCode() throws Exception {
        mockMvc.perform(get("/_test/change-cooldown"))
            .andExpect(status().isTooEarly())
            .andExpect(jsonPath("$.code").value("phone_change_cooldown"));
    }

    /** Error bodies that carry no wait do not grow the field. */
    @Test
    void anUnrelatedErrorBodyIsUnchanged() throws Exception {
        mockMvc.perform(get("/_test/redis-down"))
            .andExpect(jsonPath("$.retryAfterSeconds").doesNotExist());
    }

    @Test
    void anUnknownPathIs404NotAServerError(CapturedOutput output) throws Exception {
        mockMvc.perform(get("/_test/no-such-path"))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.code").value("not_found"));
        assertThat(output).doesNotContain("Unhandled exception");
    }

    @Test
    void aWrongMethodIs405WithTheAllowedMethods() throws Exception {
        mockMvc.perform(get("/_test/post-only"))
            .andExpect(status().isMethodNotAllowed())
            .andExpect(header().string("Allow", "POST"))
            .andExpect(jsonPath("$.code").value("method_not_allowed"));
    }

    @Test
    void aMissingParameterIs400() throws Exception {
        mockMvc.perform(get("/_test/typed"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("bad_request"));
    }

    @Test
    void aMistypedParameterIs400() throws Exception {
        mockMvc.perform(get("/_test/typed").param("n", "abc"))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("bad_request"));
    }

    @Test
    void anUnexpectedFailureIsStill500(CapturedOutput output) throws Exception {
        mockMvc.perform(get("/_test/boom"))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.code").value("server_error"))
            .andExpect(jsonPath("$.message").value("Unexpected error"));
        assertThat(output).contains("Unhandled exception");
    }

    @Test
    void aServerSideStatusExceptionIsStill500() throws Exception {
        mockMvc.perform(get("/_test/bad-gateway"))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.code").value("server_error"));
    }

    @RestController
    static class FailingController {

        @GetMapping("/_test/fresh-2fa")
        public String freshTwoFactor() {
            throw new TwoFactorCooldownException("Two-step verification was set up too recently", 432000);
        }

        @GetMapping("/_test/change-cooldown")
        public String changeCooldown() {
            throw new PhoneChangeCooldownException("Phone change cooldown active", 3600);
        }

        @GetMapping("/_test/redis-down")
        public String redisDown() {
            throw new RedisConnectionFailureException("redis is down");
        }

        @GetMapping("/_test/db-down")
        public String dbDown() {
            throw new DataAccessResourceFailureException("postgres is down");
        }

        @PostMapping("/_test/post-only")
        public String postOnly() {
            return "ok";
        }

        @GetMapping("/_test/typed")
        public String typed(@RequestParam int n) {
            return "ok";
        }

        @GetMapping("/_test/bad-gateway")
        public String badGateway() {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "upstream failed");
        }

        @GetMapping("/_test/boom")
        public String boom() {
            throw new IllegalStateException("boom");
        }
    }
}
