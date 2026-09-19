package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import me.sarahlacerda.gua.identityservice.exception.PhoneChangeCooldownException;
import me.sarahlacerda.gua.identityservice.exception.TwoFactorCooldownException;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(controllers = RestExceptionHandlerTest.FailingController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import({RestExceptionHandler.class, RestExceptionHandlerTest.FailingController.class})
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
    }
}
