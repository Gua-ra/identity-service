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

    @RestController
    static class FailingController {

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
