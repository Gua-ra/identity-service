package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * A request with no body, or a body that is not JSON, is the caller's mistake and must
 * read as one. Before this, every such request reached the catch-all handler and came
 * back as a 500, which blamed the server and told the caller nothing.
 */
@SpringBootTest
@ActiveProfiles("test")
class MalformedBodyTest {

        @Autowired
        private WebApplicationContext context;

        private MockMvc mvc() {
                return MockMvcBuilders.webAppContextSetup(context).build();
        }

        @Test
        void missingBodyIsABadRequest() throws Exception {
                mvc().perform(post("/otp/send").contentType(MediaType.APPLICATION_JSON))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.code").value("malformed_request"));
        }

        @Test
        void unparsableBodyIsABadRequest() throws Exception {
                mvc().perform(post("/otp/send").contentType(MediaType.APPLICATION_JSON).content("{not json"))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.code").value("malformed_request"));
        }
}
