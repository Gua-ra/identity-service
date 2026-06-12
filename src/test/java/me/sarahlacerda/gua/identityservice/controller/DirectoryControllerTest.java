package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.util.List;

import me.sarahlacerda.gua.identityservice.domain.DirectoryMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.controller.dto.DirectoryLookupRequest;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class DirectoryControllerTest {

    @Mock
    private DirectoryService directoryService;

    @Mock
    private HomeserverRegistry homeserverRegistry;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        DirectoryController controller = new DirectoryController(directoryService, homeserverRegistry, authenticatedUserAccessor);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new MappingJackson2HttpMessageConverter())
            .build();
    }

    @Test
    void lookupReturnsMatches() throws Exception {
        DirectoryLookupRequest request = new DirectoryLookupRequest();
        request.setUserId("@user:domain");
        request.setDigests(List.of("digest"));

        doNothing().when(authenticatedUserAccessor).requireUserIdMatches("@user:domain");
        when(directoryService.lookupMatches(List.of("digest")))
            .thenReturn(List.of(new DirectoryMatch("digest", "@user:domain", "User")));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/directory/lookup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches", hasSize(1)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches[0].digest", is("digest")));
    }
}
