package me.sarahlacerda.gua.identityservice.controller;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.when;

import java.util.List;

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
import me.sarahlacerda.gua.identityservice.domain.ContactMatch;
import me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException;
import me.sarahlacerda.gua.identityservice.service.ContactDiscoveryService;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(MockitoExtension.class)
class DirectoryControllerTest {

    @Mock
    private DirectoryService directoryService;

    @Mock
    private ContactDiscoveryService contactDiscoveryService;

    @Mock
    private HomeserverRegistry homeserverRegistry;

    @Mock
    private AuthenticatedUserAccessor authenticatedUserAccessor;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        DirectoryController controller = new DirectoryController(
            directoryService, contactDiscoveryService, homeserverRegistry, authenticatedUserAccessor);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
            .setMessageConverters(new MappingJackson2HttpMessageConverter())
            .setControllerAdvice(new RestExceptionHandler())
            .build();
    }

    @Test
    void lookupReturnsMatches() throws Exception {
        DirectoryLookupRequest request = new DirectoryLookupRequest();
        request.setPhones(List.of("+5511999998888"));

        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@me:gua.global");
        when(contactDiscoveryService.match(List.of("+5511999998888")))
            .thenReturn(List.of(new ContactMatch("+5511999998888", "@friend:gua.global", "friend", "Friend")));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/directory/lookup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches", hasSize(1)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches[0].phone", is("+5511999998888")))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches[0].userId", is("@friend:gua.global")))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches[0].username", is("friend")))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.matches[0].displayName", is("Friend")));
    }

    @Test
    void lookupRejectsOversizedBatch() throws Exception {
        DirectoryLookupRequest request = new DirectoryLookupRequest();
        request.setPhones(List.of("+5511999998888"));

        when(authenticatedUserAccessor.requireCurrentUserId()).thenReturn("@me:gua.global");
        when(contactDiscoveryService.match(anyList()))
            .thenThrow(new LookupBatchTooLargeException("At most 1000 phone numbers can be matched per request"));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/directory/lookup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isBadRequest())
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.code", is("lookup_batch_too_large")));
    }
}
