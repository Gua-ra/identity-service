package me.sarahlacerda.gua.identityservice.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import me.sarahlacerda.gua.identityservice.controller.dto.BetaSignupRequest;
import me.sarahlacerda.gua.identityservice.controller.dto.SupportRequest;
import me.sarahlacerda.gua.identityservice.service.PublicSubmissionService;

@ExtendWith(MockitoExtension.class)
class PublicSubmissionControllerTest {

    @Mock
    private PublicSubmissionService publicSubmissionService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        PublicSubmissionController controller = new PublicSubmissionController(publicSubmissionService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .setControllerAdvice(new RestExceptionHandler())
                .build();
    }

    // ---- support ----

    @Test
    void supportPersistsAndNotifies() throws Exception {
        SupportRequest request = new SupportRequest();
        request.setName("Ana Souza");
        request.setEmail("ana@example.com");
        request.setMessage("I didn't get my code.");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/support")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accepted").value(true));

        verify(publicSubmissionService).recordSupport(
                eq("Ana Souza"), eq("ana@example.com"), eq("I didn't get my code."), any());
    }

    @Test
    void supportRejectsInvalidEmail() throws Exception {
        SupportRequest request = new SupportRequest();
        request.setName("Ana");
        request.setEmail("not-an-email");
        request.setMessage("Hello");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/support")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

        verify(publicSubmissionService, never()).recordSupport(any(), any(), any(), any());
    }

    @Test
    void supportRejectsEmptyMessage() throws Exception {
        SupportRequest request = new SupportRequest();
        request.setName("Ana");
        request.setEmail("ana@example.com");
        request.setMessage("");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/support")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

        verify(publicSubmissionService, never()).recordSupport(any(), any(), any(), any());
    }

    @Test
    void supportHoneypotIsSilentlyIgnored() throws Exception {
        SupportRequest request = new SupportRequest();
        request.setName("Ana");
        request.setEmail("ana@example.com");
        request.setMessage("Hello");
        request.setWebsite("http://spam.example"); // honeypot tripped

        mockMvc.perform(MockMvcRequestBuilders.post("/public/support")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accepted").value(true));

        verify(publicSubmissionService, never()).recordSupport(any(), any(), any(), any());
    }

    // ---- beta sign-up ----

    @Test
    void betaPersistsAndNotifies() throws Exception {
        BetaSignupRequest request = new BetaSignupRequest();
        request.setEmail("ana@example.com");
        request.setPlatform("ios");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/beta-signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accepted").value(true));

        verify(publicSubmissionService).recordBetaSignup(eq("ana@example.com"), eq("ios"), any());
    }

    @Test
    void betaRejectsUnknownPlatform() throws Exception {
        BetaSignupRequest request = new BetaSignupRequest();
        request.setEmail("ana@example.com");
        request.setPlatform("windows");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/beta-signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

        verify(publicSubmissionService, never()).recordBetaSignup(any(), any(), any());
    }

    @Test
    void betaRejectsBlankEmail() throws Exception {
        BetaSignupRequest request = new BetaSignupRequest();
        request.setEmail("");
        request.setPlatform("android");

        mockMvc.perform(MockMvcRequestBuilders.post("/public/beta-signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest());

        verify(publicSubmissionService, never()).recordBetaSignup(any(), any(), any());
    }

    @Test
    void betaHoneypotIsSilentlyIgnored() throws Exception {
        BetaSignupRequest request = new BetaSignupRequest();
        request.setEmail("ana@example.com");
        request.setPlatform("android");
        request.setWebsite("http://spam.example"); // honeypot tripped

        mockMvc.perform(MockMvcRequestBuilders.post("/public/beta-signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(request)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.accepted").value(true));

        verify(publicSubmissionService, never()).recordBetaSignup(any(), any(), any());
    }
}
