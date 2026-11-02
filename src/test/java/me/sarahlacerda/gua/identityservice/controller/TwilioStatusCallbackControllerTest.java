package me.sarahlacerda.gua.identityservice.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;
import me.sarahlacerda.gua.identityservice.service.SmsDeliveryLog;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;

@WebMvcTest(TwilioStatusCallbackController.class)
@Import({ SmsDeliveryLog.class, PhoneNumberMasker.class, TwilioStatusCallbackControllerTest.Metrics.class })
@EnableConfigurationProperties(IdentityServiceProperties.class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = {
        "identity.sms.twilio.enabled=true",
        "identity.sms.twilio.auth-token=" + TwilioStatusCallbackControllerTest.AUTH_TOKEN,
        "identity.sms.twilio.status-callback-url=" + TwilioStatusCallbackControllerTest.CALLBACK_URL
})
class TwilioStatusCallbackControllerTest {

    static final String AUTH_TOKEN = "test-auth-token";
    static final String CALLBACK_URL = "https://identity.example.com/sms/twilio/status";
    private static final String PHONE = "+212612345678";

    @TestConfiguration
    static class Metrics {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    @Autowired
    MockMvc mockMvc;

    @Autowired
    MeterRegistry metrics;

    @MockitoBean
    EndpointRateLimiter endpointRateLimiter;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(SmsDeliveryLog.class);

    @BeforeEach
    void captureLogs() {
        metrics.clear();
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach
    void releaseLogs() {
        logger.detachAppender(logs);
    }

    @Test
    void aSignedFinalStatusIsLoggedAndCounted() throws Exception {
        Map<String, String> params = callback("undelivered", "30034");

        mockMvc.perform(signed(params, sign(AUTH_TOKEN, CALLBACK_URL, params))).andExpect(status().isNoContent());

        assertThat(logs.list).extracting(ILoggingEvent::getFormattedMessage).containsExactly(
                "sms_status sid=SM0123 status=undelivered error_code=30034 country=MA phone=+212••••5678");
        assertThat(metrics.counter("gua.identity.sms.delivery", "status", "undelivered", "error_code", "30034",
                "country", "MA").count()).isEqualTo(1.0);
    }

    @Test
    void aMissingSignatureIsRefused() throws Exception {
        mockMvc.perform(form(callback("failed", "21408"))).andExpect(status().isForbidden());

        assertNothingRecorded();
    }

    @Test
    void aSignatureFromAnotherAuthTokenIsRefused() throws Exception {
        Map<String, String> params = callback("failed", "21408");

        mockMvc.perform(signed(params, sign("other-token", CALLBACK_URL, params))).andExpect(status().isForbidden());

        assertNothingRecorded();
    }

    @Test
    void aSignatureForAnotherUrlIsRefused() throws Exception {
        Map<String, String> params = callback("failed", "21408");

        mockMvc.perform(signed(params, sign(AUTH_TOKEN, "https://attacker.example/status", params)))
                .andExpect(status().isForbidden());

        assertNothingRecorded();
    }

    @Test
    void aTamperedParameterIsRefused() throws Exception {
        Map<String, String> params = callback("failed", "21408");
        String signature = sign(AUTH_TOKEN, CALLBACK_URL, params);
        params.put("MessageStatus", "delivered");

        mockMvc.perform(signed(params, signature)).andExpect(status().isForbidden());

        assertNothingRecorded();
    }

    @Test
    void anIntermediateStatusIsAcknowledgedButNotRecorded() throws Exception {
        Map<String, String> params = callback("sent", null);

        mockMvc.perform(signed(params, sign(AUTH_TOKEN, CALLBACK_URL, params))).andExpect(status().isNoContent());

        assertNothingRecorded();
    }

    private void assertNothingRecorded() {
        assertThat(logs.list).isEmpty();
        assertThat(metrics.find("gua.identity.sms.delivery").counters()).isEmpty();
    }

    private static Map<String, String> callback(String status, String errorCode) {
        Map<String, String> params = new TreeMap<>();
        params.put("MessageSid", "SM0123");
        params.put("MessageStatus", status);
        params.put("To", PHONE);
        params.put("AccountSid", "AC0123");
        if (errorCode != null) {
            params.put("ErrorCode", errorCode);
        }
        return params;
    }

    private static MockHttpServletRequestBuilder form(Map<String, String> params) {
        MockHttpServletRequestBuilder request = post(TwilioStatusCallbackController.PATH)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED);
        params.forEach(request::param);
        return request;
    }

    private static MockHttpServletRequestBuilder signed(Map<String, String> params, String signature) {
        return form(params).header(TwilioStatusCallbackController.SIGNATURE_HEADER, signature);
    }

    /** Twilio's scheme: HMAC-SHA1 over the URL followed by each parameter name and value, sorted by name. */
    private static String sign(String authToken, String url, Map<String, String> params) throws Exception {
        StringBuilder data = new StringBuilder(url);
        new TreeMap<>(params).forEach((name, value) -> data.append(name).append(value));
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(authToken.getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
        return Base64.getEncoder().encodeToString(mac.doFinal(data.toString().getBytes(StandardCharsets.UTF_8)));
    }
}
