// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorityPushTimeoutTest {

    @Test
    void aConnectionToAPushProviderTimesOut() {
        assertThat(AuthorityPushTransport.httpClient().build().connectTimeout())
                .contains(AuthorityPushTransport.CONNECT_TIMEOUT);
    }

    @Test
    void anApnsRequestTimesOut() throws Exception {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        IdentityServiceProperties.ApnsProperties apns = properties.getAuthority().getNotifications().getApns();
        apns.setBaseUrl("https://apns.example.invalid");
        apns.setKeyId("AAAAAAAAAA");
        apns.setTeamId("BBBBBBBBBB");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        apns.setPrivateKeyPkcs8Base64(
                Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded()));
        HttpClient http = answering(200, "");

        new AuthorityApnsTransport(properties, http, Clock.systemUTC()).send("a1b2", "global.gua", "t", "b");

        assertThat(sentThrough(http).timeout()).contains(AuthorityPushTransport.REQUEST_TIMEOUT);
    }

    @Test
    void anFcmRequestTimesOut() throws Exception {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getAuthority().getNotifications().getFcm().setBaseUrl("https://fcm.example.invalid");
        properties.getAuthority().getNotifications().getFcm().setProjectId("gua");
        AuthorityFcmBearer bearer = mock(AuthorityFcmBearer.class);
        when(bearer.current()).thenReturn("bearer");
        HttpClient http = answering(200, "{}");

        new AuthorityFcmTransport(properties, bearer, http).send("token", "global.gua", "t", "b");

        assertThat(sentThrough(http).timeout()).contains(AuthorityPushTransport.REQUEST_TIMEOUT);
    }

    @Test
    void theFcmTokenExchangeTimesOut() throws Exception {
        HttpClient http = answering(200, "{}");

        new AuthorityFcmBearer.HttpExchange(http).post("https://oauth.example.invalid/token", "grant_type=x");

        assertThat(sentThrough(http).timeout()).contains(AuthorityPushTransport.REQUEST_TIMEOUT);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static HttpClient answering(int status, String body) throws Exception {
        HttpClient http = mock(HttpClient.class);
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.body()).thenReturn(body);
        when(http.send(any(HttpRequest.class), any())).thenReturn(response);
        return http;
    }

    private static HttpRequest sentThrough(HttpClient http) throws Exception {
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(request.capture(), any());
        return request.getValue();
    }
}
