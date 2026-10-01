// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.Flow;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorityAlertPayloadTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-09-25T22:00:00Z"), ZoneOffset.UTC);

    @Test
    void theApnsAlertCarriesTheMarkerBesideTheAps() throws Exception {
        IdentityServiceProperties properties = propertiesWithKeys();
        HttpClient http = okClient();
        AuthorityApnsTransport transport = new AuthorityApnsTransport(properties, http, CLOCK);

        transport.send("device-token", "global.gua.dev.ios.prod", "Gua security", "A device asked");

        String body = bodyOf(http);
        assertThat(body).contains("\"" + AuthorityPushTransport.ALERT_MARKER + "\":\"1\"");
        assertThat(body).contains("\"title\":\"Gua security\"");
        assertThat(body).contains("time-sensitive");
    }

    @Test
    void theFcmAlertCarriesTheMarkerAndTheTextInData() throws Exception {
        IdentityServiceProperties properties = propertiesWithKeys();
        AuthorityFcmBearer bearer = mock(AuthorityFcmBearer.class);
        when(bearer.current()).thenReturn("stub-bearer");
        HttpClient http = okClient();
        AuthorityFcmTransport transport = new AuthorityFcmTransport(properties, bearer, http);

        transport.send("device-token", "global.gua.android", "Gua security", "A device asked");

        String body = bodyOf(http);
        assertThat(body).contains("\"" + AuthorityPushTransport.ALERT_MARKER + "\":\"1\"");
        assertThat(body).contains("\"data\":{");
        assertThat(body).contains("\"body\":\"A device asked\"");
    }

    private static IdentityServiceProperties propertiesWithKeys() throws Exception {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        var notifications = properties.getAuthority().getNotifications();
        notifications.getApns().setBaseUrl("https://api.push.apple.com");
        notifications.getApns().setKeyId("AAAAAAAAAA");
        notifications.getApns().setTeamId("BBBBBBBBBB");
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        notifications.getApns().setPrivateKeyPkcs8Base64(
                Base64.getEncoder().encodeToString(ec.generateKeyPair().getPrivate().getEncoded()));
        notifications.getFcm().setBaseUrl("https://fcm.googleapis.com");
        notifications.getFcm().setProjectId("gua-dev");
        return properties;
    }

    @SuppressWarnings("unchecked")
    private static HttpClient okClient() throws Exception {
        HttpClient http = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn("{}");
        when(http.send(any(), any())).thenReturn((HttpResponse) response);
        return http;
    }

    private static String bodyOf(HttpClient http) throws Exception {
        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(http).send(captor.capture(), any());
        return read(captor.getValue());
    }

    private static String read(HttpRequest request) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                out.writeBytes(chunk);
            }

            @Override
            public void onError(Throwable throwable) {
                throw new IllegalStateException(throwable);
            }

            @Override
            public void onComplete() {
            }
        });
        return out.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

}
