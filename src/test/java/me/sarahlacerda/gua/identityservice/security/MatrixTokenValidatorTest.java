package me.sarahlacerda.gua.identityservice.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.Optional;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.SocketPolicy;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

class MatrixTokenValidatorTest {

    private MockWebServer server;
    private MatrixTokenValidator validator;

    @BeforeEach
    void setUp() throws IOException {
        server = new MockWebServer();
        server.start();

        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getMatrix().setClientApiBaseUrl(server.url("/").toString());

        validator = new MatrixTokenValidator(WebClient.builder(), properties);
    }

    @AfterEach
    void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    void returnsUserIdOnSuccess() throws InterruptedException {
        server.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"user_id\":\"@user:gua.global\"}"));

        Optional<String> result = validator.validate("access-token");

        assertThat(result).contains("@user:gua.global");
        RecordedRequest request = server.takeRequest();
        assertThat(request.getPath()).isEqualTo("/_matrix/client/v3/account/whoami");
        assertThat(request.getHeader("Authorization")).isEqualTo("Bearer access-token");
    }

    @Test
    void returnsEmptyOnUnauthorized() {
        server.enqueue(new MockResponse().setResponseCode(401));

        Optional<String> result = validator.validate("bad-token");

        assertThat(result).isEmpty();
    }

    @Test
    void returnsEmptyOnConnectionFailure() {
        server.enqueue(new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AT_START));

        Optional<String> result = validator.validate("token");

        assertThat(result).isEmpty();
    }
}
