package me.sarahlacerda.gua.identityservice.client.matrix;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

class WebClientMatrixAdminClientWireMockTest {

    private static final String USER_PATH_REGEX = "/_synapse/admin/v2/users/.+";

    private WireMockServer wireMock;
    private WebClientMatrixAdminClient client;

    @BeforeEach
    void start() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();

        IdentityServiceProperties properties = new IdentityServiceProperties();
        IdentityServiceProperties.MatrixProperties matrix = properties.getMatrix();
        matrix.setAdminApiBaseUrl(wireMock.baseUrl());
        matrix.setClientApiBaseUrl(wireMock.baseUrl());
        matrix.setHomeserverDomain("example.com");
        matrix.setAdminAccessToken("admin-token-abc");
        matrix.setUserLocalpartPrefix("gua");

        client = new WebClientMatrixAdminClient(WebClient.builder(), properties);
    }

    @AfterEach
    void stop() {
        wireMock.stop();
    }

    @Test
    void upsertUserSendsPutWithThreepidAndDisplayName() {
        wireMock.stubFor(put(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse().withStatus(200)));

        client.upsertUser("@user:example.com", "secret-pw", "+15551234567", "Alice");

        wireMock.verify(putRequestedFor(urlPathMatching(USER_PATH_REGEX))
            .withHeader("Authorization", equalTo("Bearer admin-token-abc"))
            .withRequestBody(matchingJsonPath("$.password", equalTo("secret-pw")))
            .withRequestBody(matchingJsonPath("$.deactivated", equalTo("false")))
            .withRequestBody(matchingJsonPath("$.displayname", equalTo("Alice")))
            .withRequestBody(matchingJsonPath("$.threepids[0].medium", equalTo("msisdn")))
            .withRequestBody(matchingJsonPath("$.threepids[0].address", equalTo("+15551234567"))));
    }

    @Test
    void upsertUserOmitsThreepidsAndDisplayNameWhenNotProvided() {
        wireMock.stubFor(put(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse().withStatus(200)));

        client.upsertUser("@user:example.com", "secret-pw", null, null);

        List<LoggedRequest> puts = wireMock.findAll(putRequestedFor(urlPathMatching(USER_PATH_REGEX)));
        assertThat(puts).hasSize(1);
        String body = puts.get(0).getBodyAsString();
        assertThat(body).contains("\"password\":\"secret-pw\"");
        assertThat(body).doesNotContain("threepids");
        assertThat(body).doesNotContain("displayname");
    }

    @Test
    void getLinkedPhonesFiltersToMsisdnOnly() {
        wireMock.stubFor(get(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "threepids": [
                        {"medium": "email", "address": "alice@example.com"},
                        {"medium": "msisdn", "address": "+15551234567"},
                        {"medium": "msisdn", "address": "+15557654321"}
                      ]
                    }
                    """)));

        List<String> phones = client.getLinkedPhones("@user:example.com");

        assertThat(phones).containsExactly("+15551234567", "+15557654321");
    }

    @Test
    void linkPhoneReadsExistingThreepidsAndAppendsNewOne() {
        wireMock.stubFor(get(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "threepids": [
                        {"medium": "msisdn", "address": "+15551234567"}
                      ]
                    }
                    """)));
        wireMock.stubFor(put(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse().withStatus(200)));

        client.linkPhone("@user:example.com", "+15557654321");

        wireMock.verify(getRequestedFor(urlPathMatching(USER_PATH_REGEX)));
        wireMock.verify(putRequestedFor(urlPathMatching(USER_PATH_REGEX))
            .withRequestBody(equalToJson("""
                {
                  "threepids": [
                    {"medium": "msisdn", "address": "+15551234567"},
                    {"medium": "msisdn", "address": "+15557654321"}
                  ]
                }
                """)));
    }

    @Test
    void linkPhoneIsNoopWhenPhoneAlreadyLinked() {
        wireMock.stubFor(get(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {"threepids":[{"medium":"msisdn","address":"+15551234567"}]}
                    """)));

        client.linkPhone("@user:example.com", "+15551234567");

        assertThat(wireMock.findAll(putRequestedFor(urlPathMatching(USER_PATH_REGEX)))).isEmpty();
    }

    @Test
    void unlinkPhoneRemovesMatchingMsisdnAndPutsFilteredList() {
        wireMock.stubFor(get(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "threepids": [
                        {"medium": "msisdn", "address": "+15551234567"},
                        {"medium": "msisdn", "address": "+15557654321"},
                        {"medium": "email", "address": "alice@example.com"}
                      ]
                    }
                    """)));
        wireMock.stubFor(put(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse().withStatus(200)));

        client.unlinkPhone("@user:example.com", "+15551234567");

        wireMock.verify(putRequestedFor(urlPathMatching(USER_PATH_REGEX))
            .withRequestBody(equalToJson("""
                {
                  "threepids": [
                    {"medium": "msisdn", "address": "+15557654321"},
                    {"medium": "email", "address": "alice@example.com"}
                  ]
                }
                """)));
    }

    @Test
    void unlinkPhoneIsNoopWhenPhoneNotLinked() {
        wireMock.stubFor(get(urlPathMatching(USER_PATH_REGEX))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {"threepids":[{"medium":"msisdn","address":"+15557654321"}]}
                    """)));

        client.unlinkPhone("@user:example.com", "+15551111111");

        assertThat(wireMock.findAll(putRequestedFor(urlPathMatching(USER_PATH_REGEX)))).isEmpty();
    }

    @Test
    void findUserIdByPhoneResolvesViaThreepidBinding() {
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.+"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {"user_id": "@user:example.com"}
                    """)));

        assertThat(client.findUserIdByPhone("+15551234567"))
            .contains("@user:example.com");

        wireMock.verify(getRequestedFor(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.+"))
            .withHeader("Authorization", equalTo("Bearer admin-token-abc")));
    }

    @Test
    void findUserIdByPhoneReturnsEmptyWhenNotBound() {
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.+"))
            .willReturn(aResponse()
                .withStatus(404)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {"errcode": "M_NOT_FOUND", "error": "User not found"}
                    """)));

        assertThat(client.findUserIdByPhone("+15551234567")).isEmpty();
    }

    @Test
    void findUserIdByPhoneReturnsEmptyForBlankInput() {
        assertThat(client.findUserIdByPhone(null)).isEmpty();
        assertThat(client.findUserIdByPhone("  ")).isEmpty();
    }

    @Test
    void loginPostsCredentialsAndParsesAccessToken() {
        wireMock.stubFor(post(urlEqualTo("/_matrix/client/v3/login"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "user_id": "@user:example.com",
                      "access_token": "syt_abc123",
                      "device_id": "DEVICE1",
                      "home_server": "example.com"
                    }
                    """)));

        MatrixLoginResponse response = client.login("@user:example.com", "secret-pw");

        assertThat(response.accessToken()).isEqualTo("syt_abc123");
        assertThat(response.userId()).isEqualTo("@user:example.com");
        assertThat(response.deviceId()).isEqualTo("DEVICE1");

        wireMock.verify(postRequestedFor(urlEqualTo("/_matrix/client/v3/login"))
            .withRequestBody(matchingJsonPath("$.type", equalTo("m.login.password")))
            .withRequestBody(matchingJsonPath("$.identifier.type", equalTo("m.id.user")))
            .withRequestBody(matchingJsonPath("$.identifier.user", equalTo("@user:example.com")))
            .withRequestBody(matchingJsonPath("$.password", equalTo("secret-pw"))));
    }
}
