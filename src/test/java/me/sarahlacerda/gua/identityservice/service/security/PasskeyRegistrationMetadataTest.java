package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.data.ByteArray;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;
import me.sarahlacerda.gua.identityservice.service.oidc.LoginSession;

/**
 * What a credential manager shows for a Gua passkey, and what the authenticator stores for it.
 *
 * <p>The label is the account's own handle and the stored user handle is the principal's canonical bytes.
 * Neither carries the Matrix id, the phone number or the accountId text: a label is synced to every device the
 * manager reaches and cannot be changed once the credential exists.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyRegistrationMetadataTest {

    private static final String HOME_DOMAIN = "gua.global";
    private static final String USER_ID = "@alice:" + HOME_DOMAIN;
    private static final String PHONE = "+15550100200";
    private static final String USERNAME = "alice";
    private static final String DISPLAY_NAME = "Alice Example";
    private static final AccountId ACCOUNT = AccountId.derive(
            AccountId.CLASS_BOOTSTRAP, "registration-metadata-fixture".getBytes(StandardCharsets.UTF_8));
    private static final String PRINCIPAL = ACCOUNT.value();
    private static final Pattern CANONICAL_ACCOUNT_ID = Pattern.compile(AccountId.CANONICAL_PATTERN);

    @Mock
    private PasskeyCredentialRepository repository;
    @Mock
    private PasskeyPrincipals principals;
    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private PasskeyService service;

    @BeforeEach
    void setUp() {
        LoginFlowProperties properties = new LoginFlowProperties();
        properties.getPasskeys().setRpId(HOME_DOMAIN);
        properties.getPasskeys().setOrigins(new ArrayList<>(List.of("https://identity." + HOME_DOMAIN)));
        service = new PasskeyService(repository, principals, properties, redisTemplate, objectMapper);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(principals.forUserId(USER_ID))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(PRINCIPAL, ACCOUNT.rawBytes())));
    }

    private static LoginSession session(String username, String displayName) {
        LoginSession session = new LoginSession();
        session.setUserId(USER_ID);
        session.setPhoneNumber(PHONE);
        session.setPreferredUsername(username);
        session.setDisplayName(displayName);
        return session;
    }

    private JsonNode storedOptions(String sessionId) throws Exception {
        ArgumentCaptor<String> stored = ArgumentCaptor.forClass(String.class);
        verify(valueOperations).set(eq("passkey:registration:" + sessionId), stored.capture(), any());
        return objectMapper.readTree(stored.getValue());
    }

    private static List<String> textValues(JsonNode node) {
        List<String> values = new ArrayList<>();
        collectText(node, values);
        return values;
    }

    private static void collectText(JsonNode node, List<String> into) {
        if (node.isTextual()) {
            into.add(node.asText());
            return;
        }
        node.forEach(child -> collectText(child, into));
    }

    @Test
    void theRelyingPartyIsGuaOnTheConfiguredId() {
        JsonNode options = service.startRegistration("s-1", session(USERNAME, DISPLAY_NAME));

        assertThat(options.path("rp").path("name").asText()).isEqualTo("Gua");
        assertThat(options.path("rp").path("id").asText()).isEqualTo(HOME_DOMAIN);
    }

    @Test
    void theHandleIsThePrincipalsCanonicalBytes() throws Exception {
        JsonNode options = service.startRegistration("s-1", session(USERNAME, DISPLAY_NAME));

        byte[] handle = ByteArray.fromBase64Url(options.path("user").path("id").asText()).getBytes();

        assertThat(handle).hasSize(AccountId.RAW_LENGTH);
        assertThat(AccountId.fromRawBytes(handle).value()).isEqualTo(PRINCIPAL);
    }

    @Test
    void theLabelIsTheAccountHandleAndTheDisplayNameIsTheDirectoryOne() {
        JsonNode options = service.startRegistration("s-1", session(" " + USERNAME + " ", DISPLAY_NAME));

        assertThat(options.path("user").path("name").asText()).isEqualTo("@" + USERNAME);
        assertThat(options.path("user").path("displayName").asText()).isEqualTo(DISPLAY_NAME);
    }

    @Test
    void aBlankDisplayNameFallsBackToTheLabel() {
        JsonNode options = service.startRegistration("s-1", session(USERNAME, "  "));

        assertThat(options.path("user").path("displayName").asText())
                .isEqualTo(options.path("user").path("name").asText())
                .isEqualTo("@" + USERNAME);
    }

    @Test
    void aBlankUsernameFallsBackToTheDisplayNameAndNeverToTheMatrixId() {
        JsonNode options = service.startRegistration("s-1", session(null, DISPLAY_NAME));

        assertThat(options.path("user").path("name").asText()).isEqualTo(DISPLAY_NAME);
        assertThat(options.toString()).doesNotContain(USER_ID);
    }

    @Test
    void nothingTheBrowserSeesNamesTheMatrixIdThePhoneOrTheAccountId() {
        JsonNode options = service.startRegistration("s-1", session(USERNAME, DISPLAY_NAME));

        assertThat(options.toString())
                .doesNotContain(":" + HOME_DOMAIN)
                .doesNotContain(USER_ID)
                .doesNotContain(PHONE)
                .doesNotContain(PRINCIPAL);
        assertThat(textValues(options))
                .noneMatch(value -> CANONICAL_ACCOUNT_ID.matcher(value).matches())
                .noneMatch(value -> value.startsWith(AccountId.PREFIX) && value.length() == AccountId.LENGTH)
                .noneMatch(value -> value.startsWith("@") && value.contains(":"));
    }

    /**
     * The library's user stays the principal: it keys excludeCredentials, the step-up allow list and the
     * handle mapping, and the stored ceremony is what finishRegistration verifies against.
     */
    @Test
    void theStoredCeremonyStillKeysOnThePrincipal() throws Exception {
        service.startRegistration("s-1", session(USERNAME, DISPLAY_NAME));

        JsonNode stored = storedOptions("s-1");

        assertThat(stored.path("user").path("name").asText()).isEqualTo(PRINCIPAL);
        assertThat(stored.path("user").path("id").asText())
                .isEqualTo(new ByteArray(ACCOUNT.rawBytes()).getBase64Url());
        assertThat(stored.toString()).doesNotContain(USER_ID).doesNotContain(PHONE);
    }

    /** The relabelled copy finishes the stored ceremony: same challenge, same handle. */
    @Test
    void theBrowserCopyAndTheStoredCopyShareTheChallengeAndTheHandle() throws Exception {
        JsonNode options = service.startRegistration("s-1", session(USERNAME, DISPLAY_NAME));

        JsonNode stored = storedOptions("s-1");

        assertThat(options.path("challenge").asText()).isEqualTo(stored.path("challenge").asText());
        assertThat(options.path("user").path("id").asText()).isEqualTo(stored.path("user").path("id").asText());
    }

    /** Stable handle canonical: what the account is called never reaches the bytes the authenticator keeps. */
    @Test
    void theHandleIsTheSameWhateverTheAccountIsCalled() {
        JsonNode first = service.startRegistration("s-1", session("alice", "Alice"));
        JsonNode second = service.startRegistration("s-2", session("alice-renamed", "A. Example"));

        assertThat(first.path("user").path("id").asText()).isEqualTo(second.path("user").path("id").asText());
        assertThat(first.path("user").path("name").asText())
                .isNotEqualTo(second.path("user").path("name").asText());
    }
}
