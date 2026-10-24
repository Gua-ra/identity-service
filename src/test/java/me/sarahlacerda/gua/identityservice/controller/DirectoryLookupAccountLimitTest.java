package me.sarahlacerda.gua.identityservice.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.RateLimitRule;
import me.sarahlacerda.gua.identityservice.security.AuthenticatedUserAccessor;
import me.sarahlacerda.gua.identityservice.security.OidcAuthenticationToken;
import me.sarahlacerda.gua.identityservice.service.ContactDiscoveryService;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.RateLimiter;
import me.sarahlacerda.gua.identityservice.service.oidc.OidcAuthenticatedPrincipal;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;
import me.sarahlacerda.gua.identityservice.web.ratelimit.EndpointRateLimiter;
import me.sarahlacerda.gua.identityservice.web.ratelimit.RateLimitingInterceptor;

/**
 * The per-account lookup budget against a real Redis, behind the endpoint limiter, which keys
 * each bucket by account and address.
 */
@Testcontainers
class DirectoryLookupAccountLimitTest {

    private static final String ACCOUNT = "@me:gua.global";
    private static final String BODY = "{\"phones\":[\"+5511999998888\"]}";

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;

    private MockMvc mockMvc;

    @BeforeAll
    static void connect() {
        connectionFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(redis.getHost(), redis.getMappedPort(6379)));
        connectionFactory.afterPropertiesSet();
        connectionFactory.start();
    }

    @AfterAll
    static void disconnect() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        StringRedisTemplate redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushAll();
            return null;
        });

        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getDirectory().setPepper("test-pepper");
        properties.getDirectory().setMaxLookupsPerAccountPerHour(3);
        RateLimitRule lookupRule = new RateLimitRule();
        lookupRule.setPath("/directory/lookup");
        lookupRule.setMethods(Set.of(HttpMethod.POST));
        lookupRule.setLimitForPeriod(30);
        lookupRule.setRefreshPeriod(Duration.ofMinutes(5));
        properties.getRateLimits().getEndpoints().add(lookupRule);

        DirectoryService directoryService = Mockito.mock(DirectoryService.class);
        ContactDiscoveryService contactDiscovery = new ContactDiscoveryService(directoryService,
                new PhoneNumberHasher(properties), properties, new RateLimiter(redisTemplate));
        DirectoryController controller = new DirectoryController(directoryService, contactDiscovery,
                Mockito.mock(HomeserverRegistry.class), new AuthenticatedUserAccessor());
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setMessageConverters(new MappingJackson2HttpMessageConverter())
                .setControllerAdvice(new RestExceptionHandler())
                .addInterceptors(new RateLimitingInterceptor(new EndpointRateLimiter(properties)))
                .build();
    }

    @AfterEach
    void signOut() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void theAccountBudgetIsSharedAcrossAddresses() throws Exception {
        lookup(ACCOUNT, "198.51.100.7").andExpect(status().isOk());
        lookup(ACCOUNT, "198.51.100.7").andExpect(status().isOk());
        lookup(ACCOUNT, "203.0.113.9").andExpect(status().isOk());

        // A fresh address has a fresh endpoint bucket but not a fresh account budget.
        lookup(ACCOUNT, "203.0.113.9")
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.code").value("rate_limited"))
                .andExpect(header().exists("Retry-After"));
        lookup(ACCOUNT, "192.0.2.44").andExpect(status().isTooManyRequests());

        lookup("@someone-else:gua.global", "203.0.113.9").andExpect(status().isOk());
    }

    private ResultActions lookup(String account, String address) throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new OidcAuthenticationToken(
                new OidcAuthenticatedPrincipal(account, null, null, Set.of("openid")), "token"));
        return mockMvc.perform(post("/directory/lookup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(BODY)
                .with(request -> {
                    request.setRemoteAddr(address);
                    return request;
                }));
    }
}
