package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.micrometer.core.instrument.MeterRegistry;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.placement.PlacementSchedulingConfig;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient;

@SpringBootTest
@ActiveProfiles("test")
class PlacementInertAtStartupTest {

        @Autowired
        private WebApplicationContext context;

        @Autowired
        private IdentityServiceProperties properties;

        @Autowired
        private MeterRegistry meterRegistry;

        @Autowired
        private ResolverPlacementClient resolverPlacementClient;

        @Test
        void theApplicationBootsWithEveryPlacementFlagOff() {
                IdentityServiceProperties.PlacementProperties placement = properties.getPlacement();
                assertThat(placement.getShadow().isEnabled()).isFalse();
                assertThat(placement.getShadow().isHealDirectory()).isFalse();
                assertThat(placement.getPublish().isEnabled()).isFalse();
                assertThat(placement.getMas().getAdminApi().isEnabled()).isFalse();
                assertThat(placement.getMas().getSql().isEnabled()).isFalse();
                assertThat(placement.getResolverBaseUrl()).isEmpty();
        }

        @Test
        void noBackgroundWorkIsScheduled() {
                assertThat(context.getBeanNamesForType(PlacementSchedulingConfig.class)).isEmpty();
        }

        @Test
        void noPlacementMeterIsRegistered() {
                assertThat(meterRegistry.getMeters())
                                .noneMatch(meter -> meter.getId().getName().startsWith("gua.identity.placement"));
        }

        @Test
        void noHttpClientIsBuiltForTheResolver() {
                assertThat(resolverPlacementClient.isConfigured()).isFalse();
        }

        @Test
        void anExistingOpenEndpointAnswersExactlyAsBefore() throws Exception {
                MockMvcBuilders.webAppContextSetup(context).build()
                                .perform(post("/otp/send").contentType(MediaType.APPLICATION_JSON))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.code").value("malformed_request"));
        }
}
