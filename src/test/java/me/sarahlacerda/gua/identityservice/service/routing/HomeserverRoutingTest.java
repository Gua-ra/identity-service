package me.sarahlacerda.gua.identityservice.service.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;

class HomeserverRoutingTest {

    private IdentityServiceProperties propsWithLegacyHomeserver() {
        IdentityServiceProperties props = new IdentityServiceProperties();
        props.getMatrix().setHomeserverDomain("dev.local");
        props.getMatrix().setAdminApiBaseUrl("http://hs/admin");
        props.getMatrix().setClientApiBaseUrl("http://hs/client");
        props.getMatrix().setAdminAccessToken("tok");
        return props;
    }

    private HomeserverConfig hs(String id, String domain, String region, int weight, boolean enabled) {
        HomeserverConfig c = new HomeserverConfig();
        c.setId(id);
        c.setDomain(domain);
        c.setAdminApiBaseUrl("http://" + id + "/admin");
        c.setClientApiBaseUrl("http://" + id + "/client");
        c.setAdminAccessToken("tok-" + id);
        c.setRegion(region);
        c.setWeight(weight);
        c.setEnabled(enabled);
        return c;
    }

    private HomeserverRegistry registry(IdentityServiceProperties props) {
        HomeserverRegistry registry = new HomeserverRegistry(props);
        registry.init();
        return registry;
    }

    @Test
    void synthesizesLegacyHomeserverWhenNoneConfigured() {
        HomeserverRegistry registry = registry(propsWithLegacyHomeserver());

        assertThat(registry.all()).hasSize(1);
        Homeserver legacy = registry.getDefault();
        assertThat(legacy.id()).isEqualTo(HomeserverRegistry.LEGACY_ID);
        assertThat(legacy.domain()).isEqualTo("dev.local");
    }

    @Test
    void singleStrategyAlwaysReturnsDefault() {
        IdentityServiceProperties props = propsWithLegacyHomeserver();
        props.getRouting().setStrategy("single");
        props.getRouting().getHomeservers().add(hs("a", "a.gua.app", "br", 1, true));
        props.getRouting().getHomeservers().add(hs("b", "b.gua.app", "eu", 1, true));
        props.getRouting().setDefaultHomeserverId("a");
        HomeserverRegistry registry = registry(props);
        DefaultHomeserverRouter router = new DefaultHomeserverRouter(registry, props);

        for (int i = 0; i < 20; i++) {
            assertThat(router.selectForNewAccount(AccountPlacementContext.empty()).id()).isEqualTo("a");
        }
    }

    @Test
    void regionStrategyPlacesByRegionHint() {
        IdentityServiceProperties props = propsWithLegacyHomeserver();
        props.getRouting().setStrategy("region");
        props.getRouting().getHomeservers().add(hs("br1", "br.gua.app", "br", 1, true));
        props.getRouting().getHomeservers().add(hs("eu1", "eu.gua.app", "eu", 1, true));
        HomeserverRegistry registry = registry(props);
        DefaultHomeserverRouter router = new DefaultHomeserverRouter(registry, props);

        Homeserver chosen = router.selectForNewAccount(new AccountPlacementContext(null, "eu"));
        assertThat(chosen.id()).isEqualTo("eu1");
    }

    @Test
    void weightedStrategyNeverPicksDisabledHomeserver() {
        IdentityServiceProperties props = propsWithLegacyHomeserver();
        props.getRouting().setStrategy("weighted");
        props.getRouting().getHomeservers().add(hs("a", "a.gua.app", null, 5, true));
        props.getRouting().getHomeservers().add(hs("disabled", "x.gua.app", null, 5, false));
        props.getRouting().setDefaultHomeserverId("a");
        HomeserverRegistry registry = registry(props);
        DefaultHomeserverRouter router = new DefaultHomeserverRouter(registry, props);

        for (int i = 0; i < 50; i++) {
            assertThat(router.selectForNewAccount(AccountPlacementContext.empty()).enabled()).isTrue();
        }
    }

    @Test
    void rejectsDuplicateHomeserverIds() {
        IdentityServiceProperties props = propsWithLegacyHomeserver();
        props.getRouting().getHomeservers().add(hs("dup", "a.gua.app", null, 1, true));
        props.getRouting().getHomeservers().add(hs("dup", "b.gua.app", null, 1, true));

        assertThatThrownBy(() -> registry(props)).isInstanceOf(IllegalStateException.class);
    }
}
