package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.ContactMatch;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException;
import me.sarahlacerda.gua.identityservice.exception.RateLimiterException;

@ExtendWith(MockitoExtension.class)
class ContactDiscoveryServiceTest {

    private static final String ACCOUNT = "@me:gua.global";

    @Mock
    private DirectoryService directoryService;

    @Mock
    private RateLimiter rateLimiter;

    private PhoneNumberHasher hasher;
    private IdentityServiceProperties properties;
    private ContactDiscoveryService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        properties.getDirectory().setPepper("test-pepper");
        properties.getDirectory().setMaxLookupBatch(3);
        hasher = new PhoneNumberHasher(properties);
        service = new ContactDiscoveryService(directoryService, hasher, properties, rateLimiter);
    }

    @Test
    void matchesValidPhonesAndMapsBackToSubmittedNumber() {
        String phone = "+5511999998888";
        String digest = hasher.digest(phone);
        DirectoryEntry entry = DirectoryEntry.builder()
            .phoneDigest(digest)
            .userId("@friend:gua.global")
            .username("friend")
            .displayName("Friend")
            .build();
        when(directoryService.findDiscoverableByDigests(Set.of(digest))).thenReturn(List.of(entry));

        List<ContactMatch> matches = service.match(ACCOUNT, List.of(phone));

        assertThat(matches).singleElement().satisfies(match -> {
            assertThat(match.phoneNumber()).isEqualTo(phone);
            assertThat(match.userId()).isEqualTo("@friend:gua.global");
            assertThat(match.username()).isEqualTo("friend");
            assertThat(match.displayName()).isEqualTo("Friend");
        });
    }

    @Test
    void skipsInvalidEntriesAndCollapsesDuplicates() {
        String phone = "+14165550123";
        String digest = hasher.digest(phone);
        when(directoryService.findDiscoverableByDigests(Set.of(digest))).thenReturn(List.of());

        // duplicate and garbage entries must not fail the sync (cap counts raw entries)
        service.match(ACCOUNT, java.util.Arrays.asList(phone, phone, "not-a-phone"));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Collection<String>> captor = ArgumentCaptor.forClass(Collection.class);
        verify(directoryService).findDiscoverableByDigests(captor.capture());
        assertThat(captor.getValue()).containsExactly(digest);
    }

    @Test
    void returnsEmptyWithoutQueryingWhenNothingIsValid() {
        assertThat(service.match(ACCOUNT, List.of("garbage", "123"))).isEmpty();
        org.mockito.Mockito.verifyNoInteractions(directoryService);
    }

    @Test
    void rejectsBatchesAboveTheConfiguredCap() {
        List<String> oversized = List.of("+551100000001", "+551100000002", "+551100000003", "+551100000004");

        assertThatThrownBy(() -> service.match(ACCOUNT, oversized))
            .isInstanceOf(LookupBatchTooLargeException.class)
            .hasMessageContaining("3");
        org.mockito.Mockito.verifyNoInteractions(rateLimiter);
    }

    @Test
    void everyLookupSpendsTheAccountsHourlyBudget() {
        properties.getDirectory().setMaxLookupsPerAccountPerHour(7);

        service.match(ACCOUNT, List.of("garbage"));

        verify(rateLimiter).checkRate("directory:lookup:account:" + ACCOUNT, 7, Duration.ofHours(1));
    }

    @Test
    void aSpentBudgetRefusesTheLookupBeforeAnyMatching() {
        org.mockito.Mockito.doThrow(new RateLimiterException("Rate limit exceeded", Duration.ofMinutes(10)))
            .when(rateLimiter).checkRate("directory:lookup:account:" + ACCOUNT, 60, Duration.ofHours(1));

        assertThatThrownBy(() -> service.match(ACCOUNT, List.of("+5511999998888")))
            .isInstanceOf(RateLimiterException.class);
        org.mockito.Mockito.verifyNoInteractions(directoryService);
    }
}
