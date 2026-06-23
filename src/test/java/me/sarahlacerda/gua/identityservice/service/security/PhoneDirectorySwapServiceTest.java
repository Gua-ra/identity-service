package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.PhoneAlreadyLinkedException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberMasker;

@ExtendWith(MockitoExtension.class)
class PhoneDirectorySwapServiceTest {

    private static final String USER = "@alice:gua.global";
    private static final String OTHER = "@bob:gua.global";
    private static final String NEW_E164 = "+14155550123";
    private static final String NEW_DIGEST = "new-digest";
    private static final String OLD_DIGEST = "old-digest";

    @Mock
    private DirectoryService directoryService;
    @Mock
    private UserSecurityService userSecurityService;
    @Mock
    private PhoneNumberHasher phoneNumberHasher;

    private PhoneDirectorySwapService swapService;

    @BeforeEach
    void setUp() {
        swapService = new PhoneDirectorySwapService(
                directoryService, userSecurityService, phoneNumberHasher, new PhoneNumberMasker());
        when(phoneNumberHasher.digest(NEW_E164)).thenReturn(NEW_DIGEST);
    }

    @Test
    void rejectsWhenNewNumberOwnedByAnotherAccountWithoutMutating() {
        // The target digest already belongs to Bob: upsertByDigest would reassign it
        // via an UPDATE (digest unchanged -> UNIQUE never fires), hijacking Bob's row.
        when(directoryService.findByDigest(NEW_DIGEST)).thenReturn(Optional.of(
                DirectoryEntry.builder().phoneDigest(NEW_DIGEST).userId(OTHER).build()));

        assertThatThrownBy(() -> swapService.swap(USER, NEW_E164))
                .isInstanceOf(PhoneAlreadyLinkedException.class);

        // Nothing destructive happened (transaction would roll back regardless).
        verify(directoryService, never()).deleteByDigest(anyString());
        verify(directoryService, never()).upsertByDigest(anyString(), anyString(), anyString(), anyString());
        verify(userSecurityService, never()).stampPhoneChange(anyString());
    }

    @Test
    void allowsWhenNewDigestAlreadyOwnedByCaller() {
        // Idempotent re-run: the new digest is already the caller's — not a conflict.
        when(directoryService.findByDigest(NEW_DIGEST)).thenReturn(Optional.of(
                DirectoryEntry.builder().phoneDigest(NEW_DIGEST).userId(USER).build()));
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest(NEW_DIGEST).userId(USER).build()));

        swapService.swap(USER, NEW_E164);

        verify(userSecurityService).stampPhoneChange(USER);
    }

    @Test
    void carriesForwardAndDeletesOldRows() {
        when(directoryService.findByDigest(NEW_DIGEST)).thenReturn(Optional.empty());
        DirectoryEntry old = DirectoryEntry.builder()
                .phoneDigest(OLD_DIGEST)
                .userId(USER)
                .username("alice")
                .homeserverId("hs-1")
                .displayName("Alice")
                .build();
        old.setDiscoverable(false); // user opted OUT of discovery
        when(directoryService.findByUserId(USER)).thenReturn(List.of(old));

        swapService.swap(USER, NEW_E164);

        verify(directoryService).deleteByDigest(OLD_DIGEST);
        verify(directoryService).upsertByDigest(eq(NEW_DIGEST), anyString(), eq(USER), eq("Alice"));
        verify(directoryService).assignRouting(NEW_DIGEST, "hs-1", "alice");
        // Regression guard: the @Builder drops discoverable; the opt-out must survive.
        verify(directoryService).setDiscoverable(NEW_DIGEST, false);
        verify(userSecurityService).stampPhoneChange(USER);
    }

    @Test
    void mapsUniqueViolationFromConcurrentInsertToConflict() {
        when(directoryService.findByDigest(NEW_DIGEST)).thenReturn(Optional.empty());
        when(directoryService.findByUserId(USER)).thenReturn(List.of(
                DirectoryEntry.builder().phoneDigest(OLD_DIGEST).userId(USER).build()));
        when(directoryService.upsertByDigest(eq(NEW_DIGEST), anyString(), eq(USER), org.mockito.ArgumentMatchers.any()))
                .thenThrow(new DataIntegrityViolationException("unique"));

        assertThatThrownBy(() -> swapService.swap(USER, NEW_E164))
                .isInstanceOf(PhoneAlreadyLinkedException.class);

        verify(userSecurityService, never()).stampPhoneChange(anyString());
    }
}
