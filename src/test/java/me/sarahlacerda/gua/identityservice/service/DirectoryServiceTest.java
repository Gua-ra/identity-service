package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.List;

import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;

@ExtendWith(MockitoExtension.class)
class DirectoryServiceTest {

    @Mock
    private DirectoryEntryRepository repository;

    @InjectMocks
    private DirectoryService directoryService;

    @Test
    void retainsDisplayNameWhenNotProvided() {
        DirectoryEntry existing = DirectoryEntry.builder()
            .phoneDigest("digest")
            .userId("@user:gua.global")
            .displayName("Existing Name")
            .build();

        when(repository.findByPhoneDigest("digest")).thenReturn(Optional.of(existing));
        when(repository.save(existing)).thenReturn(existing);

        DirectoryEntry saved = directoryService.upsertByDigest("digest", "@user:gua.global", null);

        assertThat(saved.getDisplayName()).isEqualTo("Existing Name");
        verify(repository).save(existing);
    }

    @Test
    void createsNewEntryWhenMissing() {
        when(repository.findByPhoneDigest("new-digest")).thenReturn(Optional.empty());
        ArgumentCaptor<DirectoryEntry> captor = ArgumentCaptor.forClass(DirectoryEntry.class);
        when(repository.save(any(DirectoryEntry.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DirectoryEntry saved = directoryService.upsertByDigest("new-digest", "@new:gua.global", "Alice");

        verify(repository).save(captor.capture());
        DirectoryEntry persisted = captor.getValue();
        assertThat(persisted.getPhoneDigest()).isEqualTo("new-digest");
        assertThat(persisted.getUserId()).isEqualTo("@new:gua.global");
        assertThat(persisted.getDisplayName()).isEqualTo("Alice");
        assertThat(saved).isSameAs(persisted);
    }

    @Test
    void updatesDisplayNameWhenProvided() {
        DirectoryEntry existing = DirectoryEntry.builder()
            .phoneDigest("digest")
            .userId("@user:gua.global")
            .displayName("Old")
            .build();

        when(repository.findByPhoneDigest("digest")).thenReturn(Optional.of(existing));
        when(repository.save(existing)).thenReturn(existing);

        directoryService.upsertByDigest("digest", "@user:gua.global", "New");

        assertThat(existing.getDisplayName()).isEqualTo("New");
        verify(repository).save(existing);
    }

    @Test
    void lookupMatchesMapsEntities() {
        DirectoryEntry entry = DirectoryEntry.builder()
            .phoneDigest("digest")
            .userId("@user:gua.global")
            .displayName("Name")
            .build();

        when(repository.findByPhoneDigestIn(List.of("digest"))).thenReturn(List.of(entry));

        assertThat(directoryService.lookupMatches(List.of("digest"))).singleElement().satisfies(match -> {
            assertThat(match.digest()).isEqualTo("digest");
            assertThat(match.userId()).isEqualTo("@user:gua.global");
            assertThat(match.displayName()).isEqualTo("Name");
        });
    }

    @Test
    void delegatesFindAndDeleteOperations() {
        directoryService.findByDigest("digest");
        directoryService.findByUserId("@user:gua.global");
        directoryService.deleteByDigest("digest");

        verify(repository).findByPhoneDigest("digest");
        verify(repository).findByUserId("@user:gua.global");
        verify(repository).deleteByPhoneDigest("digest");
    }
}
