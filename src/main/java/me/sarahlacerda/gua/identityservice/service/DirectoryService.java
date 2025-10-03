package me.sarahlacerda.gua.identityservice.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import lombok.AllArgsConstructor;
import me.sarahlacerda.gua.identityservice.domain.DirectoryMatch;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;

@Service
@AllArgsConstructor
public class DirectoryService {

    private final DirectoryEntryRepository repository;

    @Transactional
    public DirectoryEntry upsertByDigest(String phoneDigest, String userId, String displayName) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
            .map(existing -> updateExisting(existing, userId, displayName))
            .orElseGet(() -> DirectoryEntry.builder()
                .phoneDigest(phoneDigest)
                .userId(userId)
                .displayName(displayName)
                .build());
        return repository.save(entry);
    }

    private DirectoryEntry updateExisting(DirectoryEntry entry, String userId, String displayName) {
        entry.setUserId(userId);
        if (displayName != null) {
            entry.setDisplayName(displayName);
        }
        return entry;
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> findByDigest(String phoneDigest) {
        return repository.findByPhoneDigest(phoneDigest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryMatch> lookupMatches(Collection<String> digests) {
        return repository.findByPhoneDigestIn(digests).stream()
            .map(entry -> new DirectoryMatch(entry.getPhoneDigest(), entry.getUserId(), entry.getDisplayName()))
            .toList();
    }

    @Transactional
    public void deleteByDigest(String digest) {
        repository.deleteByPhoneDigest(digest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryEntry> findByUserId(String userId) {
        return repository.findByUserId(userId);
    }
}
