package me.sarahlacerda.gua.identityservice.service;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;

@Service
@AllArgsConstructor
public class DirectoryService {

    private static final Logger log = LoggerFactory.getLogger(DirectoryService.class);

    private final DirectoryEntryRepository repository;

    /** A null displayName preserves the existing value. An empty string clears it. */
    @Transactional
    public DirectoryEntry upsertByDigest(String phoneDigest, String userId, String displayName) {
        return upsertByDigest(phoneDigest, null, userId, displayName);
    }

    @Transactional
    public DirectoryEntry upsertByDigest(String phoneDigest, String phoneMasked, String userId, String displayName) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
                .map(existing -> updateExisting(existing, phoneMasked, userId, displayName))
                .orElseGet(() -> DirectoryEntry.builder()
                        .phoneDigest(phoneDigest)
                        .phoneMasked(phoneMasked)
                        .userId(userId)
                        .displayName(displayName)
                        .build());
        return repository.save(entry);
    }

    private DirectoryEntry updateExisting(DirectoryEntry entry, String phoneMasked, String userId, String displayName) {
        entry.setUserId(userId);
        if (phoneMasked != null) {
            entry.setPhoneMasked(phoneMasked);
        }
        if (displayName != null) {
            entry.setDisplayName(displayName);
        } else if (entry.getDisplayName() != null) {
            log.debug("Preserving existing display name for user {} (null displayName in upsert)", userId);
        }
        return entry;
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> findByDigest(String phoneDigest) {
        return repository.findByPhoneDigest(phoneDigest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryEntry> findDiscoverableByDigests(Collection<String> digests) {
        return repository.findByPhoneDigestInAndDiscoverableTrue(digests);
    }

    @Transactional
    public void deleteByDigest(String digest) {
        repository.deleteByPhoneDigest(digest);
    }

    @Transactional(readOnly = true)
    public List<DirectoryEntry> findByUserId(String userId) {
        return repository.findByUserId(userId);
    }

    @Transactional(readOnly = true)
    public Optional<String> findMaskedPhoneByUserId(String userId) {
        return repository.findByUserId(userId).stream()
                .map(DirectoryEntry::getPhoneMasked)
                .filter(masked -> masked != null && !masked.isBlank())
                .findFirst();
    }

    @Transactional
    public DirectoryEntry assignRouting(String phoneDigest, String homeserverId, String username) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
                .orElseThrow(() -> new IllegalStateException(
                        "Cannot assign routing: no directory entry for the given phone digest"));
        if (homeserverId != null) {
            entry.setHomeserverId(homeserverId);
        }
        if (username != null) {
            entry.setUsername(username);
        }
        return repository.save(entry);
    }

    /** The builder does not carry discoverable, so a phone change must call this to preserve an opt-out. */
    @Transactional
    public DirectoryEntry setDiscoverable(String phoneDigest, boolean discoverable) {
        DirectoryEntry entry = repository.findByPhoneDigest(phoneDigest)
                .orElseThrow(() -> new IllegalStateException(
                        "Cannot set discoverable: no directory entry for the given phone digest"));
        entry.setDiscoverable(discoverable);
        return repository.save(entry);
    }

    @Transactional(readOnly = true)
    public boolean isUsernameTaken(String username) {
        return repository.existsByUsernameIgnoreCase(username);
    }

    @Transactional(readOnly = true)
    public Optional<DirectoryEntry> resolveByUsername(String username) {
        return repository.findByUsernameIgnoreCase(username);
    }
}
