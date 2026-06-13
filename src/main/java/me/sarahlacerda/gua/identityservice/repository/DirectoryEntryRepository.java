package me.sarahlacerda.gua.identityservice.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;

public interface DirectoryEntryRepository extends JpaRepository<DirectoryEntry, UUID> {
    Optional<DirectoryEntry> findByPhoneDigest(String phoneDigest);

    List<DirectoryEntry> findByPhoneDigestIn(Iterable<String> phoneDigests);

    List<DirectoryEntry> findByUserId(String userId);

    /** Case-insensitive lookup of the global username (matches the unique index). */
    Optional<DirectoryEntry> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    void deleteByPhoneDigest(String phoneDigest);
}
