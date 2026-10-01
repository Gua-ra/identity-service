package me.sarahlacerda.gua.identityservice.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.ContactMatch;
import me.sarahlacerda.gua.identityservice.exception.LookupBatchTooLargeException;

// Raw numbers are digested in memory and never persisted or logged.
// Client-side hashing is not used: the phone keyspace is small enough to reverse by dictionary.
@Service
@RequiredArgsConstructor
public class ContactDiscoveryService {

    private static final Pattern E164 = Pattern.compile("^\\+[1-9]\\d{6,14}$");

    private final DirectoryService directoryService;
    private final PhoneNumberHasher phoneNumberHasher;
    private final IdentityServiceProperties properties;

    /** Invalid entries are skipped so one bad contact does not fail the sync. */
    public List<ContactMatch> match(List<String> phoneNumbers) {
        int maxBatch = properties.getDirectory().getMaxLookupBatch();
        if (phoneNumbers.size() > maxBatch) {
            throw new LookupBatchTooLargeException(
                    "At most " + maxBatch + " phone numbers can be matched per request");
        }
        Map<String, String> phoneByDigest = new LinkedHashMap<>();
        for (String phone : phoneNumbers) {
            if (phone != null && E164.matcher(phone).matches()) {
                phoneByDigest.putIfAbsent(phoneNumberHasher.digest(phone), phone);
            }
        }
        if (phoneByDigest.isEmpty()) {
            return List.of();
        }
        return directoryService.findDiscoverableByDigests(phoneByDigest.keySet()).stream()
                .map(entry -> new ContactMatch(
                        phoneByDigest.get(entry.getPhoneDigest()),
                        entry.getUserId(),
                        entry.getUsername(),
                        entry.getDisplayName()))
                .toList();
    }
}
