package me.sarahlacerda.gua.identityservice.service.account;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;

@Service
@RequiredArgsConstructor
public class AccountCreationService {

    private final DirectoryService directoryService;
    private final AccountGenesisService accountGenesisService;

    /** Handle and challenge come from the server-side session. Only the proof comes from the client. */
    public record GenesisAttachment(String attachHandle, String challengeB64, String proofB64, boolean nativeClient) {

        public boolean hasHandle() {
            return StringUtils.hasText(attachHandle);
        }

        public static GenesisAttachment none(boolean nativeClient) {
            return new GenesisAttachment(null, null, null, nativeClient);
        }
    }

    /** A null attachment means the feature is off and no genesis row is written. */
    @Transactional
    public void createAccount(String phoneDigest, String maskedPhone, String userId, String displayName,
            String homeserverId, String localpart, GenesisAttachment attachment) {
        directoryService.upsertByDigest(phoneDigest, maskedPhone, userId, displayName);
        directoryService.assignRouting(phoneDigest, homeserverId, localpart);

        if (attachment == null || !accountGenesisService.isEnabled()) {
            return;
        }
        if (attachment.hasHandle()) {
            accountGenesisService.attach(attachment.attachHandle(), attachment.challengeB64(),
                    attachment.proofB64(), userId);
            return;
        }
        if (attachment.nativeClient() && accountGenesisService.isRequiredForNative()) {
            throw new LoginFlowException(HttpStatus.BAD_REQUEST, "genesis_required",
                    "This app version can no longer create an account. Please update.");
        }
        accountGenesisService.bootstrap(userId);
    }
}
