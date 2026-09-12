package me.sarahlacerda.gua.identityservice.service.account;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;

/**
 * Creates the local records of a brand-new account as one unit: the directory row, this deployment's
 * routing choice, and the account's genesis row.
 *
 * <p>The three are one transaction because ADM-008 decision 6 puts the attach-proof verification inside
 * the account-creation transaction. A handle that was presented and fails to attach therefore fails the
 * whole signup: no directory row is left behind, and no account exists that silently fell back to a
 * bootstrap id. A signup that presents no handle at all takes the bootstrap branch, which is not a
 * failure.
 */
@Service
@RequiredArgsConstructor
public class AccountCreationService {

    private final DirectoryService directoryService;
    private final AccountGenesisService accountGenesisService;

    /**
     * What the login session knows about an account genesis when the profile step is submitted. The
     * handle and the challenge come from the server-side session; only the proof comes from the client.
     */
    public record GenesisAttachment(String attachHandle, String challengeB64, String proofB64, boolean nativeClient) {

        public boolean hasHandle() {
            return StringUtils.hasText(attachHandle);
        }

        /** A signup with no genesis in play at all, for callers that have no login session. */
        public static GenesisAttachment none(boolean nativeClient) {
            return new GenesisAttachment(null, null, null, nativeClient);
        }
    }

    /**
     * Writes the directory row, records the routing choice, and settles the account's accountId.
     *
     * @param attachment the session's genesis state; {@code null} when the feature is switched off, in
     *                   which case no genesis row is written at all and the behaviour is exactly what it
     *                   was before the feature existed
     */
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
