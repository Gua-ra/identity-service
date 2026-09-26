// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Instant;

/**
 * The out-of-band channel a pending authority transition is announced on (ADM-009 gate 2).
 *
 * <p>Every window in ADM-009 rests entirely on this. An adoption, a grant and a revocation of another
 * device all complete unless the account holder objects inside the window, so a window the holder never
 * hears about is not a control, it is a delay. That is why gate 2 blocks production rather than being an
 * aspiration.
 *
 * <p><b>What does not count as a channel, and why.</b>
 * <ul>
 * <li>A log line. {@code DeviceNotificationService} has one implementation today and that is what it
 * writes. Nobody outside the operator reads it.</li>
 * <li>The account's phone number. It is the channel the SIM-swap attacker holds, and the SIM swap is the
 * attack the adoption window exists to make expensive.</li>
 * <li>A signed-in session. Completing an account recovery revokes the account's sessions in the same
 * transaction that mints the attacker's PIN, so the session channel is empty at exactly the moment it
 * would be needed.</li>
 * </ul>
 *
 * <p>An implementation therefore has to reach the holder through something that survives both. Until one
 * is wired, {@link AuthorityNotificationGate} refuses to start a deployment with
 * {@code identity.authority.enabled=true}: {@link #isOutOfBand()} is how an implementation declares that
 * it is such a channel, and the shipped one answers false.
 */
public interface AuthorityNotifier {

    /**
     * Whether this implementation reaches the account holder on a channel that neither a SIM swap nor an
     * account recovery empties.
     *
     * <p>Declared rather than inferred, and answered false by the shipped implementation. A notifier that
     * answers true is asserting the property gate 2 requires, so the assertion belongs in the
     * implementation that can be read next to the transport it uses.
     */
    boolean isOutOfBand();

    /**
     * Whether this implementation reaches <em>this</em> account holder out of band right now.
     *
     * <p>The per-account half of the same claim, and the one a transition consults. {@link #isOutOfBand()}
     * answers a question about the deployment, which is what the startup gate needs; a window, though, is a
     * promise made to one account holder, and an account with no live registration has nothing behind that
     * promise. Answering the deployment question for both would let gate 2 pass on the existence of a
     * transport while the owner of the account being rooted is told nothing.
     *
     * <p>False by default, because an implementation that is not a channel is not a channel for anybody.
     */
    default boolean reachesOutOfBand(String userId) {
        return false;
    }

    /**
     * A transition has been recorded and its window is running.
     *
     * @param userId       the account holder
     * @param transition   what was started, in the reader's own words
     * @param deviceLabel  the label the record carried, which is the only thing a notification may name
     *                     about the device
     * @param effectiveAt  when it completes if nobody objects
     */
    void notifyTransitionPending(String userId, String transition, String deviceLabel, Instant effectiveAt);

    /** A pending transition was cancelled, by an opposition or by a higher-rank record. */
    void notifyTransitionCancelled(String userId, String transition, String deviceLabel);

    /** A transition took effect, whether after its window or immediately. */
    void notifyTransitionCompleted(String userId, String transition, String deviceLabel);

    /**
     * A security-notification registration was removed from the account.
     *
     * <p>Announced because removing a channel is how an attacker would go quiet before opening a window, so
     * the remaining installs are told rather than left to notice. A default no-op, so an implementation that
     * is not a channel has nothing to say about one being taken away.
     */
    default void notifyChannelRemoved(String userId, String deviceLabel) {
    }
}
