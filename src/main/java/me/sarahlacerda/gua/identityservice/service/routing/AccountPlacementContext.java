package me.sarahlacerda.gua.identityservice.service.routing;

import java.util.Optional;

/**
 * Inputs the router may use to decide where a brand-new account should live.
 * Everything is optional so callers supply only what they know; the router
 * degrades gracefully (e.g. to the default homeserver) when hints are absent.
 *
 * @param e164PhoneNumber the account's phone (E.164), verified by this service's OTP step; it may inform
 *                        this deployment's own placement choice, which is not a committed placement
 *                        record (ADM-001 L6)
 * @param regionHint      an explicit region/tenant hint, if the caller has one
 */
public record AccountPlacementContext(String e164PhoneNumber, String regionHint) {

    public static AccountPlacementContext empty() {
        return new AccountPlacementContext(null, null);
    }

    public static AccountPlacementContext forPhone(String e164PhoneNumber) {
        return new AccountPlacementContext(e164PhoneNumber, null);
    }

    public Optional<String> phoneNumber() {
        return Optional.ofNullable(e164PhoneNumber);
    }

    public Optional<String> region() {
        return Optional.ofNullable(regionHint);
    }
}
