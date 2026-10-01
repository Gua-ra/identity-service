package me.sarahlacerda.gua.identityservice.service.routing;

import java.util.Optional;

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
