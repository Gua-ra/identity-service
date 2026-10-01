// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

/** Never carries the MAS column that holds a phone number. The subject is the account's Matrix user id. */
public record MasLink(String federationId, String subject, String masUserId, String masUsername) {
}
