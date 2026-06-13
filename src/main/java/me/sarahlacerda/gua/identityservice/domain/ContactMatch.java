package me.sarahlacerda.gua.identityservice.domain;

/**
 * A single contact-discovery hit: the submitted phone number (echoed back so the
 * client can map the result onto its local address book) and the public profile
 * of the Gua account behind it.
 */
public record ContactMatch(String phoneNumber, String userId, String username, String displayName) { }
