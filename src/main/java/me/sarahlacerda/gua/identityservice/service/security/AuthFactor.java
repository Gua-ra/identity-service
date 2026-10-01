package me.sarahlacerda.gua.identityservice.service.security;

// Ordered strongest first; AuthFactorPolicy relies on the order.
// Every value means registered on the server, never usable on the calling device.
public enum AuthFactor {

    PASSKEY,

    PIN,

    /** Not enough on its own to change the number it is delivered to. */
    PHONE_OTP
}
