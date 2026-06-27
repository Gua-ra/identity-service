package me.sarahlacerda.gua.identityservice.exception;

/**
 * Raised when a flow that requires the account PIN as a step-up factor is invoked
 * by a user who has not configured a PIN yet. Distinct from {@link InvalidPinException}
 * (wrong PIN) and {@link InvalidPinOperationException} (generic pin_error): clients map
 * this to the "set up a PIN first" interstitial in the change-phone flow.
 */
public class PinSetupRequiredException extends RuntimeException {

    public PinSetupRequiredException(String message) {
        super(message);
    }
}
