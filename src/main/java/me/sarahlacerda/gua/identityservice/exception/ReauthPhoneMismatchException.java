package me.sarahlacerda.gua.identityservice.exception;

/**
 * The number submitted to a reauthentication step is not the number on the caller's own
 * account.
 *
 * <p>
 * One refusal for every way of being wrong: a number nobody has, a number somebody else has,
 * and a number that parses but belongs elsewhere all raise this, with the same message. The
 * caller is already authenticated, so the only thing they can learn from it is whether the
 * number they typed is their own, which they are entitled to know. What they must not learn is
 * anything about an account that is not theirs.
 */
public class ReauthPhoneMismatchException extends RuntimeException {

    public ReauthPhoneMismatchException(String message) {
        super(message);
    }
}
