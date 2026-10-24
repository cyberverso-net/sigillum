package net.cyberverso.sigillum.dssoracle;

/** The command line is not valid. */
public final class UsageException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Creates an exception with a message for the user. */
    public UsageException(String message) {
        super(message);
    }
}
