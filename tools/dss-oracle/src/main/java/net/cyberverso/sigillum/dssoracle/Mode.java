package net.cyberverso.sigillum.dssoracle;

/** The modes of the tool. */
public enum Mode {
    /** Validates a signed document. */
    VALIDATE_DOCUMENT("validate-document"),
    /** Validates a certificate with offline revocation data. */
    VALIDATE_CERTIFICATE("validate-certificate"),
    /** Validates a standalone RFC 3161 timestamp token. */
    VALIDATE_TIMESTAMP("validate-timestamp"),
    /** Creates a signature with test keys. */
    SIGN("sign");

    private final String commandName;

    Mode(String commandName) {
        this.commandName = commandName;
    }

    /** Returns the name of the mode on the command line. */
    public String commandName() {
        return commandName;
    }
}
