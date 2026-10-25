package net.cyberverso.sigillum.dssoracle;

/** Selects the runner of each mode. */
public final class Modes {

    /** Runs the selected mode; modes that are not implemented yet exit with {@link ExitCodes#NOT_IMPLEMENTED}. */
    public static final Main.ModeRunner RUNNER = (arguments, out, err) -> switch (arguments.mode()) {
        case VALIDATE_TIMESTAMP -> new ValidateTimestamp().run(arguments, out, err);
        case VALIDATE_CERTIFICATE -> new ValidateCertificate().run(arguments, out, err);
        case VALIDATE_DOCUMENT -> new ValidateDocument().run(arguments, out, err);
        case SIGN -> Main.NOT_IMPLEMENTED.run(arguments, out, err);
    };

    private Modes() {
    }
}
