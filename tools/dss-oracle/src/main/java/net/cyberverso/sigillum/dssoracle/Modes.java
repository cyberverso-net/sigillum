package net.cyberverso.sigillum.dssoracle;

import java.util.Map;

/** Selects the runner of each mode. */
public final class Modes {

    /** Runs the selected mode in the environment of the process. */
    public static final Main.ModeRunner RUNNER = runner(System.getenv());

    /**
     * Returns the runner of the modes with a given environment, which the
     * sign mode reads to locate {@code sigillum-testpki}.
     *
     * @param environment the environment
     * @return the runner
     */
    public static Main.ModeRunner runner(Map<String, String> environment) {
        return (arguments, out, err) -> switch (arguments.mode()) {
            case VALIDATE_TIMESTAMP -> new ValidateTimestamp().run(arguments, out, err);
            case VALIDATE_CERTIFICATE -> new ValidateCertificate().run(arguments, out, err);
            case VALIDATE_DOCUMENT -> new ValidateDocument().run(arguments, out, err);
            case SIGN -> new Sign(environment).run(arguments, out, err);
        };
    }

    private Modes() {
    }
}
