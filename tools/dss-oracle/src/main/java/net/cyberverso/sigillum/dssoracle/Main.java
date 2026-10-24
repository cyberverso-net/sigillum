package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Properties;
import java.util.stream.Collectors;

/** Entry point of {@code dss-oracle}. */
public final class Main {

    /** Runs a mode with parsed arguments. */
    @FunctionalInterface
    public interface ModeRunner {
        /**
         * Runs the mode.
         *
         * @param arguments the parsed command line
         * @param out standard output
         * @param err standard error
         * @return the exit code
         * @throws Exception if the mode fails
         */
        int run(Arguments arguments, PrintStream out, PrintStream err) throws Exception;
    }

    /** The runner used until the modes are implemented. */
    public static final ModeRunner NOT_IMPLEMENTED = (arguments, out, err) -> {
        err.println("dss-oracle: the mode " + arguments.mode().commandName() + " is not implemented yet.");
        return ExitCodes.NOT_IMPLEMENTED;
    };

    private Main() {
    }

    /**
     * Runs the tool.
     *
     * @param args the command-line arguments
     * @param runner the runner of the selected mode
     * @param out standard output
     * @param err standard error
     * @return the exit code, one of {@link ExitCodes}
     */
    public static int run(String[] args, ModeRunner runner, PrintStream out, PrintStream err) {
        if (args.length > 1 && (Arrays.asList(args).contains("--version") || Arrays.asList(args).contains("--help"))) {
            err.println("dss-oracle: --version and --help take no other arguments.");
            return ExitCodes.USAGE;
        }
        if (args.length == 1 && args[0].equals("--version")) {
            Properties versions = versions();
            out.println("dss-oracle " + versions.getProperty("tool.version")
                    + " (DSS " + versions.getProperty("dss.version") + ")");
            return ExitCodes.SUCCESS;
        }
        if (args.length == 1 && args[0].equals("--help")) {
            out.println(usage());
            return ExitCodes.SUCCESS;
        }
        Arguments arguments;
        try {
            arguments = Arguments.parse(Arrays.asList(args));
        } catch (UsageException e) {
            err.println("dss-oracle: " + e.getMessage());
            err.println(usage());
            return ExitCodes.USAGE;
        }
        try (OfflineGuard guard = OfflineGuard.install()) {
            int code;
            try {
                code = runner.run(arguments, out, err);
            } catch (Exception | Error e) {
                err.println("dss-oracle: " + e);
                code = ExitCodes.FAILURE;
            }
            if (guard.attempted()) {
                err.println("dss-oracle: network access was attempted: " + guard.attempts());
                return ExitCodes.NETWORK_ACCESS;
            }
            return code;
        }
    }

    /**
     * Runs the tool and exits with its exit code.
     *
     * @param args the command-line arguments
     */
    public static void main(String[] args) {
        System.exit(run(args, NOT_IMPLEMENTED, System.out, System.err));
    }

    private static String usage() {
        String modes = Arrays.stream(Mode.values()).map(Mode::commandName).collect(Collectors.joining(" | "));
        return String.join(System.lineSeparator(),
                "Usage: dss-oracle <mode> [options]",
                "       dss-oracle --version | --help",
                "Modes: " + modes,
                "Options:",
                "  --validation-time <RFC 3339 time>  fixed validation or signing time",
                "  --trust-anchor <file>              trust anchor certificate (repeatable)",
                "  --certificate <file>               certificate supplied offline (repeatable)",
                "  --crl <file>                       CRL supplied offline (repeatable)",
                "  --ocsp <file>                      OCSP response supplied offline (repeatable)",
                "  --out <directory>                  output directory",
                "Exit codes: 0 success, 1 failure, 2 usage error, 3 mode not implemented, 4 network access attempted.");
    }

    private static Properties versions() {
        Properties properties = new Properties();
        try (InputStream in = Main.class.getResourceAsStream("/dss-oracle.properties")) {
            if (in != null) {
                properties.load(in);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return properties;
    }
}
