package net.cyberverso.sigillum.dssoracle;

import java.io.PrintStream;
import java.util.Arrays;
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
            out.println("dss-oracle " + Versions.tool() + " (DSS " + Versions.dss() + ")");
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
            } catch (UsageException e) {
                err.println("dss-oracle: " + e.getMessage());
                err.println(usage());
                code = ExitCodes.USAGE;
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
        System.exit(run(args, Modes.RUNNER, System.out, System.err));
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
                "  --out <directory>                  output directory, absent or empty",
                "  --timeout <seconds>                time limit of a validation (default "
                        + ResourceLimits.DEFAULT_TIMEOUT_SECONDS + ")",
                "  --policy aligned|default|<file>    validation policy of a validation mode (default: aligned)",
                "validate-document options:",
                "  --document <file>                  signed document: CAdES, PAdES or JAdES",
                "  --detached <file>                  detached content of the signed document",
                "validate-certificate: the first --certificate is the certificate to validate;",
                "  the others are supplied for its chain.",
                "validate-timestamp options:",
                "  --timestamp <file>                 RFC 3161 timestamp token, DER",
                "  --data <file>                      data covered by the token",
                "  --digest <hex>                     digest of the data covered by the token",
                "  --digest-algorithm <name>          algorithm of --digest, such as SHA256",
                "sign options (--certificate is the signing certificate, --out the signed file):",
                "  --format <cades|pades|jades>       signature format",
                "  --level <B-B|B-T|B-LT>             baseline level",
                "  --key <file>                       PKCS#8 private key of the signer",
                "  --chain <file>                     certificate above the signing certificate (repeatable)",
                "  --signing-time <RFC 3339 time>     signing time, in whole seconds",
                "  --document <file>                  document to sign",
                "  --packaging <enveloping|detached>  CAdES and JAdES packaging, enveloping by default",
                "  --serialisation <compact|flattened|general>  JWS serialisation, required for JAdES",
                "  --signature-algorithm <name>       DSS signature algorithm, such as RSA_SSA_PSS_SHA256_MGF1",
                "  --tsa-program <file>               path of sigillum-testpki, or the variable " + Sign.PROGRAM_VARIABLE,
                "  --tsa-key <file>                   private key of the timestamping authority",
                "  --tsa-cert <file>                  certificate of the timestamping authority",
                "  --tsa-chain <file>                 certificate above the TSA certificate, B-LT only (repeatable)",
                "  --timestamp-time <RFC 3339 time>   genTime of the signature timestamp, in whole seconds",
                "  At B-LT, --validation-time is the time at which DSS checks the validation data,",
                "  --trust-anchor is required, and --crl and --ocsp give the revocation data to embed.",
                "Exit codes: 0 success, 1 failure, 2 usage error, 3 mode not implemented, 4 network access attempted.");
    }
}
