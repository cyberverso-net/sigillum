package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class MainTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(Main.ModeRunner runner, String... args) {
        return Main.run(args, runner,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private int run(String... args) {
        return run(Main.NOT_IMPLEMENTED, args);
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    @Test
    void versionPrintsTheToolAndDssVersions() {
        assertEquals(ExitCodes.SUCCESS, run("--version"));
        assertTrue(stdout().contains("dss-oracle 0.0.0"), stdout());
        assertTrue(stdout().contains("DSS 6.5.1"), stdout());
    }

    @Test
    void helpListsTheModes() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        for (Mode mode : Mode.values()) {
            assertTrue(stdout().contains(mode.commandName()), stdout());
        }
    }

    @Test
    void everyModeIsReportedAsNotImplemented() {
        for (Mode mode : Mode.values()) {
            err.reset();
            assertEquals(ExitCodes.NOT_IMPLEMENTED, run(mode.commandName()), mode.commandName());
            assertTrue(stderr().contains(mode.commandName()), stderr());
            assertTrue(stderr().contains("not implemented"), stderr());
        }
    }

    @Test
    void usageErrorsHaveTheirOwnExitCode() {
        assertEquals(ExitCodes.USAGE, run());
        assertTrue(stderr().contains("Usage"), stderr());
        assertEquals(ExitCodes.USAGE, run("verify"));
        assertEquals(ExitCodes.USAGE, run("sign", "--out"));
    }

    @Test
    void theRunnerReceivesTheParsedArguments() {
        int code = run((arguments, stdout, stderr) -> {
            assertEquals(Mode.SIGN, arguments.mode());
            return ExitCodes.SUCCESS;
        }, "sign", "--out", "x");
        assertEquals(ExitCodes.SUCCESS, code);
    }

    @Test
    void aSwallowedNetworkAttemptStillFailsTheRun() {
        int code = run((arguments, stdout, stderr) -> {
            try {
                URI.create("http://example.invalid/").toURL().openConnection().connect();
            } catch (IOException | RuntimeException expected) {
                // The mode ignores the failure; the run must fail anyway.
            }
            return ExitCodes.SUCCESS;
        }, "sign");
        assertEquals(ExitCodes.NETWORK_ACCESS, code);
        assertTrue(stderr().contains("example.invalid"), stderr());
    }

    @Test
    void anErrorThrownByARunnerStillFailsOnANetworkAttempt() {
        int code = run((arguments, stdout, stderr) -> {
            try {
                URI.create("http://example.invalid/").toURL().openConnection().connect();
            } catch (IOException | RuntimeException expected) {
                // Ignored, as a careless mode might.
            }
            throw new ExceptionInInitializerError("static initialiser failed");
        }, "sign");
        assertEquals(ExitCodes.NETWORK_ACCESS, code);
    }

    @Test
    void versionAndHelpTakeNoOtherArguments() {
        assertEquals(ExitCodes.USAGE, run("--version", "sign"));
        assertEquals(ExitCodes.USAGE, run("sign", "--help"));
    }

    @Test
    void aUsageErrorFoundByARunnerHasTheUsageExitCode() {
        int code = run((arguments, stdout, stderr) -> {
            throw new UsageException("--out is required.");
        }, "sign");
        assertEquals(ExitCodes.USAGE, code);
        assertTrue(stderr().contains("--out is required."), stderr());
        assertTrue(stderr().contains("Usage"), stderr());
    }

    @Test
    void theDefaultRunnerImplementsEveryMode() {
        for (Mode mode : Mode.values()) {
            assertEquals(ExitCodes.USAGE, run(Modes.RUNNER, mode.commandName()), mode.commandName());
        }
    }

    @Test
    void helpListsTheDocumentOptions() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        for (String option : List.of("--document", "--detached", "--policy")) {
            assertTrue(stdout().contains(option), stdout());
        }
    }

    @Test
    void helpListsTheSignOptions() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        for (String option : SignArguments.OPTIONS) {
            assertTrue(stdout().contains(option + " "), option);
        }
    }

    @Test
    void helpListsTheTimestampOptions() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        for (String option : List.of("--timestamp", "--data", "--digest", "--digest-algorithm")) {
            assertTrue(stdout().contains(option), stdout());
        }
    }

    @Test
    void helpNamesThePoliciesAndTheDefault() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        assertTrue(stdout().contains("--policy aligned|default|<file>"), stdout());
        assertTrue(stdout().contains("default: aligned"), stdout());
    }

    @Test
    void helpNamesTheCertificateToValidate() {
        assertEquals(ExitCodes.SUCCESS, run("--help"));
        assertTrue(stdout().contains("validate-certificate: the first --certificate is the certificate to validate"),
                stdout());
    }

    @Test
    void aRunnerFailureIsReported() {
        int code = run((arguments, stdout, stderr) -> {
            throw new IllegalStateException("broken");
        }, "sign");
        assertEquals(ExitCodes.FAILURE, code);
        assertTrue(stderr().contains("broken"), stderr());
    }
}
