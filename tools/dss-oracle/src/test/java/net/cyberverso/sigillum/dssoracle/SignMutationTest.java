package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The fuzz coverage of the input paths of the sign mode: inputs of the
 * corpus, mutated deterministically from a fixed seed, are run through the
 * mode in process.
 *
 * <p>The inputs of the sign mode are files of the project, so the mode has
 * no {@code rejected} result: an input that DSS cannot use fails the run.
 * Every run must end with exit code 0 or 1, never a usage error, a network
 * attempt or a hang. A run that fails writes no file and says why on
 * standard error. A run that succeeds writes a signature that DSS alone,
 * without any code of the tool, finds intact, with an intact signature
 * timestamp when the level has one: the mode never writes a signature that
 * does not verify. A failing mutation is reported with its number, so that
 * it can be reproduced and given its own regression test.
 */
class SignMutationTest {

    /** The number of mutated runs. */
    static final int RUNS = 600;
    private static final long SEED = 38;

    @TempDir
    Path temp;

    /**
     * An input of the mode.
     *
     * @param name the name in failure messages
     * @param format the format of the run
     * @param level the level of the run
     * @param option the option that names the input, or {@code --tsa-program} for the token the program writes
     * @param original the corpus file that the mutation replaces
     * @param pem whether the input is a PEM file, mutated in its DER and encoded again
     */
    private record Input(String name, String format, String level, String option, String original, boolean pem) {
    }

    private static final List<Input> INPUTS = List.of(
            new Input("key", "cades", "B-B", "--key", "pki/keys/signer-p256.test-key.pem", true),
            new Input("certificate", "cades", "B-B", "--certificate", "pki/signer-p256.pem", true),
            new Input("chain", "cades", "B-B", "--chain", "pki/ca-ecdsa.pem", true),
            new Input("pdf", "pades", "B-B", "--document", "documents/simple.pdf", false),
            new Input("json", "jades", "B-B", "--document", "documents/payload.json", false),
            new Input("ocsp", "cades", "B-LT", "--ocsp", "ocsp/signer-p256.der", false),
            new Input("crl", "cades", "B-LT", "--crl", "crl/root-ca.crl", false),
            new Input("token", "cades", "B-T", "--tsa-program", "token", false));

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    /** The token that the program of a run writes, unless the token is the input mutated. */
    private byte[] token;

    @Test
    void mutatedInputsFailOrGiveIntactSignatures() throws Exception {
        token = validToken();
        Random random = new Random(SEED);
        List<String> failures = new ArrayList<>();
        int signed = 0;
        for (int run = 0; run < RUNS; run++) {
            Input input = INPUTS.get(run % INPUTS.size());
            byte[] original = input.original().equals("token") ? token : read(input.original());
            byte[] content = input.pem() ? Pem.decode(new String(original, StandardCharsets.US_ASCII)) : original;
            MutationTest.Mutation mutation = MutationTest.Mutation.random(random, content, !input.name().equals("pdf")
                    && !input.name().equals("json"));
            byte[] mutated = mutation.apply(content);
            if (input.pem()) {
                mutated = Pem.encode(input.name().equals("key") ? "PRIVATE KEY" : "CERTIFICATE", mutated)
                        .getBytes(StandardCharsets.US_ASCII);
            }
            Path directory = Files.createDirectory(temp.resolve("run-" + run));
            String failure = runOne(input, mutated, directory);
            if (failure == null && Files.exists(directory.resolve("signed"))) {
                signed++;
            }
            if (failure != null) {
                failures.add("run " + run + " (" + input.name() + ", " + mutation + "): " + failure);
            }
        }
        assertTrue(failures.isEmpty(), String.join("\n", failures));
        // The mutations leave some inputs usable, such as a PDF or JSON payload changed in its text.
        assertTrue(signed > 0, "no mutated run signed");
    }

    @Test
    void theUnmutatedInputsSign() throws Exception {
        token = validToken();
        for (Input input : INPUTS) {
            byte[] original = input.original().equals("token") ? token : read(input.original());
            Path directory = Files.createDirectory(temp.resolve("control-" + input.name()));
            assertEquals(null, runOne(input, original, directory), input.name());
            assertTrue(Files.exists(directory.resolve("signed")), input.name());
        }
    }

    /**
     * A timestamp token from {@link TestTsa} over the signature value of the
     * B-T run, which the runs copy. The B-LT runs sign the same signed
     * attributes with the same deterministic key, so the token fits them too.
     */
    private byte[] validToken() throws Exception {
        Path directory = Files.createDirectory(temp.resolve("token"));
        Path log = directory.resolve("tsa.log");
        Path tsa = Signing.tsaScript(directory, log);
        Path capture = Signing.script(directory.resolve("capture.sh"),
                "\"" + tsa + "\" \"$@\" | tee \"" + directory.resolve("token.tst") + "\"");
        List<String> args = arguments(INPUTS.get(INPUTS.size() - 1), directory.resolve("signed"), capture);
        assertEquals(ExitCodes.SUCCESS, run(args), err.toString(StandardCharsets.UTF_8));
        return Files.readAllBytes(directory.resolve("token.tst"));
    }

    private static byte[] read(String path) throws IOException {
        return Files.readAllBytes(Signing.CORPUS.resolve(path));
    }

    /** The arguments of a run of {@code input}, with the corpus files and a program that writes the token. */
    private static List<String> arguments(Input input, Path signed, Path program) {
        String document = switch (input.format()) {
            case "pades" -> Signing.corpus("documents/simple.pdf");
            case "jades" -> Signing.corpus("documents/payload.json");
            default -> Signing.corpus("documents/text.txt");
        };
        List<String> args = new ArrayList<>(Signing.base(input.format(), input.level(), Signing.P256, document));
        if (input.format().equals("jades")) {
            args.addAll(List.of("--serialisation", "flattened"));
        }
        if (!input.level().equals("B-B")) {
            args.addAll(Signing.timestamp(program));
        }
        if (input.level().equals("B-LT")) {
            args.addAll(Signing.longTerm(Signing.P256));
        }
        args.addAll(List.of("--out", signed.toString()));
        return args;
    }

    /**
     * Runs the mode with one input replaced by {@code content}.
     *
     * @return {@code null} if the run kept the contract, or what went wrong
     */
    private String runOne(Input input, byte[] content, Path directory) throws Exception {
        Path signed = directory.resolve("signed");
        Path tokenProgram = Signing.script(directory.resolve("tsa.sh"),
                "cat \"" + directory.resolve("token.tst") + "\"");
        Files.write(directory.resolve("token.tst"), input.option().equals("--tsa-program") ? content : token);
        Path file = directory.resolve("input-" + Path.of(input.original()).getFileName());
        Files.write(file, content);
        List<String> args = arguments(input, signed, tokenProgram);
        if (!input.option().equals("--tsa-program")) {
            int at = args.indexOf(input.option());
            if (input.option().equals("--ocsp") || input.option().equals("--crl") || input.option().equals("--chain")) {
                String replaced = Signing.corpus(input.original());
                at = args.indexOf(replaced) - 1;
            }
            args.set(at + 1, file.toString());
        }
        int code = run(args);
        String stderr = err.toString(StandardCharsets.UTF_8);
        if (code == ExitCodes.FAILURE) {
            if (Files.exists(signed)) {
                return "a failed run wrote " + signed;
            }
            return stderr.startsWith("dss-oracle: ") ? null : "no message: " + stderr;
        }
        if (code != ExitCodes.SUCCESS) {
            return "exit code " + code + ": " + stderr;
        }
        return checkIntact(input, signed);
    }

    /** Checks with DSS alone that a written signature, and its timestamp, are intact. */
    private static String checkIntact(Input input, Path signed) throws IOException {
        List<Path> detached = List.of();
        Reports reports;
        try {
            reports = Signing.validate(signed, detached, List.of(), List.of(Signing.P256.caCertificate()));
        } catch (RuntimeException e) {
            return "DSS cannot validate the signature written: " + e;
        }
        List<SignatureWrapper> signatures = reports.getDiagnosticData().getSignatures();
        if (signatures.size() != 1) {
            return signatures.size() + " signatures in the output";
        }
        SignatureWrapper signature = signatures.get(0);
        if (!signature.isSignatureIntact() || !signature.isSignatureValid()
                || !signature.getDigestMatchers().stream().allMatch(m -> m.isDataFound() && m.isDataIntact())) {
            return "the signature written is not intact";
        }
        if (!input.level().equals("B-B")) {
            List<TimestampWrapper> timestamps = signature.getTimestampList();
            if (timestamps.isEmpty() || !timestamps.stream().allMatch(t -> t.isSignatureIntact()
                    && t.isMessageImprintDataFound() && t.isMessageImprintDataIntact())) {
                return "the signature timestamp written is not intact";
            }
        }
        return null;
    }

    private int run(List<String> args) {
        out.reset();
        err.reset();
        return Main.run(args.toArray(String[]::new), Modes.runner(Map.of()),
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @Test
    void theInputsCoverEveryFileTheModeReads() {
        List<String> options = INPUTS.stream().map(Input::option).distinct().toList();
        for (String option : List.of("--key", "--certificate", "--chain", "--document", "--ocsp", "--crl",
                "--tsa-program")) {
            assertTrue(options.contains(option), option);
        }
        assertFalse(options.contains("--trust-anchor"), "the trust anchor is checked as a certificate");
    }
}
