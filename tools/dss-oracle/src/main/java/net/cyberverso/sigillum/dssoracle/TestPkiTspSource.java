package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;

/**
 * A DSS timestamp source that runs {@code sigillum-testpki tsa} once per
 * token (ADR-0013). The program receives the digest that DSS asks to be
 * timestamped and the configured time as explicit arguments, without a
 * shell, and writes the token in DER to its standard output. No clock is
 * read: the genTime of every token is the configured time, which the source
 * checks together with the message imprint before it gives the token to DSS.
 */
final class TestPkiTspSource implements TSPSource {

    private static final long serialVersionUID = 1L;

    /** The largest token read from the program, far above any token of the test PKI. */
    static final int MAX_TOKEN = 1024 * 1024;
    /** The largest error output that the program may write. */
    static final int MAX_ERROR = 64 * 1024;
    /** How long the program may run. */
    static final Duration TIMEOUT = Duration.ofSeconds(60);

    /**
     * How often the source checks the size of the outputs of the program and
     * records the processes that it started, so that one whose parent has
     * ended can still be killed. The program stays in the process group of
     * the JVM, so that a supervisor that kills that group, as
     * {@code sigillum-testpki generate signed} does, kills them too.
     */
    private static final long POLL_MILLIS = 10;

    private final transient Path program;
    private final transient Path key;
    private final transient Path certificate;
    private final Instant time;
    private final Duration timeout;

    /**
     * Creates the source.
     *
     * @param program the {@code sigillum-testpki} program
     * @param key the private key of the timestamping authority
     * @param certificate the certificate of the timestamping authority
     * @param time the genTime of every token
     */
    TestPkiTspSource(Path program, Path key, Path certificate, Instant time) {
        this(program, key, certificate, time, TIMEOUT);
    }

    /**
     * Creates the source with another time limit, for the tests.
     *
     * @param program the {@code sigillum-testpki} program
     * @param key the private key of the timestamping authority
     * @param certificate the certificate of the timestamping authority
     * @param time the genTime of every token
     * @param timeout how long the program may run
     */
    TestPkiTspSource(Path program, Path key, Path certificate, Instant time, Duration timeout) {
        this.program = program;
        this.key = key;
        this.certificate = certificate;
        this.time = time;
        this.timeout = timeout;
    }

    /**
     * Returns the command line that issues a token, as a list of arguments
     * passed to the program without a shell. Each option and its value form
     * one argument, {@code --name=value}, so that no value, such as a path
     * that starts with a hyphen, can be read as an option.
     *
     * @param digestAlgorithm the algorithm of the message imprint
     * @param digest the digest to timestamp
     * @return the command line
     * @throws DSSException if {@code sigillum-testpki tsa} does not support the algorithm
     */
    List<String> command(DigestAlgorithm digestAlgorithm, byte[] digest) {
        String name = switch (digestAlgorithm) {
            case SHA256 -> "SHA-256";
            case SHA384 -> "SHA-384";
            case SHA512 -> "SHA-512";
            default -> throw new DSSException("sigillum-testpki tsa does not support the digest algorithm "
                    + digestAlgorithm.getName());
        };
        return List.of(program.toString(), "tsa",
                "--digest-algorithm=" + name,
                "--digest=" + HexFormat.of().formatHex(digest),
                "--time=" + ValidationOutput.format(time),
                "--tsa-key=" + key,
                "--tsa-cert=" + certificate);
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        List<String> command = command(digestAlgorithm, digest);
        byte[] token = run(command);
        check(token, digestAlgorithm, digest);
        return new TimestampBinary(token);
    }

    /**
     * Runs the program and returns its standard output. Both outputs go to
     * temporary files rather than pipes, so that the result does not depend
     * on whether a process that the program started keeps them open, nor on
     * when the JVM notices that the program has ended.
     */
    private byte[] run(List<String> command) {
        Set<ProcessHandle> started = new LinkedHashSet<>();
        Path output = null;
        Path error = null;
        Process process = null;
        try {
            try {
                output = Files.createTempFile("sigillum-tsa-", ".der");
                error = Files.createTempFile("sigillum-tsa-", ".txt");
            } catch (IOException e) {
                throw new DSSException("the outputs of --tsa-program cannot be stored: " + e.getMessage(), e);
            }
            try {
                process = new ProcessBuilder(command)
                        .redirectInput(ProcessBuilder.Redirect.PIPE)
                        .redirectOutput(output.toFile())
                        .redirectError(error.toFile())
                        .start();
            } catch (IOException e) {
                throw new DSSException("--tsa-program " + command.get(0) + " cannot be run: " + e.getMessage(), e);
            }
            process.getOutputStream().close();
            long deadline = System.nanoTime() + timeout.toNanos();
            switch (waitFor(process, deadline, started, output, error)) {
                case TIMED_OUT -> throw new DSSException("--tsa-program " + command.get(0)
                        + " did not finish within " + timeout.toSeconds() + " seconds");
                case OUTPUT_TOO_LARGE -> throw tooLarge(command);
                case ERROR_TOO_LARGE -> throw errorTooLarge(command);
                case FINISHED -> { }
            }
            // The limits are checked again, in the same order, so that the
            // result does not depend on whether the program ended before
            // the last check while it ran. What a process left by the
            // program writes after this point is not read.
            byte[] token = read(output, MAX_TOKEN + 1);
            byte[] errorOutput = read(error, MAX_ERROR + 1);
            if (token.length > MAX_TOKEN) {
                throw tooLarge(command);
            }
            if (errorOutput.length > MAX_ERROR) {
                throw errorTooLarge(command);
            }
            String message = new String(errorOutput, StandardCharsets.UTF_8).strip();
            if (process.exitValue() != 0) {
                throw new DSSException("--tsa-program " + command.get(0) + " exited with code "
                        + process.exitValue() + (message.isEmpty() ? "" : ": " + message));
            }
            if (token.length == 0) {
                throw new DSSException("--tsa-program " + command.get(0) + " wrote no token");
            }
            return token;
        } catch (IOException e) {
            throw new DSSException("--tsa-program " + command.get(0) + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DSSException("interrupted while --tsa-program ran", e);
        } finally {
            if (process != null) {
                terminate(process, started);
            }
            delete(output);
            delete(error);
        }
    }

    private static DSSException tooLarge(List<String> command) {
        return new DSSException("--tsa-program " + command.get(0) + " wrote more than " + MAX_TOKEN + " bytes");
    }

    private static DSSException errorTooLarge(List<String> command) {
        return new DSSException("--tsa-program " + command.get(0) + " wrote more than " + MAX_ERROR
                + " bytes of error output");
    }

    /** How a run of the program ended. */
    private enum Ending {
        FINISHED,
        TIMED_OUT,
        OUTPUT_TOO_LARGE,
        ERROR_TOO_LARGE
    }

    /**
     * Waits for the program until the deadline, or until one of its outputs
     * exceeds its limit, and records every process that the program starts
     * while it runs.
     */
    private static Ending waitFor(Process process, long deadline, Set<ProcessHandle> started, Path output,
            Path error) throws InterruptedException, IOException {
        while (true) {
            process.descendants().forEach(started::add);
            if (Files.size(output) > MAX_TOKEN) {
                return Ending.OUTPUT_TOO_LARGE;
            }
            if (Files.size(error) > MAX_ERROR) {
                return Ending.ERROR_TOO_LARGE;
            }
            long left = remaining(deadline);
            if (process.waitFor(Math.min(left, POLL_MILLIS), TimeUnit.MILLISECONDS)) {
                return Ending.FINISHED;
            }
            if (left == 0) {
                return Ending.TIMED_OUT;
            }
        }
    }

    /** Reads at most {@code limit} bytes from the start of a file. */
    private static byte[] read(Path file, int limit) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return in.readNBytes(limit);
        }
    }

    /** Deletes a temporary file, if it was created. */
    private static void delete(Path file) {
        if (file == null) {
            return;
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException e) {
            // A file left in the temporary directory changes no result.
        }
    }

    /** Kills the program, the processes recorded while it ran, and those found now. */
    private static void terminate(Process process, Set<ProcessHandle> started) {
        process.descendants().forEach(started::add);
        for (ProcessHandle handle : started) {
            handle.descendants().forEach(ProcessHandle::destroyForcibly);
            handle.destroyForcibly();
        }
        process.destroyForcibly();
    }

    /** The milliseconds left before a deadline of {@link System#nanoTime()}, at least zero. */
    private static long remaining(long deadline) {
        return Math.max(0, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
    }

    /**
     * Checks that a token timestamps the requested digest at the configured
     * time (RFC 3161, section 2.4.2), so that DSS receives no other token.
     */
    private void check(byte[] token, DigestAlgorithm digestAlgorithm, byte[] digest) {
        TimeStampToken parsed;
        try {
            parsed = new TimeStampToken(new CMSSignedData(token));
        } catch (CMSException | TSPException | IOException | RuntimeException e) {
            throw new DSSException("--tsa-program wrote no timestamp token: " + e.getMessage(), e);
        }
        if (!parsed.getTimeStampInfo().getMessageImprintAlgOID().getId().equals(digestAlgorithm.getOid())
                || !Arrays.equals(parsed.getTimeStampInfo().getMessageImprintDigest(), digest)) {
            throw new DSSException("--tsa-program wrote a token for another digest");
        }
        if (!parsed.getTimeStampInfo().getGenTime().toInstant().equals(time)) {
            throw new DSSException("--tsa-program wrote a token with the genTime "
                    + ValidationOutput.format(parsed.getTimeStampInfo().getGenTime().toInstant())
                    + ", not " + ValidationOutput.format(time));
        }
    }
}
