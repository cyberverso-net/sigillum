package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
    /** The largest error output kept from the program. */
    static final int MAX_ERROR = 64 * 1024;
    /** How long the program may run, until its output and error streams are closed. */
    static final Duration TIMEOUT = Duration.ofSeconds(60);

    /**
     * How often the source records the processes that the program started,
     * so that one whose parent has ended can still be killed. The program
     * stays in the process group of the JVM, so that a supervisor that kills
     * that group, as {@code sigillum-testpki generate signed} does, kills
     * them too.
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
     * @param timeout how long the program may run, until its output and error streams are closed
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

    /** Runs the program and returns its standard output. */
    private byte[] run(List<String> command) {
        Process process;
        Set<ProcessHandle> started = new LinkedHashSet<>();
        try {
            process = new ProcessBuilder(command).redirectInput(ProcessBuilder.Redirect.PIPE).start();
        } catch (IOException e) {
            throw new DSSException("--tsa-program " + command.get(0) + " cannot be run: " + e.getMessage(), e);
        }
        try {
            process.getOutputStream().close();
            Drain output = Drain.start(process.getInputStream(), MAX_TOKEN);
            Drain error = Drain.start(process.getErrorStream(), MAX_ERROR);
            long deadline = System.nanoTime() + timeout.toNanos();
            boolean finished = waitFor(process, deadline, started);
            // A process that the program started may keep its streams open after it ends.
            if (finished) {
                output.join(Math.max(1, remaining(deadline)));
                error.join(Math.max(1, remaining(deadline)));
            }
            if (!finished || output.isAlive() || error.isAlive()) {
                terminate(process, started);
                throw new DSSException("--tsa-program " + command.get(0) + " did not finish within "
                        + timeout.toSeconds() + " seconds");
            }
            if (output.failure() != null) {
                throw output.failure();
            }
            String message = new String(error.bytes(), StandardCharsets.UTF_8).strip();
            if (process.exitValue() != 0) {
                throw new DSSException("--tsa-program " + command.get(0) + " exited with code "
                        + process.exitValue() + (message.isEmpty() ? "" : ": " + message));
            }
            if (output.truncated()) {
                throw new DSSException("--tsa-program " + command.get(0) + " wrote more than " + MAX_TOKEN
                        + " bytes");
            }
            if (output.bytes().length == 0) {
                throw new DSSException("--tsa-program " + command.get(0) + " wrote no token");
            }
            return output.bytes();
        } catch (IOException e) {
            throw new DSSException("--tsa-program " + command.get(0) + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new DSSException("interrupted while --tsa-program ran", e);
        } finally {
            terminate(process, started);
        }
    }

    /**
     * Waits for the program until the deadline, and records every process
     * that the program starts while it runs.
     */
    private static boolean waitFor(Process process, long deadline, Set<ProcessHandle> started)
            throws InterruptedException {
        while (true) {
            process.descendants().forEach(started::add);
            long left = remaining(deadline);
            if (process.waitFor(Math.min(left, POLL_MILLIS), TimeUnit.MILLISECONDS)) {
                return true;
            }
            if (left == 0) {
                return false;
            }
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

    /** Reads a stream to its end in a thread of its own, keeping at most a given number of bytes. */
    private static final class Drain extends Thread {
        private final InputStream in;
        private final int limit;
        private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
        private boolean truncated;
        private IOException failed;

        private Drain(InputStream in, int limit) {
            this.in = in;
            this.limit = limit;
            setDaemon(true);
        }

        static Drain start(InputStream in, int limit) {
            Drain drain = new Drain(in, limit);
            drain.start();
            return drain;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[8192];
            try (in) {
                for (int read = in.read(buffer); read >= 0; read = in.read(buffer)) {
                    int keep = Math.min(read, limit - kept.size());
                    if (keep > 0) {
                        kept.write(buffer, 0, keep);
                    }
                    if (keep < read) {
                        truncated = true;
                    }
                }
            } catch (IOException e) {
                failed = e;
            }
        }

        synchronized IOException failure() {
            return failed;
        }

        synchronized byte[] bytes() {
            return kept.toByteArray();
        }

        synchronized boolean truncated() {
            return truncated;
        }
    }
}
