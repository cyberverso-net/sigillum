package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests of the bounds that the timestamp source puts on {@code sigillum-testpki tsa}. */
class TestPkiTspSourceTest {

    private static final Instant TIME = Instant.parse("2029-12-16T10:00:00Z");

    @TempDir
    Path temp;

    private TestPkiTspSource source(Path program) {
        return source(program, Duration.ofSeconds(2));
    }

    private TestPkiTspSource source(Path program, Duration timeout) {
        return new TestPkiTspSource(program, Path.of("key.pem"), Path.of("tsa.pem"), TIME, timeout);
    }

    @Test
    void passesEachOptionWithItsValueAsOneArgument() {
        List<String> command = new TestPkiTspSource(Path.of("/bin/testpki"), Path.of("-key.pem"), Path.of("tsa.pem"),
                TIME).command(DigestAlgorithm.SHA256, new byte[32]);
        assertEquals(List.of("/bin/testpki", "tsa", "--digest-algorithm=SHA-256", "--digest=" + "00".repeat(32),
                "--time=2029-12-16T10:00:00Z", "--tsa-key=-key.pem", "--tsa-cert=tsa.pem"), command);
    }

    @Test
    void aProgramThatRunsTooLongFails() throws Exception {
        Path program = Signing.script(temp.resolve("slow.sh"), "sleep 30");
        long start = System.nanoTime();
        DSSException error = assertThrows(DSSException.class,
                () -> source(program).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
        assertTrue(error.getMessage().contains("did not finish"), error.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 20);
    }

    @Test
    void anOutputHeldOpenAfterTheProgramEndsDoesNotDelayTheResult() throws Exception {
        // The program exits at once, but a process it started keeps its standard output open.
        // The result must not depend on when the JVM notices that the program ended. The
        // process is orphaned before the source can record it, so the source cannot kill it:
        // the test does, and a supervisor that kills the process group does in real runs.
        for (int run = 0; run < 20; run++) {
            Path pid = temp.resolve("held-" + run + ".pid");
            Path program = Signing.script(temp.resolve("held-" + run + ".sh"),
                    "sleep 30 &\necho $! > '" + pid + "'\nexit 0");
            long start = System.nanoTime();
            try {
                DSSException error = assertThrows(DSSException.class,
                        () -> source(program, Duration.ofSeconds(30))
                                .getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
                assertTrue(error.getMessage().contains("wrote no token"), "run " + run + ": " + error.getMessage());
                assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 10);
            } finally {
                kill(pid);
            }
        }
    }

    @Test
    void aProgramThatWritesTooMuchIsStopped() throws Exception {
        Path pid = temp.resolve("yes.pid");
        Path program = Signing.script(temp.resolve("output.sh"), "yes &\necho $! > '" + pid + "'\nwait");
        long start = System.nanoTime();
        DSSException error = assertThrows(DSSException.class,
                () -> source(program, Duration.ofSeconds(60)).getTimeStampResponse(DigestAlgorithm.SHA256,
                        new byte[32]));
        assertTrue(error.getMessage().contains("wrote more than " + TestPkiTspSource.MAX_TOKEN + " bytes"),
                error.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 20);
        assertEnded(pid);
    }

    @Test
    void theOutputFilesAreDeletedAfterARun() throws Exception {
        Path program = Signing.script(temp.resolve("files.sh"), "printf token\necho note >&2\nexit 1");
        Path directory = Path.of(System.getProperty("java.io.tmpdir"));
        List<Path> before = outputFiles(directory);
        assertThrows(DSSException.class,
                () -> source(program).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
        assertEquals(before, outputFiles(directory));
    }

    @Test
    void aProgramThatWritesTooMuchErrorOutputIsStopped() throws Exception {
        Path program = Signing.script(temp.resolve("error.sh"), "yes >&2");
        long start = System.nanoTime();
        DSSException error = assertThrows(DSSException.class,
                () -> source(program, Duration.ofSeconds(60)).getTimeStampResponse(DigestAlgorithm.SHA256,
                        new byte[32]));
        assertTrue(error.getMessage().contains("wrote more than " + TestPkiTspSource.MAX_ERROR
                + " bytes of error output"), error.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 20);
    }

    @Test
    void aProgramThatWritesTooMuchAndExitsAtOnceFailsTheSameWayEachTime() throws Exception {
        // The limits apply whether the source sees them while the program runs or after it ends.
        Path output = Signing.script(temp.resolve("output-exit.sh"), "head -c 2000000 /dev/zero\nexit 1");
        Path error = Signing.script(temp.resolve("error-exit.sh"), "head -c 100000 /dev/zero >&2\nexit 1");
        for (int run = 0; run < 20; run++) {
            DSSException tooMuch = assertThrows(DSSException.class,
                    () -> source(output).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
            assertTrue(tooMuch.getMessage().endsWith("wrote more than " + TestPkiTspSource.MAX_TOKEN + " bytes"),
                    "run " + run + ": " + tooMuch.getMessage());
            DSSException tooMuchError = assertThrows(DSSException.class,
                    () -> source(error).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
            assertTrue(tooMuchError.getMessage().endsWith("wrote more than " + TestPkiTspSource.MAX_ERROR
                    + " bytes of error output"), "run " + run + ": " + tooMuchError.getMessage());
        }
    }

    @Test
    void theErrorOutputOfAFailedRunIsReported() throws Exception {
        Path program = Signing.script(temp.resolve("failed.sh"), "echo 'no key' >&2\nexit 3");
        DSSException error = assertThrows(DSSException.class,
                () -> source(program).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
        assertTrue(error.getMessage().endsWith("exited with code 3: no key"), error.getMessage());
    }

    @Test
    void aProcessThatTheProgramStartedIsKilledAtTheDeadline() throws Exception {
        // The process outlives the program, which ends after the source has seen it.
        Path pid = temp.resolve("child.pid");
        Path program = Signing.script(temp.resolve("child.sh"), "sleep 30 &\necho $! > '" + pid + "'\nsleep 1\nexit 0");
        assertThrows(DSSException.class,
                () -> source(program).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
        assertEnded(pid);
    }

    /** The temporary files of the source in a directory, sorted. */
    private static List<Path> outputFiles(Path directory) throws Exception {
        try (var files = Files.list(directory)) {
            return files.filter(file -> file.getFileName().toString().startsWith("sigillum-tsa-")).sorted().toList();
        }
    }

    /** Kills the process whose identifier the file holds, if the file exists. */
    private static void kill(Path pid) throws Exception {
        if (Files.exists(pid)) {
            ProcessHandle.of(Long.parseLong(Files.readString(pid).strip())).ifPresent(ProcessHandle::destroyForcibly);
        }
    }

    /** Checks that the process whose identifier the file holds ends within five seconds. */
    private static void assertEnded(Path pid) throws Exception {
        long id = Long.parseLong(Files.readString(pid).strip());
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (ProcessHandle.of(id).map(ProcessHandle::isAlive).orElse(false) && System.nanoTime() < deadline) {
            Thread.sleep(50);
        }
        assertFalse(ProcessHandle.of(id).map(ProcessHandle::isAlive).orElse(false), "process " + id + " is still running");
    }
}
