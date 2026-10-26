package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
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
        return new TestPkiTspSource(program, Path.of("key.pem"), Path.of("tsa.pem"), TIME, Duration.ofSeconds(2));
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
    void anOutputHeldOpenAfterTheProgramEndsFails() throws Exception {
        // The program exits at once, but a process it started keeps its standard output open.
        Path program = Signing.script(temp.resolve("held.sh"), "sleep 30 &\nexit 0");
        long start = System.nanoTime();
        DSSException error = assertThrows(DSSException.class,
                () -> source(program).getTimeStampResponse(DigestAlgorithm.SHA256, new byte[32]));
        assertTrue(error.getMessage().contains("did not finish"), error.getMessage());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 20);
    }
}
