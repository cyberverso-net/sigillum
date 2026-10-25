package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Runs, in a JVM of its own, work that allocates more than the heap that
 * the test gives that JVM, so that the heap limit of {@link ResourceLimits}
 * is reached whatever the heap of the host.
 */
final class HeapLimitProbe {

    /** The allocation, 128 MiB, more than the heap of 64 MiB that the test gives. */
    static final int LONGS = 16 * 1024 * 1024;

    private HeapLimitProbe() {
    }

    /**
     * Runs the work and writes its output.
     *
     * @param args the output directory
     * @throws Exception if the run fails
     */
    public static void main(String[] args) throws Exception {
        ValidationOutput output = ValidationOutput.check(Path.of(args[0]), Mode.VALIDATE_DOCUMENT,
                Instant.parse("2030-01-15T10:00:00Z"), PolicySelection.named(OraclePolicy.ALIGNED));
        ResourceLimits.run(ResourceLimits.Limits.of(60), output, () -> {
            long[] huge = new long[LONGS];
            huge[0] = 1;
        });
    }
}
