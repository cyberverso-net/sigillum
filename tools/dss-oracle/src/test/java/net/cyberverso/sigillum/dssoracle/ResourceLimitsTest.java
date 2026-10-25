package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests of the worker that runs a validation within the limits of heap, stack and time. */
class ResourceLimitsTest {

    private static final Instant TIME = Instant.parse("2030-01-15T10:00:00Z");

    @TempDir
    Path temp;

    private static Map<String, Object> summary(Path directory) throws IOException {
        return JsonReader.object(Files.readString(directory.resolve("summary.json")));
    }

    private static List<String> files(Path directory) throws IOException {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    private ValidationOutput output(String name) throws IOException {
        return ValidationOutput.check(temp.resolve(name), Mode.VALIDATE_DOCUMENT, TIME,
                PolicySelection.named(OraclePolicy.ALIGNED));
    }

    private static void assertResourceLimit(Path directory, String limit, ResourceLimits.Limits limits)
            throws IOException {
        Map<String, Object> summary = summary(directory);
        assertEquals("resource-limit", summary.get("result"), summary.toString());
        assertEquals(limit, summary.get("limit"));
        assertTrue(summary.get("message") instanceof String message && !message.isBlank(), summary.toString());
        @SuppressWarnings("unchecked")
        Map<String, Object> recorded = (Map<String, Object>) summary.get("limits");
        assertEquals(limits.heapBytes(), recorded.get("heap-bytes"));
        assertEquals(ResourceLimits.STACK_BYTES, recorded.get("stack-bytes"));
        assertEquals(limits.timeoutSeconds(), recorded.get("timeout-seconds"));
        assertEquals(limits.garbageCollectors(), recorded.get("garbage-collectors"));
        ValidateDocumentTest.assertOracle(summary);
        assertEquals(List.of("summary.json"), files(directory));
    }

    /** A recursion depth that a stack of 1 MiB, the default of most hosts, cannot reach. */
    private static final int DEEP = 300_000;

    private static int depth(int remaining) {
        return remaining == 0 ? 0 : 1 + depth(remaining - 1);
    }

    @Test
    void theWorkerReachesARecursionDepthThatADefaultStackCannot() throws Exception {
        // A thread with a stack of 1 MiB overflows at this depth...
        Throwable[] small = new Throwable[1];
        Thread thread = new Thread(null, () -> {
            try {
                depth(DEEP);
            } catch (StackOverflowError e) {
                small[0] = e;
            }
        }, "small-stack", 1024 * 1024);
        thread.start();
        thread.join();
        assertTrue(small[0] instanceof StackOverflowError, String.valueOf(small[0]));
        // ...and the worker does not.
        int[] reached = new int[1];
        ResourceLimits.run(ResourceLimits.Limits.of(60), output("deep"), () -> reached[0] = depth(DEEP));
        assertEquals(DEEP, reached[0]);
        assertFalse(Files.exists(temp.resolve("deep").resolve("summary.json")));
    }

    @Test
    void theLimitsNameTheGarbageCollectors() {
        String collectors = String.join(", ", java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()
                .stream().map(java.lang.management.GarbageCollectorMXBean::getName).toList());
        assertEquals(collectors, ResourceLimits.Limits.of(60).garbageCollectors());
    }

    @Test
    void anOutOfMemoryErrorIsAHeapLimit() throws Exception {
        // In a JVM of its own with a heap of 64 MiB and the serial collector, so that the allocation fails
        // whatever the heap of the host.
        Path out = temp.resolve("heap");
        Process process = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx64m", "-XX:+UseSerialGC",
                "-cp", System.getProperty("java.class.path"), HeapLimitProbe.class.getName(), out.toString())
                .redirectErrorStream(true).start();
        String console = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), console);
        Map<String, Object> summary = summary(out);
        assertEquals("resource-limit", summary.get("result"), summary.toString());
        assertEquals("heap", summary.get("limit"));
        @SuppressWarnings("unchecked")
        Map<String, Object> recorded = (Map<String, Object>) summary.get("limits");
        assertTrue((Long) recorded.get("heap-bytes") <= 64L * 1024 * 1024, recorded.toString());
        assertEquals(ResourceLimits.STACK_BYTES, recorded.get("stack-bytes"));
        assertEquals(60L, recorded.get("timeout-seconds"));
        assertEquals("Copy, MarkSweepCompact", recorded.get("garbage-collectors"), recorded.toString());
        ValidateDocumentTest.assertOracle(summary);
        assertEquals(List.of("summary.json"), files(out));
    }


    @Test
    void aStackOverflowIsAStackLimit() throws Exception {
        ResourceLimits.Limits limits = ResourceLimits.Limits.of(60);
        ResourceLimits.run(limits, output("stack"), ResourceLimitsTest::recurse);
        assertResourceLimit(temp.resolve("stack"), "stack", limits);
    }

    private static void recurse() {
        recurse();
    }

    @Test
    void aRunPastItsTimeoutIsATimeLimitAndWritesNothingMore() throws Exception {
        ResourceLimits.Limits limits = new ResourceLimits.Limits(Runtime.getRuntime().maxMemory(), 1, 200,
                ResourceLimits.Limits.of(1).garbageCollectors());
        ValidationOutput output = output("time");
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(1);
        ResourceLimits.run(limits, output, () -> {
            try {
                release.await();
                output.writeValidated(List.of(new ValidationOutput.Report("late.xml", "<late/>")), null, null,
                        Map.of());
            } catch (IllegalStateException expected) {
                // The output is closed once the time limit is recorded.
            } finally {
                finished.countDown();
            }
        });
        release.countDown();
        assertTrue(finished.await(10, TimeUnit.SECONDS));
        assertResourceLimit(temp.resolve("time"), "time", limits);
    }

    @Test
    void reportsWrittenBeforeTheLimitAreRemoved() throws Exception {
        ResourceLimits.Limits limits = ResourceLimits.Limits.of(60);
        ValidationOutput output = output("partial");
        ResourceLimits.run(limits, output, () -> {
            // The reports and the summary are written, then the run runs out of memory.
            output.writeValidated(List.of(new ValidationOutput.Report("early.xml", "<early/>")), null, null,
                    Map.of());
            throw new OutOfMemoryError("simulated");
        });
        assertResourceLimit(temp.resolve("partial"), "heap", limits);
    }

    @Test
    void otherErrorsAndExceptionsPropagate() throws Exception {
        ResourceLimits.Limits limits = ResourceLimits.Limits.of(60);
        assertThrows(IllegalStateException.class, () -> ResourceLimits.run(limits, output("exception"), () -> {
            throw new IllegalStateException("broken");
        }));
        assertThrows(AssertionError.class, () -> ResourceLimits.run(limits, output("error"), () -> {
            throw new AssertionError("broken");
        }));
        assertThrows(RejectedInputException.class, () -> ResourceLimits.run(limits, output("rejected"), () -> {
            throw new RejectedInputException("--document", Path.of("x"), new IllegalArgumentException("bad"));
        }));
        assertFalse(Files.exists(temp.resolve("exception").resolve("summary.json")));
    }

    @Test
    void theLimitsRecordTheHeapOfTheJvm() {
        ResourceLimits.Limits limits = ResourceLimits.Limits.of(42);
        assertEquals(Runtime.getRuntime().maxMemory(), limits.heapBytes());
        assertEquals(42L, limits.timeoutSeconds());
        assertEquals(42_000L, limits.timeoutMillis());
    }
}
