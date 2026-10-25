package net.cyberverso.sigillum.dssoracle;

/**
 * Runs a validation on a worker thread within limits of heap, stack and
 * time, so that a run that exceeds one ends with the recorded result
 * {@code resource-limit} instead of failing the tool.
 *
 * <ul>
 * <li>The heap is the maximum heap of the JVM, set with {@code -Xmx}. An
 * {@link OutOfMemoryError} on the worker is the limit {@code heap}.</li>
 * <li>The stack of the worker is fixed at {@link #STACK_BYTES}, whatever
 * the default of the host, so that the depth that DSS reaches does not
 * depend on it. A {@link StackOverflowError} is the limit
 * {@code stack}.</li>
 * <li>The time is given with {@code --timeout}, in seconds, by default
 * {@link #DEFAULT_TIMEOUT_SECONDS}. A worker still running then is the limit
 * {@code time}. It is interrupted and left to end on its own: Java cannot
 * stop a thread safely. The output is closed, so it can write nothing more,
 * and the tool exits when the run returns.</li>
 * </ul>
 *
 * <p>A caller in the same JVM, such as a test, keeps a timed-out worker
 * running after {@link #run} returns, and so after {@code Main} has closed
 * the network guard: network attempts of that worker are then not recorded.
 * The command-line tool exits instead, which ends the worker.
 */
final class ResourceLimits {

    /**
     * The stack of the worker, 64 MiB. With it, DSS 6.5.1 has been observed
     * to parse JSON nested up to the limit of its JSON schema validator,
     * 100,000 levels, without exhausting the stack, also with the JIT
     * compiler disabled ({@code -Xint}), where the frames are largest.
     */
    static final long STACK_BYTES = 64L * 1024 * 1024;

    /** The default time limit of a run, in seconds. */
    static final int DEFAULT_TIMEOUT_SECONDS = 300;

    private ResourceLimits() {
    }

    /** The work of a run. */
    @FunctionalInterface
    interface Work {
        /**
         * Runs the work.
         *
         * @throws Exception if it fails
         */
        void run() throws Exception;
    }

    /**
     * The limits of a run.
     *
     * @param heapBytes the maximum heap of the JVM
     * @param timeoutSeconds the time limit, in seconds, as recorded
     * @param timeoutMillis the time limit applied, in milliseconds
     * @param garbageCollectors the garbage collectors of the JVM, by name,
     *        which decide how close to the heap limit a run can come
     */
    record Limits(long heapBytes, long timeoutSeconds, long timeoutMillis, String garbageCollectors) {

        /**
         * Returns the limits of this JVM with a time limit.
         *
         * @param seconds the time limit, in seconds
         * @return the limits
         */
        static Limits of(int seconds) {
            return new Limits(Runtime.getRuntime().maxMemory(), seconds, seconds * 1000L, String.join(", ",
                    java.lang.management.ManagementFactory.getGarbageCollectorMXBeans().stream()
                            .map(java.lang.management.GarbageCollectorMXBean::getName).toList()));
        }

        /**
         * Returns the limits of a command line: {@code --timeout}, or the default.
         *
         * @param arguments the command line
         * @return the limits
         */
        static Limits of(Arguments arguments) {
            return of(arguments.timeout().orElse(DEFAULT_TIMEOUT_SECONDS));
        }
    }

    /** A worker thread, which knows its stack size. */
    private static final class Worker extends Thread {
        private final long stackBytes;
        private final Work work;
        private Throwable failure;

        Worker(Work work) {
            super(null, null, "dss-oracle-worker", STACK_BYTES);
            this.stackBytes = STACK_BYTES;
            this.work = work;
            setDaemon(true);
        }

        @Override
        public void run() {
            try {
                work.run();
            } catch (Throwable e) {
                failure = e;
            }
        }
    }

    /**
     * Returns the stack size of the current thread when it is a worker.
     *
     * @return the stack size, or 0 on another thread
     */
    static long currentStackBytes() {
        return Thread.currentThread() instanceof Worker worker ? worker.stackBytes : 0;
    }

    /**
     * Runs the work on a worker thread within the limits. When it exceeds
     * one, the output records it as the result {@code resource-limit}.
     *
     * @param limits the limits
     * @param output the output of the run
     * @param work the work
     * @throws Exception the exception or error of the work, other than the
     *         errors of the limits
     */
    static void run(Limits limits, ValidationOutput output, Work work) throws Exception {
        Worker worker = new Worker(work);
        worker.start();
        worker.join(limits.timeoutMillis());
        if (worker.isAlive()) {
            worker.interrupt();
            output.writeResourceLimit("time", limits,
                    "the run took longer than " + limits.timeoutSeconds() + " s");
            return;
        }
        Throwable failure = worker.failure;
        if (failure == null) {
            return;
        }
        if (failure instanceof OutOfMemoryError) {
            output.writeResourceLimit("heap", limits, failure.toString());
            return;
        }
        if (failure instanceof StackOverflowError) {
            output.writeResourceLimit("stack", limits, failure.toString());
            return;
        }
        if (failure instanceof Exception exception) {
            throw exception;
        }
        throw (Error) failure;
    }
}
