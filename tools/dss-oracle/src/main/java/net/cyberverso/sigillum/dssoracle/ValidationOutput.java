package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Writes the result of a validation mode to its output directory: the DSS
 * reports of the mode as XML, unchanged, and {@code summary.json}, which is
 * written last.
 * The schema of {@code summary.json} is described in the README of the tool.
 */
public final class ValidationOutput {

    /** The version of the schema of {@code summary.json}. */
    public static final int FORMAT_VERSION = 3;
    /** The file name of the summary. */
    public static final String SUMMARY = "summary.json";

    private final Path directory;
    private final Mode mode;
    private final Instant validationTime;
    private final PolicySelection policy;
    /** The files written so far, which a resource limit removes. */
    private final List<Path> written = new ArrayList<>();
    /** Whether a resource limit has been recorded, after which nothing more is written. */
    private boolean closed;

    /**
     * Checks the output directory before a run. It must not exist yet, or be
     * an empty directory, so that no file of an earlier run is mistaken for a
     * result of this one.
     *
     * @param directory the output directory
     * @param mode the mode that writes it
     * @param validationTime the validation time of the run
     * @param policy the validation policy of the run, which the summary names
     * @return the output, not yet created
     * @throws IOException if the path is a file or a directory that is not empty
     */
    public static ValidationOutput check(Path directory, Mode mode, Instant validationTime, PolicySelection policy)
            throws IOException {
        if (Files.exists(directory)) {
            if (!Files.isDirectory(directory)) {
                throw new IOException("--out " + directory + ": not a directory");
            }
            try (Stream<Path> entries = Files.list(directory)) {
                if (entries.findAny().isPresent()) {
                    throw new IOException("--out " + directory + ": the directory is not empty");
                }
            }
        }
        return new ValidationOutput(directory, mode, validationTime, policy);
    }

    private ValidationOutput(Path directory, Mode mode, Instant validationTime, PolicySelection policy) {
        this.directory = directory;
        this.mode = mode;
        this.validationTime = validationTime;
        this.policy = policy;
    }

    /**
     * A report of DSS to write unchanged, under a file name that the mode
     * chooses.
     *
     * @param fileName the file name, without a directory
     * @param xml the report as DSS produces it
     */
    public record Report(String fileName, String xml) {
    }

    /**
     * Writes the reports of a mode unchanged, in their order, then the
     * summary of a validation that DSS ran. The set of reports belongs to the
     * mode: DSS gives a timestamp an ETSI validation report, for example, but
     * not a certificate.
     *
     * @param reports the reports, each with a distinct plain file name other
     *        than {@value #SUMMARY}
     * @param indication the indication of the validated token
     * @param subIndication its sub-indication, or {@code null}
     * @param details the details of the mode, written under {@code details}
     * @throws IllegalArgumentException if a file name is not allowed; nothing
     *         is written then
     * @throws IOException if a file cannot be written
     */
    public synchronized void writeValidated(List<Report> reports, Indication indication,
            SubIndication subIndication, Map<String, Object> details) throws IOException {
        Set<String> names = new HashSet<>();
        for (Report report : reports) {
            String name = report.fileName();
            Path path = Path.of(name);
            if (name.equals(SUMMARY) || path.getNameCount() != 1 || name.equals(".") || name.equals("..")
                    || path.isAbsolute() || !names.add(name)) {
                throw new IllegalArgumentException("Report file name not allowed: " + name);
            }
        }
        requireOpen();
        Files.createDirectories(directory);
        for (Report report : reports) {
            write(report.fileName(), report.xml());
        }
        Map<String, Object> summary = header("validated");
        summary.put("indication", indication == null ? null : indication.name());
        summary.put("sub-indication", subIndication == null ? null : subIndication.name());
        summary.put("details", details);
        write(SUMMARY, Json.write(summary));
    }

    /**
     * Writes the summary of an input that DSS cannot parse. No report is
     * written.
     *
     * @param rejection the rejection
     * @throws IOException if the file cannot be written
     */
    public synchronized void writeRejected(RejectedInputException rejection) throws IOException {
        requireOpen();
        Files.createDirectories(directory);
        Map<String, Object> summary = header("rejected");
        summary.put("input", rejection.option());
        summary.put("file", rejection.file());
        summary.put("message", rejection.getMessage());
        write(SUMMARY, Json.write(summary));
    }

    /**
     * Writes the summary of a run that exceeded a resource limit, in place of
     * any file written before, and closes the output: a later write fails
     * with {@link IllegalStateException}. A run that has exceeded a limit
     * may still be in progress on its worker thread.
     *
     * @param limit the limit exceeded: {@code heap}, {@code stack} or {@code time}
     * @param limits the limits of the run
     * @param message what happened, such as the message of the error
     * @throws IOException if a file cannot be removed or written
     */
    public synchronized void writeResourceLimit(String limit, ResourceLimits.Limits limits, String message)
            throws IOException {
        requireOpen();
        closed = true;
        for (Path file : written) {
            Files.deleteIfExists(file);
        }
        written.clear();
        Files.createDirectories(directory);
        Map<String, Object> summary = header("resource-limit");
        summary.put("limit", limit);
        Map<String, Object> recorded = new LinkedHashMap<>();
        recorded.put("heap-bytes", limits.heapBytes());
        recorded.put("stack-bytes", ResourceLimits.STACK_BYTES);
        recorded.put("timeout-seconds", limits.timeoutSeconds());
        recorded.put("garbage-collectors", limits.garbageCollectors());
        summary.put("limits", recorded);
        summary.put("message", message);
        write(SUMMARY, Json.write(summary));
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("The run exceeded a resource limit; its output is closed");
        }
    }

    /**
     * Formats a time as in RFC 3339, in UTC, as DSS reports times.
     *
     * @param time the time
     * @return the formatted time, such as {@code 2030-01-15T10:00:00Z}
     */
    public static String format(Instant time) {
        return DateTimeFormatter.ISO_INSTANT.format(time);
    }

    /**
     * Converts the messages of a DSS report into the entries of the lists
     * {@code errors} and {@code warnings} of {@code summary.json}.
     *
     * @param messages the messages, in the order of the report
     * @return one object per message, with its {@code key} and English {@code message}
     */
    public static List<Object> messages(List<Message> messages) {
        List<Object> list = new ArrayList<>();
        for (Message message : messages) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("key", message.getKey());
            entry.put("message", message.getValue());
            list.add(entry);
        }
        return list;
    }

    private Map<String, Object> header(String result) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("format-version", FORMAT_VERSION);
        summary.put("oracle", Versions.oracle());
        summary.put("mode", mode.commandName());
        summary.put("validation-time", format(validationTime));
        summary.put("policy", policy.summary());
        summary.put("result", result);
        return summary;
    }

    private void write(String name, String content) throws IOException {
        Path file = directory.resolve(name);
        written.add(file);
        Files.writeString(file, content, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
    }
}
