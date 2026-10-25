package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
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
    public static final int FORMAT_VERSION = 1;
    /** The file name of the summary. */
    public static final String SUMMARY = "summary.json";

    private final Path directory;
    private final Mode mode;
    private final Instant validationTime;

    /**
     * Checks the output directory before a run. It must not exist yet, or be
     * an empty directory, so that no file of an earlier run is mistaken for a
     * result of this one.
     *
     * @param directory the output directory
     * @param mode the mode that writes it
     * @param validationTime the validation time of the run
     * @return the output, not yet created
     * @throws IOException if the path is a file or a directory that is not empty
     */
    public static ValidationOutput check(Path directory, Mode mode, Instant validationTime) throws IOException {
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
        return new ValidationOutput(directory, mode, validationTime);
    }

    private ValidationOutput(Path directory, Mode mode, Instant validationTime) {
        this.directory = directory;
        this.mode = mode;
        this.validationTime = validationTime;
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
    public void writeValidated(List<Report> reports, Indication indication, SubIndication subIndication,
            Map<String, Object> details) throws IOException {
        Set<String> names = new HashSet<>();
        for (Report report : reports) {
            String name = report.fileName();
            Path path = Path.of(name);
            if (name.equals(SUMMARY) || path.getNameCount() != 1 || name.equals(".") || name.equals("..")
                    || path.isAbsolute() || !names.add(name)) {
                throw new IllegalArgumentException("Report file name not allowed: " + name);
            }
        }
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
    public void writeRejected(RejectedInputException rejection) throws IOException {
        Files.createDirectories(directory);
        Map<String, Object> summary = header("rejected");
        summary.put("input", rejection.option());
        summary.put("file", rejection.file());
        summary.put("message", rejection.getMessage());
        write(SUMMARY, Json.write(summary));
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

    private Map<String, Object> header(String result) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("format-version", FORMAT_VERSION);
        summary.put("mode", mode.commandName());
        summary.put("validation-time", format(validationTime));
        summary.put("result", result);
        return summary;
    }

    private void write(String name, String content) throws IOException {
        Files.writeString(directory.resolve(name), content, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
