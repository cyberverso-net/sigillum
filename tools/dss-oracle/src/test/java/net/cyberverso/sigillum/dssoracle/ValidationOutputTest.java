package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ValidationOutputTest {

    private static final Instant TIME = Instant.parse("2030-01-15T10:00:00Z");

    @TempDir
    Path temp;

    private static List<String> files(Path directory) throws Exception {
        try (Stream<Path> entries = Files.list(directory)) {
            return entries.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }

    @Test
    void writesTheReportsOfTheModeUnchangedAndTheSummary() throws Exception {
        Path out = temp.resolve("out");
        ValidationOutput output = ValidationOutput.check(out, Mode.VALIDATE_CERTIFICATE, TIME, PolicySelection.named(OraclePolicy.DEFAULT));
        output.writeValidated(List.of(
                new ValidationOutput.Report("simple-certificate-report.xml", "<a>é</a>"),
                new ValidationOutput.Report("diagnostic-data.xml", "<b/>")),
                Indication.INDETERMINATE, SubIndication.TRY_LATER, Map.of());
        assertEquals(List.of("diagnostic-data.xml", "simple-certificate-report.xml", "summary.json"), files(out));
        assertEquals("<a>é</a>", Files.readString(out.resolve("simple-certificate-report.xml"),
                StandardCharsets.UTF_8));
        Map<String, Object> summary = JsonReader.object(Files.readString(out.resolve("summary.json")));
        assertEquals("validate-certificate", summary.get("mode"));
        assertEquals("default", summary.get("policy"));
        assertEquals(List.of("format-version", "oracle", "mode", "validation-time", "policy", "result", "indication",
                "sub-indication", "details"), List.copyOf(summary.keySet()));
        assertEquals("INDETERMINATE", summary.get("indication"));
        assertEquals("TRY_LATER", summary.get("sub-indication"));
    }

    @Test
    void refusesAReportNamedLikeTheSummaryOrTwice() throws Exception {
        Path out = temp.resolve("refused");
        ValidationOutput output = ValidationOutput.check(out, Mode.VALIDATE_TIMESTAMP, TIME, PolicySelection.named(OraclePolicy.ALIGNED));
        assertThrows(IllegalArgumentException.class, () -> output.writeValidated(
                List.of(new ValidationOutput.Report("summary.json", "<a/>")), Indication.PASSED, null, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> output.writeValidated(List.of(
                new ValidationOutput.Report("a.xml", "<a/>"), new ValidationOutput.Report("a.xml", "<b/>")),
                Indication.PASSED, null, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> output.writeValidated(
                List.of(new ValidationOutput.Report("../a.xml", "<a/>")), Indication.PASSED, null, Map.of()));
        assertFalse(Files.exists(out));
    }
}
