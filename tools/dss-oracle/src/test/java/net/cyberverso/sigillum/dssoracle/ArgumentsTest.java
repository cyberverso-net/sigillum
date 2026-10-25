package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class ArgumentsTest {

    @Test
    void parsesTheModeAndEveryCommonOption() throws UsageException {
        Arguments arguments = Arguments.parse(List.of(
                "validate-certificate",
                "--validation-time", "2030-01-15T10:00:00Z",
                "--trust-anchor", "root.pem",
                "--trust-anchor", "other-root.pem",
                "--certificate", "ca.pem",
                "--certificate", "leaf.pem",
                "--crl", "ca.crl",
                "--ocsp", "leaf.ocsp",
                "--ocsp", "ca.ocsp",
                "--out", "results"));
        assertEquals(Mode.VALIDATE_CERTIFICATE, arguments.mode());
        assertEquals(Optional.of(Instant.parse("2030-01-15T10:00:00Z")), arguments.validationTime());
        assertEquals(List.of(Path.of("root.pem"), Path.of("other-root.pem")), arguments.trustAnchors());
        assertEquals(List.of(Path.of("ca.pem"), Path.of("leaf.pem")), arguments.certificates());
        assertEquals(List.of(Path.of("ca.crl")), arguments.crls());
        assertEquals(List.of(Path.of("leaf.ocsp"), Path.of("ca.ocsp")), arguments.ocspResponses());
        assertEquals(Optional.of(Path.of("results")), arguments.out());
    }

    @Test
    void acceptsEveryMode() throws UsageException {
        for (Mode mode : Mode.values()) {
            assertEquals(mode, Arguments.parse(List.of(mode.commandName())).mode());
        }
        assertEquals("validate-document", Mode.VALIDATE_DOCUMENT.commandName());
        assertEquals("validate-timestamp", Mode.VALIDATE_TIMESTAMP.commandName());
        assertEquals("sign", Mode.SIGN.commandName());
    }

    @Test
    void optionsAreOptional() throws UsageException {
        Arguments arguments = Arguments.parse(List.of("sign"));
        assertEquals(Optional.empty(), arguments.validationTime());
        assertTrue(arguments.trustAnchors().isEmpty());
        assertTrue(arguments.certificates().isEmpty());
        assertTrue(arguments.crls().isEmpty());
        assertTrue(arguments.ocspResponses().isEmpty());
        assertEquals(Optional.empty(), arguments.out());
    }

    @Test
    void convertsAnOffsetToAnInstant() throws UsageException {
        Arguments arguments = Arguments.parse(List.of("sign", "--validation-time", "2030-01-15T11:00:00+01:00"));
        assertEquals(Optional.of(Instant.parse("2030-01-15T10:00:00Z")), arguments.validationTime());
    }

    @Test
    void acceptsTheFormsThatRfc3339Allows() throws UsageException {
        for (String value : List.of("2030-01-15t10:00:00z", "2030-01-15T10:00:00.123456789Z",
                "2030-01-15T10:00:00-00:00")) {
            assertTrue(Arguments.parse(List.of("sign", "--validation-time", value)).validationTime().isPresent(), value);
        }
    }

    @Test
    void rejectsLeapSecondsWithASpecificMessage() {
        UsageException error = assertThrows(UsageException.class,
                () -> Arguments.parse(List.of("sign", "--validation-time", "2030-06-30T23:59:60Z")));
        assertTrue(error.getMessage().contains("leap seconds"), error.getMessage());
    }

    @Test
    void rejectsBlankValues() {
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "--out", "")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "--trust-anchor", " ")));
    }

    @Test
    void rejectsAMissingOrUnknownMode() {
        assertThrows(UsageException.class, () -> Arguments.parse(List.of()));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("validate")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("--out", "x")));
    }

    @Test
    void rejectsUnknownOptionsAndMissingValues() {
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "--colour", "red")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "stray")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "--out")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of("sign", "--crl", "--ocsp", "x")));
    }

    @Test
    void rejectsSingleValuedOptionsGivenTwice() {
        assertThrows(UsageException.class, () -> Arguments.parse(
                List.of("sign", "--out", "a", "--out", "b")));
        assertThrows(UsageException.class, () -> Arguments.parse(List.of(
                "sign", "--validation-time", "2030-01-15T10:00:00Z", "--validation-time", "2030-01-15T10:00:00Z")));
    }

    @Test
    void parsesTheTimestampOptions() throws UsageException {
        Arguments arguments = Arguments.parse(List.of(
                "validate-timestamp",
                "--timestamp", "token.tst",
                "--data", "content.txt",
                "--digest", "00ff",
                "--digest-algorithm", "SHA256"));
        assertEquals(Optional.of(Path.of("token.tst")), arguments.timestamp());
        assertEquals(Optional.of(Path.of("content.txt")), arguments.data());
        assertEquals(Optional.of("00ff"), arguments.digest());
        assertEquals(Optional.of("SHA256"), arguments.digestAlgorithm());
        Arguments none = Arguments.parse(List.of("validate-timestamp"));
        assertEquals(Optional.empty(), none.timestamp());
        assertEquals(Optional.empty(), none.data());
        assertEquals(Optional.empty(), none.digest());
        assertEquals(Optional.empty(), none.digestAlgorithm());
    }

    @Test
    void rejectsTimestampOptionsGivenTwice() {
        for (String option : List.of("--timestamp", "--data", "--digest", "--digest-algorithm")) {
            UsageException error = assertThrows(UsageException.class, () -> Arguments.parse(
                    List.of("validate-timestamp", option, "a", option, "b")), option);
            assertTrue(error.getMessage().contains(option), error.getMessage());
        }
    }

    @Test
    void rejectsTimestampOptionsInOtherModes() {
        for (Mode mode : List.of(Mode.VALIDATE_DOCUMENT, Mode.VALIDATE_CERTIFICATE, Mode.SIGN)) {
            for (String option : List.of("--timestamp", "--data", "--digest", "--digest-algorithm")) {
                UsageException error = assertThrows(UsageException.class,
                        () -> Arguments.parse(List.of(mode.commandName(), option, "x")), option);
                assertTrue(error.getMessage().contains(option), error.getMessage());
            }
        }
    }

    @Test
    void rejectsATimeThatIsNotRfc3339() {
        for (String value : List.of("2030-01-15", "2030-01-15T10:00:00", "soon", "2030-01-15T10:00Z",
                "2030-01-15T10:00:00+01:00:30", "+12030-01-15T10:00:00Z", "2030-02-30T10:00:00Z",
                "2030-01-15T23:59:60Z")) {
            UsageException error = assertThrows(UsageException.class,
                    () -> Arguments.parse(List.of("sign", "--validation-time", value)), value);
            assertTrue(error.getMessage().contains("--validation-time"), error.getMessage());
        }
    }
}
