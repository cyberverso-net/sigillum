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
    void parsesTheDocumentOptions() throws UsageException {
        Arguments arguments = Arguments.parse(List.of(
                "validate-document",
                "--document", "signed.pdf",
                "--detached", "content.txt"));
        assertEquals(Optional.of(Path.of("signed.pdf")), arguments.document());
        assertEquals(Optional.of(Path.of("content.txt")), arguments.detached());
        Arguments none = Arguments.parse(List.of("validate-document"));
        assertEquals(Optional.empty(), none.document());
        assertEquals(Optional.empty(), none.detached());
    }

    @Test
    void rejectsDocumentOptionsGivenTwice() {
        for (String option : List.of("--document", "--detached")) {
            UsageException error = assertThrows(UsageException.class, () -> Arguments.parse(
                    List.of("validate-document", option, "a", option, "b")), option);
            assertTrue(error.getMessage().contains(option), error.getMessage());
        }
    }

    @Test
    void rejectsDocumentOptionsInOtherModes() {
        for (Mode mode : List.of(Mode.VALIDATE_TIMESTAMP, Mode.VALIDATE_CERTIFICATE, Mode.SIGN)) {
            // In sign, --document names the document to sign.
            List<String> options = mode == Mode.SIGN ? List.of("--detached") : List.of("--document", "--detached");
            for (String option : options) {
                UsageException error = assertThrows(UsageException.class,
                        () -> Arguments.parse(List.of(mode.commandName(), option, "x")), option);
                assertTrue(error.getMessage().contains(option + " is valid only in the mode validate-document"),
                        error.getMessage());
            }
        }
    }

    @Test
    void parsesTheTimeout() throws UsageException {
        assertEquals(Optional.of(30), Arguments.parse(List.of("validate-document", "--timeout", "30")).timeout());
        assertEquals(Optional.empty(), Arguments.parse(List.of("validate-document")).timeout());
        assertEquals(Optional.of(86400), Arguments.parse(List.of("validate-timestamp", "--timeout", "86400"))
                .timeout());
    }

    @Test
    void rejectsATimeoutThatIsNotAPositiveNumberOfSeconds() {
        for (String value : List.of("0", "-1", "1.5", "x", "86401", "99999999999")) {
            UsageException error = assertThrows(UsageException.class,
                    () -> Arguments.parse(List.of("validate-document", "--timeout", value)), value);
            assertTrue(error.getMessage().contains("--timeout"), error.getMessage());
        }
        assertThrows(UsageException.class, () -> Arguments.parse(
                List.of("validate-document", "--timeout", "1", "--timeout", "2")));
        UsageException sign = assertThrows(UsageException.class,
                () -> Arguments.parse(List.of("sign", "--timeout", "1")));
        assertTrue(sign.getMessage().contains("--timeout"), sign.getMessage());
    }

    @Test
    void parsesThePolicyOfTheValidationModes() throws UsageException {
        for (Mode mode : List.of(Mode.VALIDATE_DOCUMENT, Mode.VALIDATE_CERTIFICATE, Mode.VALIDATE_TIMESTAMP)) {
            assertEquals(Optional.of(PolicyOption.named(OraclePolicy.ALIGNED)),
                    Arguments.parse(List.of(mode.commandName(), "--policy", "aligned")).policy(), mode.commandName());
            assertEquals(Optional.of(PolicyOption.named(OraclePolicy.DEFAULT)),
                    Arguments.parse(List.of(mode.commandName(), "--policy", "default")).policy(), mode.commandName());
            assertEquals(Optional.of(PolicyOption.file(Path.of("policies/strict.xml"))),
                    Arguments.parse(List.of(mode.commandName(), "--policy", "policies/strict.xml")).policy(),
                    mode.commandName());
            assertEquals(Optional.empty(), Arguments.parse(List.of(mode.commandName())).policy(), mode.commandName());
        }
        // The names come first; a file with such a name is given with a path.
        assertEquals(Optional.of(PolicyOption.file(Path.of("./aligned"))),
                Arguments.parse(List.of("validate-certificate", "--policy", "./aligned")).policy());
    }

    @Test
    void rejectsAPolicyGivenTwiceAndAPolicyInSignMode() {
        UsageException twice = assertThrows(UsageException.class, () -> Arguments.parse(
                List.of("validate-certificate", "--policy", "aligned", "--policy", "default")));
        assertTrue(twice.getMessage().contains("--policy"), twice.getMessage());
        UsageException sign = assertThrows(UsageException.class,
                () -> Arguments.parse(List.of("sign", "--policy", "aligned")));
        assertTrue(sign.getMessage().contains("--policy"), sign.getMessage());
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

    @Test
    void parsesTheSignOptions() throws UsageException {
        Arguments arguments = Arguments.parse(List.of("sign",
                "--format", "cades", "--level", "B-T", "--key", "key.pem", "--certificate", "signer.pem",
                "--chain", "ca.pem", "--chain", "root.pem", "--signing-time", "2029-12-16T11:00:00+01:00",
                "--document", "text.txt", "--packaging", "detached", "--serialisation", "general",
                "--signature-algorithm", "ECDSA_SHA256", "--tsa-program", "testpki", "--tsa-key", "tsa-key.pem",
                "--tsa-cert", "tsa.pem", "--tsa-chain", "tsa-ca.pem", "--timestamp-time", "2029-12-16T10:05:00Z",
                "--out", "signed.p7m"));
        SignArguments sign = arguments.sign();
        assertEquals(Optional.of("cades"), sign.format());
        assertEquals(Optional.of("B-T"), sign.level());
        assertEquals(Optional.of(Path.of("key.pem")), sign.key());
        assertEquals(List.of(Path.of("signer.pem")), arguments.certificates());
        assertEquals(List.of(Path.of("ca.pem"), Path.of("root.pem")), sign.chain());
        assertEquals(Optional.of(Instant.parse("2029-12-16T10:00:00Z")), sign.signingTime());
        assertEquals(Optional.of(Path.of("text.txt")), sign.document());
        assertEquals(Optional.of("detached"), sign.packaging());
        assertEquals(Optional.of("general"), sign.serialisation());
        assertEquals(Optional.of("ECDSA_SHA256"), sign.signatureAlgorithm());
        assertEquals(Optional.of(Path.of("testpki")), sign.tsaProgram());
        assertEquals(Optional.of(Path.of("tsa-key.pem")), sign.tsaKey());
        assertEquals(Optional.of(Path.of("tsa.pem")), sign.tsaCertificate());
        assertEquals(List.of(Path.of("tsa-ca.pem")), sign.tsaChain());
        assertEquals(Optional.of(Instant.parse("2029-12-16T10:05:00Z")), sign.timestampTime());
        assertEquals(Optional.of(Path.of("signed.p7m")), arguments.out());
    }

    @Test
    void signOptionsAreEmptyWhenNotGiven() throws UsageException {
        SignArguments sign = Arguments.parse(List.of("sign")).sign();
        assertEquals(Optional.empty(), sign.format());
        assertTrue(sign.chain().isEmpty());
        assertTrue(sign.tsaChain().isEmpty());
        assertEquals(Optional.empty(), sign.timestampTime());
    }

    @Test
    void signOptionsGivenOnceAreNotRepeated() {
        for (String option : List.of("--format", "--level", "--key", "--signing-time", "--document", "--packaging",
                "--serialisation", "--signature-algorithm", "--tsa-program", "--tsa-key", "--tsa-cert",
                "--timestamp-time")) {
            String value = option.endsWith("-time") ? "2029-12-16T10:00:00Z" : "x";
            UsageException error = assertThrows(UsageException.class,
                    () -> Arguments.parse(List.of("sign", option, value, option, value)), option);
            assertTrue(error.getMessage().contains(option + " is given more than once"), error.getMessage());
        }
    }

    @Test
    void signTimesAreWholeSecondsInRfc3339() {
        for (String option : List.of("--signing-time", "--timestamp-time")) {
            for (String value : List.of("2029-12-16T10:00:00.1Z", "2029-12-16", "2029-12-16T23:59:60Z")) {
                UsageException error = assertThrows(UsageException.class,
                        () -> Arguments.parse(List.of("sign", option, value)), option + " " + value);
                assertTrue(error.getMessage().contains(option), error.getMessage());
            }
        }
    }

    @Test
    void signOptionsAreRefusedInOtherModes() {
        for (String option : SignArguments.OPTIONS) {
            UsageException error = assertThrows(UsageException.class,
                    () -> Arguments.parse(List.of("validate-timestamp", option, "x")), option);
            // --document is shared with validate-document, which the message names.
            String modes = option.equals("--document") ? "validate-document" : "sign";
            assertEquals(option + " is valid only in the mode " + modes + ".", error.getMessage());
        }
    }

    @Test
    void documentIsTheDocumentToSignInSignAndTheSignedDocumentInValidateDocument() throws UsageException {
        Arguments sign = Arguments.parse(List.of("sign", "--document", "text.txt"));
        assertEquals(Optional.of(Path.of("text.txt")), sign.sign().document());
        assertEquals(Optional.empty(), sign.document());
        Arguments validate = Arguments.parse(List.of("validate-document", "--document", "signed.p7m"));
        assertEquals(Optional.of(Path.of("signed.p7m")), validate.document());
        assertEquals(Optional.empty(), validate.sign().document());
    }

    @Test
    void signRefusesThePolicyAndTheTimeoutOfTheValidationModes() {
        for (String option : List.of("--policy", "--timeout")) {
            UsageException error = assertThrows(UsageException.class,
                    () -> Arguments.parse(List.of("sign", option, "aligned")), option);
            assertEquals(option + " is valid only in the validation modes.", error.getMessage());
        }
    }
}
