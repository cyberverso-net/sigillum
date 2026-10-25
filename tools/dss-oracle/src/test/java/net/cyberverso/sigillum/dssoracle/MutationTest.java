package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The fuzz coverage of the input paths of validate-timestamp,
 * validate-certificate and validate-document: inputs of the corpus, mutated deterministically from
 * a fixed seed, are run through each mode in process. Every run must end
 * with exit code 0 and the result {@code validated} or {@code rejected}:
 * never an exception, a failure of the tool or a network attempt.
 *
 * <p>Every rejection is checked against DSS alone, without any code of the
 * tool, so that the tool rejects only what DSS cannot use. A rejected token
 * must make DSS fail at the stage where the tool rejected it. A rejected
 * certificate under validation must make DSS fail, since every validation
 * of it uses it. Any other rejected certificate, CRL or OCSP response must
 * not be one that DSS uses in a
 * validation that completes: DSS is run with the mutated file in the place
 * where the corpus uses it, and if the validation completes, the file must
 * not appear among the certificates or revocation data that DSS used. A
 * failing mutation is reported with its number, so that it can be
 * reproduced and given its own regression test.
 */
class MutationTest {

    /** The number of mutated runs. */
    static final int RUNS = 2000;
    private static final long SEED = 36;
    private static final Path CORPUS = Path.of("..", "..", "testdata");

    @TempDir
    Path temp;

    /**
     * An input of the mode: the option that names it, the corpus file it
     * replaces ({@code null} when it is added), its content, and whether the
     * run uses the token without certificates, so that DSS takes its signer
     * from the supplied certificates.
     */
    private record Input(String name, String option, String original, byte[] content, boolean der,
            boolean tokenWithoutCertificates) {
    }

    private static String corpus(String path) {
        return CORPUS.resolve(path).toString();
    }

    private static byte[] read(String path) throws IOException {
        return Files.readAllBytes(CORPUS.resolve(path));
    }

    private static byte[] der(String pemPath) throws IOException {
        return Pem.decode(Files.readString(CORPUS.resolve(pemPath)));
    }

    private static List<String> baseArguments(String token) {
        return new ArrayList<>(List.of(
                "validate-timestamp",
                "--timestamp", token,
                "--data", corpus("timestamps/content.txt"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--certificate", corpus("pki/ca-ecdsa.pem"),
                "--crl", corpus("crl/ca-ecdsa.crl"),
                "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", "2030-01-15T10:00:00Z"));
    }

    private static List<Input> inputs() throws Exception {
        List<Input> inputs = new ArrayList<>();
        for (String token : List.of("valid", "signer-without-time-stamping", "imprint-mismatch",
                "gen-time-after-validation-time")) {
            inputs.add(new Input(token, "--timestamp", corpus("timestamps/valid.tst"),
                    read("timestamps/" + token + ".tst"), true, false));
        }
        inputs.add(new Input("content", "--data", corpus("timestamps/content.txt"),
                read("timestamps/content.txt"), false, false));
        for (String crl : List.of("ca-ecdsa", "root-ca")) {
            inputs.add(new Input(crl + ".crl", "--crl", corpus("crl/" + crl + ".crl"), read("crl/" + crl + ".crl"),
                    true, false));
        }
        inputs.add(new Input("ocsp", "--ocsp", null, OcspResponses.forTsa(), true, false));
        // The signing certificate, supplied because the token leaves it out.
        inputs.add(new Input("tsa.cer", "--certificate", null, der("pki/tsa.pem"), true, true));
        // The trust anchor of every chain.
        inputs.add(new Input("root-ca.cer", "--trust-anchor", corpus("pki/root-ca.pem"), der("pki/root-ca.pem"),
                true, false));
        return inputs;
    }

    /** The files that DSS alone validates with; each list replaces the corpus files of its kind. */
    record Setup(byte[] token, List<byte[]> anchors, List<byte[]> certificates, List<byte[]> crls,
            List<byte[]> responses) {

        static Setup corpus(byte[] token) throws IOException {
            return new Setup(token, List.of(der("pki/root-ca.pem")), List.of(der("pki/ca-ecdsa.pem")),
                    List.of(read("crl/ca-ecdsa.crl"), read("crl/root-ca.crl")), List.of());
        }
    }

    /** The setup of DSS alone for a mutated input, with the file in the place where the run uses it. */
    private Setup setup(Input input, byte[] mutated, byte[] tokenWithoutCertificates) throws IOException {
        Setup corpus = Setup.corpus(read("timestamps/valid.tst"));
        return switch (input.name()) {
            case "ca-ecdsa.crl" -> new Setup(corpus.token(), corpus.anchors(), corpus.certificates(),
                    List.of(mutated, read("crl/root-ca.crl")), List.of());
            case "root-ca.crl" -> new Setup(corpus.token(), corpus.anchors(), corpus.certificates(),
                    List.of(read("crl/ca-ecdsa.crl"), mutated), List.of());
            case "ocsp" -> new Setup(corpus.token(), corpus.anchors(), corpus.certificates(), corpus.crls(),
                    List.of(mutated));
            case "tsa.cer" -> new Setup(tokenWithoutCertificates, corpus.anchors(),
                    List.of(der("pki/ca-ecdsa.pem"), mutated), corpus.crls(), List.of());
            case "root-ca.cer" -> new Setup(corpus.token(), List.of(mutated), corpus.certificates(), corpus.crls(),
                    List.of());
            default -> Setup.corpus(mutated);
        };
    }

    @Test
    void mutatedInputsAreValidatedOrRejected() throws Exception {
        List<Input> inputs = inputs();
        byte[] withoutCertificates = Tokens.withoutCertificates(read("timestamps/valid.tst"));
        Path tokenWithoutCertificates = Files.write(temp.resolve("valid-without-certificates.tst"),
                withoutCertificates);

        // Controls: DSS alone validates the corpus, and uses the files whose use the cross-checks look for.
        RawResult control = rawDss(Setup.corpus(read("timestamps/valid.tst")));
        assertEquals("PASSED null", control.indication(), String.valueOf(control.failure()));
        assertTrue(control.revocationIds().contains(CRLUtils.buildCRLBinary(read("crl/ca-ecdsa.crl")).asXmlId()));
        assertTrue(control.certificateIds().contains(DSSUtils.loadCertificate(der("pki/root-ca.pem"))
                .getDSSIdAsString()));
        Input tsa = inputs.stream().filter(input -> input.name().equals("tsa.cer")).findFirst().orElseThrow();
        RawResult supplied = rawDss(setup(tsa, tsa.content(), withoutCertificates));
        assertEquals("PASSED null", supplied.indication(), String.valueOf(supplied.failure()));
        assertTrue(supplied.certificateIds().contains(DSSUtils.loadCertificate(tsa.content()).getDSSIdAsString()));
        Input ocsp = inputs.stream().filter(input -> input.name().equals("ocsp")).findFirst().orElseThrow();
        RawResult withOcsp = rawDss(setup(ocsp, ocsp.content(), withoutCertificates));
        assertTrue(withOcsp.revocationIds().containsAll(revocationIds("--ocsp", ocsp.content())),
                withOcsp.revocationIds().toString());

        Random random = new Random(SEED);
        List<String> failures = new ArrayList<>();
        Map<String, Integer> results = new java.util.TreeMap<>();
        long start = System.nanoTime();
        for (int run = 0; run < RUNS; run++) {
            Input input = inputs.get(random.nextInt(inputs.size()));
            Mutation mutation = Mutation.random(random, input.content(), input.der());
            byte[] mutated = mutation.apply(input.content());
            Path directory = Files.createDirectories(temp.resolve("run-" + run));
            Path file = Files.write(directory.resolve("input"), mutated);
            Path out = directory.resolve("out");
            List<String> args = baseArguments(input.tokenWithoutCertificates()
                    ? tokenWithoutCertificates.toString() : corpus("timestamps/valid.tst"));
            if (input.original() == null) {
                args.addAll(List.of(input.option(), file.toString()));
            } else {
                args.set(args.indexOf(input.original()), file.toString());
            }
            args.addAll(List.of("--out", out.toString()));
            String label = "run " + run + ", " + input.name() + ", " + mutation;
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int code;
            try {
                code = Main.run(args.toArray(String[]::new), Modes.RUNNER,
                        new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                        new PrintStream(err, true, StandardCharsets.UTF_8));
            } catch (RuntimeException | Error e) {
                failures.add(label + ": " + e);
                continue;
            }
            if (code != ExitCodes.SUCCESS) {
                failures.add(label + ": exit " + code + ": " + err.toString(StandardCharsets.UTF_8).strip());
            } else {
                Map<String, Object> summary = JsonReader.object(Files.readString(out.resolve("summary.json")));
                Object result = summary.get("result");
                results.merge(input.name() + " " + result, 1, Integer::sum);
                if (!"validated".equals(result) && !"rejected".equals(result)) {
                    failures.add(label + ": result " + result);
                }
                if ("rejected".equals(result)) {
                    String message = (String) summary.get("message");
                    String problem = input.option().equals("--timestamp")
                            ? crossCheckToken(mutated, message)
                            : crossCheckFile(input, mutated, setup(input, mutated, withoutCertificates));
                    if (problem != null) {
                        failures.add(label + ": " + problem);
                    }
                }
            }
            delete(directory);
        }
        long seconds = (System.nanoTime() - start) / 1_000_000_000L;
        System.out.println("MutationTest: " + RUNS + " runs in " + seconds + " s: " + results);
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n" + String.join("\n", failures));
        assertEquals(RUNS, results.values().stream().mapToInt(Integer::intValue).sum());
    }

    /** The number of mutated runs of validate-certificate. */
    static final int CERTIFICATE_RUNS = 2000;
    private static final long CERTIFICATE_SEED = 35;

    /**
     * The files that DSS alone validates a certificate with: the certificate,
     * and the lists that replace the corpus files of each kind.
     */
    record CertificateSetup(byte[] certificate, List<byte[]> anchors, List<byte[]> certificates, List<byte[]> crls,
            List<byte[]> responses, byte[] policy) {

        CertificateSetup(byte[] certificate, List<byte[]> anchors, List<byte[]> certificates, List<byte[]> crls,
                List<byte[]> responses) {
            this(certificate, anchors, certificates, crls, responses, null);
        }

        static CertificateSetup corpus() throws IOException {
            return new CertificateSetup(der("pki/signer-p256.pem"), List.of(der("pki/root-ca.pem")),
                    List.of(der("pki/ca-ecdsa.pem")), List.of(read("crl/ca-ecdsa.crl"), read("crl/root-ca.crl")),
                    List.of());
        }
    }

    /** The input of the policy file: the aligned certificate policy, as a DSS policy file. */
    private static final String POLICY = "policy.xml";
    /**
     * The input of a policy file that DSS loads but cannot validate with: the
     * aligned certificate policy with the date format of AlgoExpirationDate
     * replaced by one that DSS cannot use.
     */
    private static final String POLICY_BAD_FORMAT = "policy-bad-format.xml";

    private static byte[] alignedPolicyFile() throws Exception {
        return eu.europa.esig.dss.policy.ValidationPolicyFacade.newFacade().marshall(
                AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.CERTIFICATE_BASE)))
                .getBytes(StandardCharsets.UTF_8);
    }

    /** The input of the OCSP response run without the CRL of pki/ca-ecdsa. */
    private static final String OCSP_ALONE = "ocsp-signer-p256-alone";

    private static List<String> certificateArguments(String certificate) {
        return new ArrayList<>(List.of(
                "validate-certificate",
                "--certificate", certificate,
                "--certificate", corpus("pki/ca-ecdsa.pem"),
                "--trust-anchor", corpus("pki/root-ca.pem"),
                "--crl", corpus("crl/ca-ecdsa.crl"),
                "--crl", corpus("crl/root-ca.crl"),
                "--validation-time", "2030-01-15T10:00:00Z"));
    }

    private static List<Input> certificateInputs() throws Exception {
        List<Input> inputs = new ArrayList<>();
        // The certificate under validation, in DER, in place of the PEM file of the corpus.
        inputs.add(new Input("signer-p256.cer", "--certificate", corpus("pki/signer-p256.pem"),
                der("pki/signer-p256.pem"), true, false));
        for (String crl : List.of("ca-ecdsa", "root-ca")) {
            inputs.add(new Input(crl + ".crl", "--crl", corpus("crl/" + crl + ".crl"), read("crl/" + crl + ".crl"),
                    true, false));
        }
        // The response of the delegated responder, which holds the responder's certificate: once beside the
        // CRL of pki/ca-ecdsa, and once alone, so that DSS takes the status of pki/signer-p256 from it.
        inputs.add(new Input("ocsp-signer-p256", "--ocsp", null, read("ocsp/signer-p256.der"), true, false));
        inputs.add(new Input(OCSP_ALONE, "--ocsp", null, read("ocsp/signer-p256.der"), true, false));
        // A policy file (ADR-0023), which DSS loads with its policy schema.
        inputs.add(new Input(POLICY, "--policy", null, alignedPolicyFile(), false, false));
        inputs.add(new Input(POLICY_BAD_FORMAT, "--policy", null, new String(alignedPolicyFile(), StandardCharsets.UTF_8)
                .replace("Format=\"yyyy-MM-dd\"", "Format=\"nonsense\"").getBytes(StandardCharsets.UTF_8), false, false));
        return inputs;
    }

    /** The setup of DSS alone for a mutated input of validate-certificate. */
    private static CertificateSetup certificateSetup(Input input, byte[] mutated) throws IOException {
        CertificateSetup corpus = CertificateSetup.corpus();
        return switch (input.name()) {
            case "signer-p256.cer" -> new CertificateSetup(mutated, corpus.anchors(), corpus.certificates(),
                    corpus.crls(), List.of());
            case "ca-ecdsa.crl" -> new CertificateSetup(corpus.certificate(), corpus.anchors(), corpus.certificates(),
                    List.of(mutated, read("crl/root-ca.crl")), List.of());
            case "root-ca.crl" -> new CertificateSetup(corpus.certificate(), corpus.anchors(), corpus.certificates(),
                    List.of(read("crl/ca-ecdsa.crl"), mutated), List.of());
            case OCSP_ALONE -> new CertificateSetup(corpus.certificate(), corpus.anchors(), corpus.certificates(),
                    List.of(read("crl/root-ca.crl")), List.of(mutated));
            case POLICY, POLICY_BAD_FORMAT -> new CertificateSetup(corpus.certificate(), corpus.anchors(),
                    corpus.certificates(), corpus.crls(), List.of(), mutated);
            default -> new CertificateSetup(corpus.certificate(), corpus.anchors(), corpus.certificates(),
                    corpus.crls(), List.of(mutated));
        };
    }

    @Test
    void mutatedCertificateInputsAreValidatedOrRejected() throws Exception {
        List<Input> inputs = certificateInputs();

        // Controls: DSS alone validates the corpus, and uses the files whose use the cross-checks look for.
        RawResult control = rawCertificateDss(CertificateSetup.corpus());
        assertEquals("PASSED null", control.indication(), String.valueOf(control.failure()));
        assertTrue(control.revocationIds().contains(CRLUtils.buildCRLBinary(read("crl/ca-ecdsa.crl")).asXmlId()));
        assertTrue(control.revocationIds().contains(CRLUtils.buildCRLBinary(read("crl/root-ca.crl")).asXmlId()));
        Input policy = inputs.stream().filter(input -> input.name().equals(POLICY)).findFirst().orElseThrow();
        RawResult withPolicy = rawCertificateDss(certificateSetup(policy, policy.content()));
        assertEquals("PASSED null", withPolicy.indication(), String.valueOf(withPolicy.failure()));
        Input badFormat = inputs.stream().filter(input -> input.name().equals(POLICY_BAD_FORMAT)).findFirst()
                .orElseThrow();
        assertTrue(rawCertificateDss(certificateSetup(badFormat, badFormat.content())).failure() != null,
                "DSS validates with the policy whose date format it cannot use");
        for (Input input : inputs.stream().filter(input -> input.option().equals("--ocsp")).toList()) {
            RawResult withOcsp = rawCertificateDss(certificateSetup(input, input.content()));
            assertEquals("PASSED null", withOcsp.indication(), input.name() + " " + withOcsp.failure());
            assertTrue(withOcsp.revocationIds().containsAll(revocationIds("--ocsp", input.content())),
                    input.name() + " " + withOcsp.revocationIds());
        }


        Random random = new Random(CERTIFICATE_SEED);
        List<String> failures = new ArrayList<>();
        Map<String, Integer> results = new java.util.TreeMap<>();
        long start = System.nanoTime();
        for (int run = 0; run < CERTIFICATE_RUNS; run++) {
            Input input = inputs.get(random.nextInt(inputs.size()));
            Mutation mutation = Mutation.random(random, input.content(), input.der());
            byte[] mutated = mutation.apply(input.content());
            Path directory = Files.createDirectories(temp.resolve("certificate-run-" + run));
            Path file = Files.write(directory.resolve("input"), mutated);
            Path out = directory.resolve("out");
            List<String> args = certificateArguments(corpus("pki/signer-p256.pem"));
            if (input.name().equals(OCSP_ALONE)) {
                int crl = args.indexOf(corpus("crl/ca-ecdsa.crl"));
                args.subList(crl - 1, crl + 1).clear();
            }
            if (input.original() == null) {
                args.addAll(List.of(input.option(), file.toString()));
            } else {
                args.set(args.indexOf(input.original()), file.toString());
            }
            args.addAll(List.of("--out", out.toString()));
            String label = "certificate run " + run + ", " + input.name() + ", " + mutation;
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int code;
            try {
                code = Main.run(args.toArray(String[]::new), Modes.RUNNER,
                        new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                        new PrintStream(err, true, StandardCharsets.UTF_8));
            } catch (RuntimeException | Error e) {
                failures.add(label + ": " + e);
                continue;
            }
            if (code != ExitCodes.SUCCESS) {
                failures.add(label + ": exit " + code + ": " + err.toString(StandardCharsets.UTF_8).strip());
            } else {
                Map<String, Object> summary = JsonReader.object(Files.readString(out.resolve("summary.json")));
                Object result = summary.get("result");
                results.merge(input.name() + " " + result, 1, Integer::sum);
                if (!"validated".equals(result) && !"rejected".equals(result)) {
                    failures.add(label + ": result " + result);
                }
                if ("rejected".equals(result)) {
                    String problem = crossCheckCertificateInput(input, mutated, certificateSetup(input, mutated));
                    if (problem != null) {
                        failures.add(label + ": " + problem);
                    }
                }
            }
            delete(directory);
        }
        long seconds = (System.nanoTime() - start) / 1_000_000_000L;
        System.out.println("MutationTest: " + CERTIFICATE_RUNS + " certificate runs in " + seconds + " s: " + results);
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n" + String.join("\n", failures));
        assertEquals(CERTIFICATE_RUNS, results.values().stream().mapToInt(Integer::intValue).sum());
    }

    /** The number of mutated runs of validate-document. */
    static final int DOCUMENT_RUNS = 2000;
    private static final long DOCUMENT_SEED = 37;

    /**
     * The files that DSS alone validates a document with, besides the chain
     * and CRLs of pki/signer-p256: the document, the detached content or
     * {@code null}, and the policy or {@code null} for the default one.
     */
    record DocumentSetup(byte[] document, byte[] detached, byte[] policy) {
    }

    /** The inputs of validate-document, and the setup of each without mutation. */
    private static Map<String, DocumentSetup> documentSetups() throws Exception {
        Map<String, DocumentSetup> setups = new java.util.LinkedHashMap<>();
        setups.put("cades", new DocumentSetup(Documents.cades(), null, null));
        setups.put("cades-t", new DocumentSetup(Documents.cadesT(), null, null));
        setups.put("cades-detached", new DocumentSetup(Documents.cadesDetached(), Documents.CONTENT, null));
        setups.put("content", new DocumentSetup(Documents.cadesDetached(), Documents.CONTENT, null));
        setups.put("pades", new DocumentSetup(Documents.pades(), null, null));
        setups.put("jades", new DocumentSetup(Documents.jades(), null, null));
        setups.put("jades-json", new DocumentSetup(Documents.jadesJson(), null, null));
        setups.put("policy", new DocumentSetup(Documents.cades(), null, Documents.defaultPolicy()));
        return setups;
    }

    /** The option of each input of validate-document. */
    private static String documentOption(String name) {
        return switch (name) {
            case "content" -> "--detached";
            case "policy" -> "--policy";
            default -> "--document";
        };
    }

    /** The setup with the mutated file in the place of the input. */
    private static DocumentSetup mutatedSetup(String name, DocumentSetup setup, byte[] mutated) {
        return switch (documentOption(name)) {
            case "--detached" -> new DocumentSetup(setup.document(), mutated, setup.policy());
            case "--policy" -> new DocumentSetup(setup.document(), setup.detached(), mutated);
            default -> new DocumentSetup(mutated, setup.detached(), setup.policy());
        };
    }

    private static byte[] mutatedInput(String name, DocumentSetup setup) {
        return switch (documentOption(name)) {
            case "--detached" -> setup.detached();
            case "--policy" -> setup.policy();
            default -> setup.document();
        };
    }

    @Test
    void mutatedDocumentInputsAreValidatedOrRejected() throws Exception {
        Map<String, DocumentSetup> setups = documentSetups();
        List<String> names = List.copyOf(setups.keySet());

        // Controls: DSS alone validates every document of the inputs as TOTAL_PASSED.
        for (Map.Entry<String, DocumentSetup> entry : setups.entrySet()) {
            RawResult control = rawDocumentDss(entry.getValue());
            assertEquals("TOTAL_PASSED null", control.indication(), entry.getKey() + " " + control.failure());
        }

        Random random = new Random(DOCUMENT_SEED);
        List<String> failures = new ArrayList<>();
        Map<String, Integer> results = new java.util.TreeMap<>();
        long start = System.nanoTime();
        for (int run = 0; run < DOCUMENT_RUNS; run++) {
            String name = names.get(random.nextInt(names.size()));
            DocumentSetup setup = setups.get(name);
            byte[] original = mutatedInput(name, setup);
            boolean der = name.startsWith("cades");
            Mutation mutation = Mutation.random(random, original, der);
            byte[] mutated = mutation.apply(original);
            DocumentSetup changed = mutatedSetup(name, setup, mutated);
            Path directory = Files.createDirectories(temp.resolve("document-run-" + run));
            Path document = Files.write(directory.resolve("document"), changed.document());
            Path out = directory.resolve("out");
            List<String> args = new ArrayList<>(List.of(
                    "validate-document",
                    "--document", document.toString(),
                    "--trust-anchor", corpus("pki/root-ca.pem"),
                    "--certificate", corpus("pki/ca-ecdsa.pem"),
                    "--crl", corpus("crl/ca-ecdsa.crl"),
                    "--crl", corpus("crl/root-ca.crl"),
                    "--validation-time", "2030-01-15T10:00:00Z",
                    "--out", out.toString()));
            if (changed.detached() != null) {
                args.addAll(List.of("--detached", Files.write(directory.resolve("detached"), changed.detached())
                        .toString()));
            }
            if (changed.policy() != null) {
                args.addAll(List.of("--policy", Files.write(directory.resolve("policy"), changed.policy())
                        .toString()));
            }
            String label = "document run " + run + ", " + name + ", " + mutation;
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int code;
            try {
                code = Main.run(args.toArray(String[]::new), Modes.RUNNER,
                        new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8),
                        new PrintStream(err, true, StandardCharsets.UTF_8));
            } catch (RuntimeException | Error e) {
                failures.add(label + ": " + e);
                continue;
            }
            if (code != ExitCodes.SUCCESS) {
                failures.add(label + ": exit " + code + ": " + err.toString(StandardCharsets.UTF_8).strip());
            } else {
                Map<String, Object> summary = JsonReader.object(Files.readString(out.resolve("summary.json")));
                Object result = summary.get("result");
                results.merge(name + " " + result, 1, Integer::sum);
                if (!"validated".equals(result) && !"rejected".equals(result)) {
                    failures.add(label + ": result " + result);
                }
                if ("validated".equals(result)) {
                    // The checks of the tool run on the objects that DSS then validates; they must not change
                    // the result that DSS alone gives.
                    RawResult raw = rawDocumentDss(changed);
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> signatures = (List<Map<String, Object>>)
                            ((Map<String, Object>) summary.get("details")).get("signatures");
                    String tool = signatures.isEmpty() ? "no signature"
                            : signatures.get(0).get("indication") + " " + signatures.get(0).get("sub-indication");
                    if (!tool.equals(raw.indication())) {
                        failures.add(label + ": the tool gives " + tool + ", DSS alone " + raw.indication()
                                + " " + raw.failure());
                    }
                }
                if ("rejected".equals(result)) {
                    if (!documentOption(name).equals(summary.get("input"))) {
                        failures.add(label + ": rejected as " + summary.get("input"));
                    }
                    // Every validation uses the document, the detached content and the policy: DSS alone must fail.
                    RawResult raw = rawDocumentDss(changed);
                    if (raw.failure() == null) {
                        failures.add(label + ": rejected (" + summary.get("message") + "), but DSS validates it: "
                                + raw.indication());
                    }
                }
            }
            delete(directory);
        }
        long seconds = (System.nanoTime() - start) / 1_000_000_000L;
        System.out.println("MutationTest: " + DOCUMENT_RUNS + " document runs in " + seconds + " s: " + results);
        assertTrue(failures.isEmpty(), failures.size() + " failures:\n" + String.join("\n", failures));
        assertEquals(DOCUMENT_RUNS, results.values().stream().mapToInt(Integer::intValue).sum());
    }

    /**
     * Validates a document with DSS alone, without any code of the tool, with
     * the chain and CRLs of pki/signer-p256, and returns the indication of
     * its first signature, or the failure. DSS is given a signature policy
     * provider without a data loader, so that it retrieves no policy.
     */
    static RawResult rawDocumentDss(DocumentSetup setup) {
        try {
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            trusted.addCertificate(DSSUtils.loadCertificate(der("pki/root-ca.pem")));
            CommonCertificateSource adjunct = new CommonCertificateSource();
            adjunct.addCertificate(DSSUtils.loadCertificate(der("pki/ca-ecdsa.pem")));
            CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
            verifier.setTrustedCertSources(trusted);
            verifier.setAdjunctCertSources(adjunct);
            verifier.setCrlSource(new ExternalResourcesCRLSource(documents(
                    List.of(read("crl/ca-ecdsa.crl"), read("crl/root-ca.crl")))));
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
                    new InMemoryDocument(setup.document(), "document"));
            validator.setCertificateVerifier(verifier);
            // As the tool does: the supplied certificates are candidates for the signing certificate.
            CommonCertificateSource signing = new CommonCertificateSource();
            trusted.getCertificates().forEach(signing::addCertificate);
            adjunct.getCertificates().forEach(signing::addCertificate);
            validator.setSigningCertificateSource(signing);
            validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
            validator.setValidationTime(Date.from(Instant.parse("2030-01-15T10:00:00Z")));
            if (setup.detached() != null) {
                validator.setDetachedContents(List.of(new InMemoryDocument(setup.detached(), "detached")));
            }
            // Without a policy file, the tool applies the aligned policy (ADR-0023).
            Reports reports = setup.policy() == null ? validator.validateDocument(AlignedPolicy.forDocuments())
                    : validator.validateDocument(new InMemoryDocument(setup.policy(), "policy"));
            // The tool writes the reports; DSS alone must be able to as well.
            reports.getXmlDiagnosticData();
            reports.getXmlDetailedReport();
            reports.getXmlSimpleReport();
            reports.getXmlValidationReport();
            SimpleReport simple = reports.getSimpleReport();
            String id = simple.getFirstSignatureId();
            return new RawResult(id == null ? "no signature" : simple.getIndication(id) + " "
                    + simple.getSubIndication(id), null, Set.of(), Set.of());
        } catch (RuntimeException | IOException | OutOfMemoryError | StackOverflowError e) {
            return new RawResult(null, e, Set.of(), Set.of());
        }
    }

    /**
     * Checks an input of validate-certificate that the tool rejects. DSS
     * alone must fail on a rejected certificate under validation, since every
     * validation uses it. If DSS alone completes the validation with a
     * rejected CRL or OCSP response in its place, it must not have used it.
     *
     * @return the problem, or {@code null}
     */
    private static String crossCheckCertificateInput(Input input, byte[] mutated, CertificateSetup setup) {
        RawResult raw = rawCertificateDss(setup);
        if (raw.failure() != null) {
            return null;
        }
        if (input.option().equals("--certificate") || input.option().equals("--policy")) {
            return "rejected, but DSS validates it: " + raw.indication();
        }
        boolean used = revocationIds(input.option(), mutated).stream().anyMatch(raw.revocationIds()::contains);
        return used ? "rejected, but DSS uses it and validates: " + raw.indication() : null;
    }

    /**
     * Validates a certificate with DSS alone, without any code of the tool,
     * and returns the indication with the identifiers of the certificates and
     * revocation data that DSS used, or the failure.
     */
    static RawResult rawCertificateDss(CertificateSetup setup) {
        try {
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            for (byte[] anchor : setup.anchors()) {
                trusted.addCertificate(DSSUtils.loadCertificate(anchor));
            }
            CommonCertificateSource adjunct = new CommonCertificateSource();
            for (byte[] certificate : setup.certificates()) {
                adjunct.addCertificate(DSSUtils.loadCertificate(certificate));
            }
            CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
            verifier.setTrustedCertSources(trusted);
            verifier.setAdjunctCertSources(adjunct);
            verifier.setCrlSource(new ExternalResourcesCRLSource(documents(setup.crls())));
            verifier.setOcspSource(new ExternalResourcesOCSPSource(documents(setup.responses())));
            CertificateToken certificate = DSSUtils.loadCertificate(setup.certificate());
            CertificateValidator validator = CertificateValidator.fromCertificate(certificate);
            validator.setCertificateVerifier(verifier);
            validator.setValidationTime(Date.from(Instant.parse("2030-01-15T10:00:00Z")));
            CertificateReports reports = setup.policy() == null ? validator.validate()
                    : validator.validate(eu.europa.esig.dss.validation.policy.ValidationPolicyLoader.fromValidationPolicy(
                            new eu.europa.esig.dss.model.InMemoryDocument(setup.policy())).create());
            // The tool writes the reports; DSS alone must be able to as well.
            reports.getXmlDiagnosticData();
            reports.getXmlDetailedReport();
            reports.getXmlSimpleReport();
            String id = certificate.getDSSIdAsString();
            DiagnosticData diagnostic = reports.getDiagnosticData();
            return new RawResult(reports.getSimpleReport().getCertificateIndication(id) + " "
                    + reports.getSimpleReport().getCertificateSubIndication(id), null,
                    diagnostic.getUsedCertificates().stream().map(CertificateWrapper::getId).collect(Collectors.toSet()),
                    usedRevocationIds(diagnostic));
        } catch (RuntimeException | OutOfMemoryError e) {
            return new RawResult(null, e, Set.of(), Set.of());
        }
    }

    /** The result of DSS alone: an indication and what it used, or the failure. */
    record RawResult(String indication, Throwable failure, Set<String> certificateIds,
            Set<String> revocationIds) {
    }

    /**
     * Where DSS must fail on a token that the tool rejects, by the start of
     * the rejection message: the DSS methods of which one must be in the
     * stack of the failure of DSS alone. Rejections with another message come
     * from parsing the token.
     */
    private static final Map<String, List<String>> STAGES = Map.of(
            "the algorithm of the message imprint", List.of("DigestAlgorithm.forOID"),
            "DSS cannot compute the digest algorithm", List.of("DSSUtils.getMessageDigest"),
            "a certificate in the token", List.of("DSSPKUtils.getPublicKeySize", "CertificateExtensionsUtils.*",
                    "DSSASN1Utils.extractAttributeFromX500Principal"),
            "the signature of the token", List.of("TimestampToken.isSignedBy"),
            "the signing certificate attribute", List.of("CMSCertificateSource.*", "CertificateRefIdentifier.*",
                    "CertificateTokenRefMatcher.*"));

    private static final List<String> PARSING = List.of("TimestampToken.<init>", "TimeStampToken.<init>");

    /**
     * Checks a token that the tool rejects: DSS alone must fail on it too, and
     * at the same stage.
     *
     * @return the problem, or {@code null}
     */
    static String crossCheckToken(byte[] token, String message) throws Exception {
        RawResult raw = rawDss(Setup.corpus(token));
        if (raw.failure() == null) {
            return "rejected, but DSS validates it: " + raw.indication();
        }
        List<String> expected = STAGES.entrySet().stream().filter(entry -> message.startsWith(entry.getKey()))
                .map(Map.Entry::getValue).findFirst().orElse(PARSING);
        for (Throwable cause = raw.failure(); cause != null; cause = cause.getCause()) {
            for (StackTraceElement frame : cause.getStackTrace()) {
                String method = frame.getClassName().substring(frame.getClassName().lastIndexOf('.') + 1)
                        + "." + frame.getMethodName();
                String type = method.substring(0, method.indexOf('.'));
                if (expected.contains(method) || expected.contains(type + ".*")) {
                    return null;
                }
            }
        }
        return "rejected (" + message + "), but DSS fails elsewhere: " + raw.failure();
    }

    /**
     * Checks a certificate, CRL or OCSP response that the tool rejects: if
     * DSS alone completes the validation with the file in its place, it must
     * not have used the file.
     *
     * @return the problem, or {@code null}
     */
    private static String crossCheckFile(Input input, byte[] mutated, Setup setup) throws Exception {
        RawResult raw = rawDss(setup);
        if (raw.failure() != null) {
            return null;
        }
        boolean used = switch (input.option()) {
            case "--certificate", "--trust-anchor" -> certificateId(mutated).map(raw.certificateIds()::contains)
                    .orElse(false);
            default -> revocationIds(input.option(), mutated).stream().anyMatch(raw.revocationIds()::contains);
        };
        return used ? "rejected, but DSS uses it and validates: " + raw.indication() : null;
    }

    private static java.util.Optional<String> certificateId(byte[] certificate) {
        try {
            return java.util.Optional.of(DSSUtils.loadCertificate(certificate).getDSSIdAsString());
        } catch (RuntimeException e) {
            return java.util.Optional.empty();
        }
    }

    /** The identifiers that DSS gives the revocation data of a file, or none when it cannot load it. */
    private static Set<String> revocationIds(String option, byte[] content) {
        try {
            if (option.equals("--crl")) {
                return Set.of(CRLUtils.buildCRLBinary(content).asXmlId());
            }
            return new ExternalResourcesOCSPSource(new InMemoryDocument(content, "ocsp")).getAllRevocationBinaries()
                    .stream().map(binary -> binary.asXmlId()).collect(Collectors.toSet());
        } catch (RuntimeException e) {
            return Set.of();
        }
    }

    /**
     * Validates a token with DSS alone, without any code of the tool, and
     * returns the indication with the identifiers of the certificates and
     * revocation data that DSS used, or the failure.
     */
    static RawResult rawDss(Setup setup) throws Exception {
        try {
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            for (byte[] anchor : setup.anchors()) {
                trusted.addCertificate(DSSUtils.loadCertificate(anchor));
            }
            CommonCertificateSource adjunct = new CommonCertificateSource();
            for (byte[] certificate : setup.certificates()) {
                adjunct.addCertificate(DSSUtils.loadCertificate(certificate));
            }
            CommonCertificateVerifier verifier = new CommonCertificateVerifier(true);
            verifier.setTrustedCertSources(trusted);
            verifier.setAdjunctCertSources(adjunct);
            verifier.setCrlSource(new ExternalResourcesCRLSource(documents(setup.crls())));
            verifier.setOcspSource(new ExternalResourcesOCSPSource(documents(setup.responses())));
            DetachedTimestampValidator validator = new DetachedTimestampValidator(
                    new InMemoryDocument(setup.token(), "token"), TimestampType.CONTENT_TIMESTAMP);
            validator.setCertificateVerifier(verifier);
            validator.setValidationTime(Date.from(Instant.parse("2030-01-15T10:00:00Z")));
            validator.setTimestampedData(new InMemoryDocument(read("timestamps/content.txt"), "content"));
            Reports reports = validator.validateDocument();
            SimpleReport simple = reports.getSimpleReport();
            DiagnosticData diagnostic = reports.getDiagnosticData();
            String id = simple.getFirstTimestampId();
            return new RawResult(id == null ? "no timestamp" : simple.getIndication(id) + " "
                    + simple.getSubIndication(id), null,
                    diagnostic.getUsedCertificates().stream().map(CertificateWrapper::getId).collect(Collectors.toSet()),
                    usedRevocationIds(diagnostic));
        } catch (RuntimeException | OutOfMemoryError e) {
            // OutOfMemoryError: DSS alone, given a mutated CRL that declares a large length, has been observed
            // to use memory in proportion to it. The tool rejects such a CRL before DSS reads it.
            return new RawResult(null, e, Set.of(), Set.of());
        }
    }

    /**
     * The identifiers of the revocation data whose signing certificate DSS
     * found. The diagnostic data also lists revocation data whose signer DSS
     * could not find, which it cannot have used. Data whose signature does
     * not verify is kept, so that a wrong rejection of a readable file with
     * a bad signature is still caught.
     */
    private static Set<String> usedRevocationIds(DiagnosticData diagnostic) {
        return diagnostic.getAllRevocationData().stream()
                .filter(revocation -> revocation.getSigningCertificate() != null)
                .map(RevocationWrapper::getId).collect(Collectors.toSet());
    }

    private static DSSDocument[] documents(List<byte[]> contents) {
        return contents.stream().map(content -> new InMemoryDocument(content, "file")).toArray(DSSDocument[]::new);
    }

    private static void delete(Path directory) throws IOException {
        try (Stream<Path> paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }

    /** A mutation of an input, described so that it can be reproduced. */
    private record Mutation(String kind, int offset, int value) {

        static Mutation random(Random random, byte[] content, boolean der) {
            int kind = random.nextInt(der ? 5 : 4);
            int offset = random.nextInt(content.length);
            return switch (kind) {
                case 0 -> new Mutation("flip", offset, 1 << random.nextInt(8));
                case 1 -> new Mutation("replace", offset, random.nextInt(256));
                case 2 -> new Mutation("truncate", offset, 0);
                case 3 -> new Mutation("insert", offset, random.nextInt(256));
                default -> {
                    List<Integer> lengths = lengthOffsets(content);
                    int at = lengths.get(random.nextInt(lengths.size()));
                    int[] values = {0x00, 0x01, 0x7f, 0x80, 0x81, 0x84, 0xff,
                        (content[at] & 0xff) + 1, (content[at] & 0xff) - 1};
                    yield new Mutation("length", at, values[random.nextInt(values.length)] & 0xff);
                }
            };
        }

        byte[] apply(byte[] content) {
            return switch (kind) {
                case "flip" -> {
                    byte[] copy = content.clone();
                    copy[offset] ^= (byte) value;
                    yield copy;
                }
                case "replace", "length" -> {
                    byte[] copy = content.clone();
                    copy[offset] = (byte) value;
                    yield copy;
                }
                case "truncate" -> Arrays.copyOf(content, offset);
                case "insert" -> {
                    byte[] copy = new byte[content.length + 1];
                    System.arraycopy(content, 0, copy, 0, offset);
                    copy[offset] = (byte) value;
                    System.arraycopy(content, offset, copy, offset + 1, content.length - offset);
                    yield copy;
                }
                default -> throw new IllegalStateException(kind);
            };
        }

        /** Returns the offsets of the first length octet of every DER element. */
        static List<Integer> lengthOffsets(byte[] der) {
            List<Integer> offsets = new ArrayList<>();
            walk(der, 0, der.length, offsets, 0);
            return offsets.isEmpty() ? List.of(0) : offsets;
        }

        private static void walk(byte[] der, int start, int end, List<Integer> offsets, int depth) {
            int at = start;
            while (at + 1 < end && depth < 32) {
                int tag = der[at] & 0xff;
                int lengthAt = at + 1;
                int first = der[lengthAt] & 0xff;
                int length;
                int header;
                if (first < 0x80) {
                    length = first;
                    header = 1;
                } else {
                    int count = first & 0x7f;
                    if (count == 0 || count > 3 || lengthAt + count >= end) {
                        return;
                    }
                    length = 0;
                    for (int i = 1; i <= count; i++) {
                        length = (length << 8) | (der[lengthAt + i] & 0xff);
                    }
                    header = 1 + count;
                }
                int contentStart = lengthAt + header;
                if (contentStart + length > end) {
                    return;
                }
                offsets.add(lengthAt);
                if ((tag & 0x20) != 0) {
                    walk(der, contentStart, contentStart + length, offsets, depth + 1);
                } else if (tag == 0x04 && length > 1 && (der[contentStart] & 0xff) == 0x30) {
                    // An OCTET STRING that holds DER, such as eContent or responseBytes.
                    walk(der, contentStart, contentStart + length, offsets, depth + 1);
                }
                at = contentStart + length;
            }
        }
    }
}
