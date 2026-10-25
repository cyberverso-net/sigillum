package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The mode {@code validate-document}: validates the signatures of a CAdES,
 * PAdES or JAdES document with DSS at a fixed time, with offline sources
 * only, and with the policy that {@code --policy} selects (ADR-0023): the
 * aligned policy by default, the default policy of DSS, or a policy file.
 * DSS runs the validation of ETSI EN 319 102-1 V1.4.1 as it implements it,
 * and reports it in the format of ETSI TS 119 102-2 V1.4.1 among its own
 * reports.
 */
public final class ValidateDocument implements Main.ModeRunner {

    /** Creates the mode. */
    public ValidateDocument() {
    }

    /** The checked command line of this mode. */
    private record Options(Path document, Instant validationTime, Path out) {
    }

    @Override
    public int run(Arguments arguments, PrintStream out, PrintStream err) throws Exception {
        Options options = check(arguments);
        PdfBoxFontCache.configure();
        PolicySelection policy = PolicySelection.of(arguments);
        ValidationOutput output = ValidationOutput.check(options.out(), Mode.VALIDATE_DOCUMENT,
                options.validationTime(), policy);

        // Read every file first: a missing file is a failure of the tool, whatever else is wrong.
        OfflineSources.Input document = OfflineSources.Input.read("--document", options.document());
        OfflineSources.Input detached = arguments.detached().isPresent()
                ? OfflineSources.Input.read("--detached", arguments.detached().get())
                : null;
        OfflineSources sources = OfflineSources.read(arguments);

        // The validation runs within limits of heap, stack and time; exceeding one is a recorded result.
        ResourceLimits.run(ResourceLimits.Limits.of(arguments), output, () -> {
            try {
                CertificateVerifier verifier = sources.certificateVerifier(List.of());
                SignedDocumentValidator validator = SignedDocuments.open(document);
                validator.setCertificateVerifier(verifier);
                // The supplied certificates are candidates for the signing certificate of a signature that does
                // not hold it, as DSS takes them when it is given a signing certificate source.
                CommonCertificateSource signing = new CommonCertificateSource();
                verifier.getTrustedCertSources().getCertificates().forEach(signing::addCertificate);
                verifier.getAdjunctCertSources().getCertificates().forEach(signing::addCertificate);
                validator.setSigningCertificateSource(signing);
                // A signature policy provider without a data loader, so that no policy document is retrieved. DSS 6.5.1
                // retrieves none for these formats without a provider either; this keeps it so if that changes.
                validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
                validator.setValidationTime(Date.from(options.validationTime()));
                validator.setLocale(Locale.ENGLISH);
                if (detached != null) {
                    validator.setDetachedContents(List.of(detached.document()));
                }
                List<CertificateToken> processed = SignedDocuments.check(document, validator, verifier, detached != null);
                // The supplied revocation data is checked again with the certificates of the document that DSS
                // processes, which it pairs with their issuers as it does with the supplied ones.
                sources.certificateVerifier(processed);

                // ADR-0023: the aligned policy, the default validation policy of DSS, or a policy file. DSS reads
                // parts of a policy file only during the validation, and only those that the document needs, so a
                // failure that the aligned policy does not reproduce belongs to the file (PolicySelection).
                Reports reports = policy.validate(PolicySelection.Kind.DOCUMENT, validator::validateDocument);

                SimpleReport simple = reports.getSimpleReport();
                // A top-level result only for a single signature: one signature must not stand for others.
                List<String> ids = simple.getSignatureIdList();
                String only = ids.size() == 1 ? ids.get(0) : null;
                output.writeValidated(List.of(
                        new ValidationOutput.Report("diagnostic-data.xml", reports.getXmlDiagnosticData()),
                        new ValidationOutput.Report("detailed-report.xml", reports.getXmlDetailedReport()),
                        new ValidationOutput.Report("simple-report.xml", reports.getXmlSimpleReport()),
                        new ValidationOutput.Report("etsi-validation-report.xml", reports.getXmlValidationReport())),
                        only == null ? null : simple.getIndication(only),
                        only == null ? null : simple.getSubIndication(only),
                        details(reports));
            } catch (RejectedInputException e) {
                output.writeRejected(e);
            } catch (RuntimeException e) {
                // The JSON schema validator of DSS refuses JSON nested too deep; in a JWS, only the document
                // holds JSON that DSS parses so, wherever the walk of JsonDepth does not reach.
                if (JsonDepth.isJws(document.content()) && JsonDepth.isDepthLimitOfDss(e)) {
                    output.writeRejected(document.rejected(e));
                } else {
                    throw e;
                }
            }
        });
        return ExitCodes.SUCCESS;
    }

    /**
     * Checks the options of the mode.
     *
     * @throws UsageException if an option is missing
     */
    private static Options check(Arguments arguments) throws UsageException {
        Path document = arguments.document().orElseThrow(() -> new UsageException("--document is required."));
        if (arguments.trustAnchors().isEmpty()) {
            throw new UsageException("--trust-anchor is required.");
        }
        Instant validationTime = arguments.validationTime()
                .orElseThrow(() -> new UsageException("--validation-time is required."));
        Path out = arguments.out().orElseThrow(() -> new UsageException("--out is required."));
        return new Options(document, validationTime, out);
    }

    /** The details of summary.json for a document. */
    private static Map<String, Object> details(Reports reports) {
        SimpleReport simple = reports.getSimpleReport();
        DiagnosticData diagnostic = reports.getDiagnosticData();
        Map<String, Object> details = new LinkedHashMap<>();
        List<Object> signatures = new ArrayList<>();
        for (String id : simple.getSignatureIdList()) {
            SignatureWrapper signature = diagnostic.getSignatureById(id);
            if (signature == null) {
                throw new IllegalStateException("DSS reports no diagnostic data for the signature " + id);
            }
            SignatureLevel level = signature.getSignatureFormat();
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("signature-id", id);
            entry.put("format", level == null || level.getSignatureForm() == null
                    ? null : level.getSignatureForm().name());
            entry.put("level", level == null ? null : level.toString());
            entry.put("indication", simple.getIndication(id) == null ? null : simple.getIndication(id).name());
            entry.put("sub-indication", simple.getSubIndication(id) == null
                    ? null : simple.getSubIndication(id).name());
            entry.put("signing-time", signature.getClaimedSigningTime() == null
                    ? null : ValidationOutput.format(signature.getClaimedSigningTime().toInstant()));
            entry.put("best-signature-time", simple.getBestSignatureTime(id) == null
                    ? null : ValidationOutput.format(simple.getBestSignatureTime(id).toInstant()));
            entry.put("errors", ValidationOutput.messages(simple.getAdESValidationErrors(id)));
            entry.put("warnings", ValidationOutput.messages(simple.getAdESValidationWarnings(id)));
            signatures.add(entry);
        }
        details.put("signatures", signatures);
        return details;
    }
}
