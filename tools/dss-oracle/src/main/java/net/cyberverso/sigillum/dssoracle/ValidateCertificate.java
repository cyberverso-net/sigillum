package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CertificateValidator;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The mode {@code validate-certificate}: validates a certificate with DSS at
 * a fixed time, with offline sources only. The first {@code --certificate}
 * is the certificate to validate; the others are supplied for its chain.
 * DSS runs the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1,
 * clause 5.2.6, with the policy that {@code --policy} selects
 * (ADR-0023).
 */
public final class ValidateCertificate implements Main.ModeRunner {

    /** Creates the mode. */
    public ValidateCertificate() {
    }

    /** The checked command line of this mode. */
    private record Options(Instant validationTime, Path out) {
    }

    @Override
    public int run(Arguments arguments, PrintStream out, PrintStream err) throws Exception {
        Options options = check(arguments);
        // Read every file first: a missing file is a failure of the tool, whatever else is wrong.
        PolicySelection policy = PolicySelection.of(arguments);
        ValidationOutput output = ValidationOutput.check(options.out(), Mode.VALIDATE_CERTIFICATE,
                options.validationTime(), policy);
        OfflineSources sources = OfflineSources.read(arguments);

        try {
            CertificateVerifier verifier = sources.certificateVerifier(List.of());
            CertificateToken certificate = sources.suppliedCertificate(0);

            CertificateValidator validator = CertificateValidator.fromCertificate(certificate);
            validator.setCertificateVerifier(verifier);
            validator.setValidationTime(Date.from(options.validationTime()));
            validator.setLocale(Locale.ENGLISH);
            // ADR-0023: the aligned policy, the default certificate policy of DSS, or a policy file.
            CertificateReports reports = policy.validate(PolicySelection.Kind.CERTIFICATE, validator::validate);

            String id = certificate.getDSSIdAsString();
            XmlBasicBuildingBlocks blocks = reports.getDetailedReport().getBasicBuildingBlockById(id);
            XmlConclusion conclusion = blocks == null || blocks.getXCV() == null
                    ? null : blocks.getXCV().getConclusion();
            if (conclusion == null || !reports.getSimpleReport().getCertificateIds().contains(id)) {
                throw new IllegalStateException("DSS reports no result for the certificate " + id);
            }
            // The result of the X.509 certificate validation of the whole chain (ETSI EN 319 102-1, clause 5.2.6)
            // is the conclusion of the XCV block of the certificate. The simple report gives the certificate the
            // conclusion of its own checks only, which details records apart.
            output.writeValidated(List.of(
                    new ValidationOutput.Report("diagnostic-data.xml", reports.getXmlDiagnosticData()),
                    new ValidationOutput.Report("detailed-report.xml", reports.getXmlDetailedReport()),
                    new ValidationOutput.Report("simple-report.xml", reports.getXmlSimpleReport())),
                    conclusion.getIndication(), conclusion.getSubIndication(),
                    details(reports, id, sources));
        } catch (RejectedInputException e) {
            output.writeRejected(e);
        }
        return ExitCodes.SUCCESS;
    }

    /**
     * Checks the options of the mode.
     *
     * @throws UsageException if an option is missing
     */
    private static Options check(Arguments arguments) throws UsageException {
        if (arguments.certificates().isEmpty()) {
            throw new UsageException("--certificate is required: the first one is the certificate to validate.");
        }
        if (arguments.trustAnchors().isEmpty()) {
            throw new UsageException("--trust-anchor is required.");
        }
        Instant validationTime = arguments.validationTime()
                .orElseThrow(() -> new UsageException("--validation-time is required."));
        Path out = arguments.out().orElseThrow(() -> new UsageException("--out is required."));
        return new Options(validationTime, out);
    }

    /** The details of summary.json for a certificate. */
    private static Map<String, Object> details(CertificateReports reports, String id, OfflineSources sources) {
        SimpleCertificateReport simple = reports.getSimpleReport();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("certificate-id", id);
        details.put("common-name", simple.getCertificateCommonName(id));
        Map<String, Object> own = new LinkedHashMap<>();
        own.put("indication", simple.getCertificateIndication(id) == null
                ? null : simple.getCertificateIndication(id).name());
        own.put("sub-indication", simple.getCertificateSubIndication(id) == null
                ? null : simple.getCertificateSubIndication(id).name());
        details.put("simple-report", own);
        details.put("revocation", revocation(reports, id, sources));
        details.put("errors", ValidationOutput.messages(simple.getX509ValidationErrors(id)));
        details.put("warnings", ValidationOutput.messages(simple.getX509ValidationWarnings(id)));
        return details;
    }

    /**
     * Describes the revocation data that DSS selected for the certificate:
     * the latest acceptable revocation data of its certificate revocation
     * data selector, in the detailed report. Returns {@code null} when DSS
     * selected none, for example for a trust anchor, or when no supplied
     * revocation data is acceptable.
     */
    private static Map<String, Object> revocation(CertificateReports reports, String id, OfflineSources sources) {
        XmlBasicBuildingBlocks blocks = reports.getDetailedReport().getBasicBuildingBlockById(id);
        if (blocks == null || blocks.getXCV() == null) {
            return null;
        }
        String selected = null;
        for (XmlSubXCV sub : blocks.getXCV().getSubXCV()) {
            XmlCRS selector = sub.getCRS();
            if (id.equals(sub.getId()) && selector != null) {
                selected = selector.getLatestAcceptableRevocationId();
            }
        }
        if (selected == null) {
            return null;
        }
        CertificateWrapper certificate = reports.getDiagnosticData().getCertificateById(id);
        CertificateRevocationWrapper data = certificate.getRevocationDataById(selected);
        OfflineSources.Input input = sources.revocationInputs().get(selected);
        if (data == null || input == null) {
            throw new IllegalStateException("DSS selected revocation data " + selected
                    + " that no supplied file holds");
        }
        Map<String, Object> revocation = new LinkedHashMap<>();
        revocation.put("status", data.getStatus() == null ? null : data.getStatus().name());
        revocation.put("revocation-time", data.getRevocationDate() == null
                ? null : ValidationOutput.format(data.getRevocationDate().toInstant()));
        revocation.put("reason", data.getReason() == null ? null : data.getReason().name());
        revocation.put("this-update", data.getThisUpdate() == null
                ? null : ValidationOutput.format(data.getThisUpdate().toInstant()));
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("type", data.getRevocationType() == null ? null : data.getRevocationType().name());
        source.put("input", input.option());
        source.put("file", input.file().toString());
        source.put("revocation-id", selected);
        revocation.put("source", source);
        return revocation;
    }
}
