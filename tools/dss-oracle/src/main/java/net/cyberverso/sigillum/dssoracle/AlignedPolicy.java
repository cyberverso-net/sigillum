package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The aligned validation policy of ADR-0023. It is built at run time from
 * the default policy that DSS ships in {@code dss-policy-jaxb}, which is not
 * copied into the repository, and changes only four parameters that
 * ETSI EN 319 102-1 V1.4.1 leaves to the validation policy:
 *
 * <ol>
 * <li>EdDSA is an acceptable signature algorithm, with no expiry date;</li>
 * <li>revocation freshness is checked, with the interval from thisUpdate to
 *     nextUpdate as the maximum freshness (clause 5.2.5.4, step 1);</li>
 * <li>a critical extension that DSS does not support makes the certificate
 *     fail (RFC 5280, sections 6.1.4 (o) and 6.1.5 (f));</li>
 * <li>a signing certificate with id-pkix-ocsp-nocheck needs no revocation
 *     data (RFC 6960, section 4.2.2.2.1; clause 5.2.6.4, step 4,
 *     EXAMPLE 2).</li>
 * </ol>
 */
public final class AlignedPolicy {

    /** The version of the deltas; a change to them takes the next number. */
    public static final int VERSION = 1;
    /** The default certificate validation policy of DSS, in {@code dss-policy-jaxb}. */
    public static final String CERTIFICATE_BASE = "/policy/certificate-constraint.xml";
    /** The default validation policy of DSS for signatures and timestamps, in {@code dss-policy-jaxb}. */
    public static final String DOCUMENT_BASE = "/policy/constraint.xml";

    /** The name DSS gives EdDSA in a policy. */
    static final String EDDSA = "EdDSA";
    /**
     * The minimum key size of EdDSA. DSS 6.5.1 measures an EdDSA public key
     * in octets: 32 for Ed25519.
     */
    static final int EDDSA_KEY_SIZE = 32;
    /** id-pkix-ocsp-nocheck, RFC 6960, section 4.2.2.2.1. */
    static final String OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5";

    private AlignedPolicy() {
    }

    /**
     * Builds the aligned certificate validation policy.
     *
     * @return the policy for {@code validate-certificate}
     */
    public static ValidationPolicy forCertificates() {
        return new EtsiValidationPolicy(apply(base(CERTIFICATE_BASE)));
    }

    /**
     * Builds the aligned validation policy for signatures and timestamps.
     *
     * @return the policy for {@code validate-timestamp}
     */
    public static ValidationPolicy forDocuments() {
        return new EtsiValidationPolicy(apply(base(DOCUMENT_BASE)));
    }

    /**
     * Reads a default policy of DSS from the classpath, checked against the
     * policy schema of DSS.
     *
     * @param resource the path of the policy in {@code dss-policy-jaxb}
     * @return the policy, unchanged
     * @throws IllegalStateException if it cannot be read
     */
    public static ConstraintsParameters base(String resource) {
        try (InputStream in = ValidationPolicyFacade.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("DSS ships no policy " + resource);
            }
            return ValidationPolicyFacade.newFacade().unmarshall(in, true);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read the policy " + resource + " of DSS", e);
        }
    }

    /**
     * Applies the deltas of ADR-0023 to a policy, in place. Applying them
     * again changes nothing.
     *
     * @param policy a default policy of DSS
     * @return the same policy, aligned
     */
    public static ConstraintsParameters apply(ConstraintsParameters policy) {
        String prefix = "sigillum aligned policy " + VERSION + ", from ";
        if (policy.getName() == null || !policy.getName().startsWith(prefix)) {
            policy.setName(prefix + policy.getName());
        }
        acceptEdDsa(policy.getCryptographic());
        for (BasicSignatureConstraints block : blocks(policy)) {
            if (block.getSigningCertificate() != null) {
                align(block.getSigningCertificate());
                skipRevocationForOcspNoCheck(block.getSigningCertificate());
            }
            if (block.getCACertificate() != null) {
                align(block.getCACertificate());
            }
        }
        return policy;
    }

    /** Every block of basic signature constraints that the policy has. */
    private static List<BasicSignatureConstraints> blocks(ConstraintsParameters policy) {
        List<BasicSignatureConstraints> blocks = new ArrayList<>();
        for (SignatureConstraints signature : Arrays.asList(policy.getSignatureConstraints(),
                policy.getCounterSignatureConstraints(), policy.getKeyBindingSignatureConstraints())) {
            add(blocks, signature == null ? null : signature.getBasicSignatureConstraints());
        }
        add(blocks, policy.getTimestamp() == null ? null : policy.getTimestamp().getBasicSignatureConstraints());
        add(blocks, policy.getRevocation() == null ? null : policy.getRevocation().getBasicSignatureConstraints());
        add(blocks, policy.getAttestationRevocation() == null
                ? null : policy.getAttestationRevocation().getBasicSignatureConstraints());
        return blocks;
    }

    private static void add(List<BasicSignatureConstraints> blocks, BasicSignatureConstraints block) {
        if (block != null) {
            blocks.add(block);
        }
    }

    /** Delta 1: EdDSA is acceptable, with a minimum key size and no expiry date. */
    private static void acceptEdDsa(CryptographicConstraint cryptographic) {
        if (cryptographic == null) {
            return;
        }
        addAlgo(cryptographic.getAcceptableEncryptionAlgo(), null);
        addAlgo(cryptographic.getMiniPublicKeySize(), EDDSA_KEY_SIZE);
        addAlgo(cryptographic.getAlgoExpirationDate(), EDDSA_KEY_SIZE);
    }

    private static void addAlgo(ListAlgo list, Integer size) {
        if (list == null || list.getAlgos().stream().anyMatch(algo -> EDDSA.equals(algo.getValue()))) {
            return;
        }
        Algo algo = new Algo();
        algo.setValue(EDDSA);
        algo.setSize(size);
        list.getAlgos().add(algo);
    }

    /** Deltas 2 and 3, for any certificate. */
    private static void align(CertificateConstraints constraints) {
        // Without RevocationFreshness, DSS takes nextUpdate minus thisUpdate as the maximum freshness, and
        // RevocationFreshnessNextUpdate sets the level of that check.
        constraints.setRevocationFreshness(null);
        constraints.setRevocationFreshnessNextUpdate(level(Level.FAIL));
        if (constraints.getSupportedCriticalExtensions() != null) {
            constraints.getSupportedCriticalExtensions().setLevel(Level.FAIL);
        }
    }

    /** Delta 4, for a signing certificate. */
    private static void skipRevocationForOcspNoCheck(CertificateConstraints constraints) {
        CertificateValuesConstraint skip = constraints.getRevocationDataSkip();
        if (skip == null) {
            skip = new CertificateValuesConstraint();
            skip.setLevel(Level.INFORM);
            constraints.setRevocationDataSkip(skip);
        }
        if (skip.getCertificateExtensions() == null) {
            skip.setCertificateExtensions(new MultiValuesConstraint());
        }
        List<String> extensions = skip.getCertificateExtensions().getId();
        if (!extensions.contains(OCSP_NO_CHECK)) {
            extensions.add(OCSP_NO_CHECK);
        }
    }

    private static LevelConstraint level(Level level) {
        LevelConstraint constraint = new LevelConstraint();
        constraint.setLevel(level);
        return constraint;
    }
}
