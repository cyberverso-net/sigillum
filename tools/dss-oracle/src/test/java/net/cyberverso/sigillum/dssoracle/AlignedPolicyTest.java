package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Tests of the aligned validation policy of ADR-0023. */
class AlignedPolicyTest {

    private static final String OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5";

    /** Every certificate constraint of the policy, with whether it is a signing certificate. */
    private record Constraint(CertificateConstraints constraints, boolean signing) {
    }

    private static List<Constraint> certificateConstraints(ConstraintsParameters policy) {
        List<BasicSignatureConstraints> blocks = new ArrayList<>();
        if (policy.getSignatureConstraints() != null) {
            blocks.add(policy.getSignatureConstraints().getBasicSignatureConstraints());
        }
        if (policy.getCounterSignatureConstraints() != null) {
            blocks.add(policy.getCounterSignatureConstraints().getBasicSignatureConstraints());
        }
        if (policy.getKeyBindingSignatureConstraints() != null) {
            blocks.add(policy.getKeyBindingSignatureConstraints().getBasicSignatureConstraints());
        }
        if (policy.getAttestationRevocation() != null) {
            blocks.add(policy.getAttestationRevocation().getBasicSignatureConstraints());
        }
        if (policy.getTimestamp() != null) {
            blocks.add(policy.getTimestamp().getBasicSignatureConstraints());
        }
        if (policy.getRevocation() != null) {
            blocks.add(policy.getRevocation().getBasicSignatureConstraints());
        }
        List<Constraint> all = new ArrayList<>();
        for (BasicSignatureConstraints block : blocks) {
            if (block != null && block.getSigningCertificate() != null) {
                all.add(new Constraint(block.getSigningCertificate(), true));
            }
            if (block != null && block.getCACertificate() != null) {
                all.add(new Constraint(block.getCACertificate(), false));
            }
        }
        return all;
    }

    private static Algo find(List<Algo> algos, String name) {
        return algos.stream().filter(algo -> name.equals(algo.getValue())).findFirst().orElse(null);
    }

    private static void assertAligned(ConstraintsParameters base, ConstraintsParameters aligned) {
        assertTrue(aligned.getName().startsWith("sigillum aligned policy 1"), aligned.getName());
        assertTrue(aligned.getName().contains(base.getName()), aligned.getName());

        // Delta 1: Ed25519.
        CryptographicConstraint crypto = aligned.getCryptographic();
        assertNotNull(find(crypto.getAcceptableEncryptionAlgo().getAlgos(), "EdDSA"));
        assertEquals(32, find(crypto.getMiniPublicKeySize().getAlgos(), "EdDSA").getSize());
        Algo expiry = find(crypto.getAlgoExpirationDate().getAlgos(), "EdDSA");
        assertNotNull(expiry);
        assertNull(expiry.getDate());
        assertNull(find(base.getCryptographic().getAcceptableEncryptionAlgo().getAlgos(), "EdDSA"));

        List<Constraint> constraints = certificateConstraints(aligned);
        assertEquals(certificateConstraints(base).size(), constraints.size());
        assertTrue(constraints.size() >= 4, String.valueOf(constraints.size()));
        int skips = 0;
        for (Constraint constraint : constraints) {
            CertificateConstraints c = constraint.constraints();
            // Delta 2: revocation freshness from thisUpdate and nextUpdate.
            assertNull(c.getRevocationFreshness());
            assertEquals(Level.FAIL, c.getRevocationFreshnessNextUpdate().getLevel());
            // Delta 3: unknown critical extensions fail.
            if (c.getSupportedCriticalExtensions() != null) {
                assertEquals(Level.FAIL, c.getSupportedCriticalExtensions().getLevel());
            }
            // Delta 4: id-pkix-ocsp-nocheck skips revocation checking of a signing certificate.
            if (constraint.signing()) {
                assertTrue(c.getRevocationDataSkip().getCertificateExtensions().getId().contains(OCSP_NO_CHECK));
                assertEquals(1, c.getRevocationDataSkip().getCertificateExtensions().getId().stream()
                        .filter(OCSP_NO_CHECK::equals).count());
                skips++;
            }
        }
        assertTrue(skips >= 2, String.valueOf(skips));
    }

    @Test
    void theCertificatePolicyIsTheDefaultOfDssWithTheFourDeltas() throws Exception {
        ConstraintsParameters base = AlignedPolicy.base(AlignedPolicy.CERTIFICATE_BASE);
        ConstraintsParameters aligned = AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.CERTIFICATE_BASE));
        assertAligned(base, aligned);
        assertEquals("Certificate policy TL based", base.getName());
        // The delta leaves the other constraints alone.
        assertEquals(base.getModel().getValue(), aligned.getModel().getValue());
        assertEquals(base.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate()
                .getNotRevoked().getLevel(), aligned.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().getNotRevoked().getLevel());
        assertEquals(Level.WARN, aligned.getSignatureConstraints().getBasicSignatureConstraints()
                .getSigningCertificate().getCRLNextUpdatePresent().getLevel());
    }

    @Test
    void theDocumentPolicyIsTheDefaultOfDssWithTheFourDeltas() throws Exception {
        ConstraintsParameters base = AlignedPolicy.base(AlignedPolicy.DOCUMENT_BASE);
        ConstraintsParameters aligned = AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.DOCUMENT_BASE));
        assertAligned(base, aligned);
        // The timestamp constraints of the default policy have no RevocationDataSkip; the delta adds one.
        assertNull(base.getTimestamp().getBasicSignatureConstraints().getSigningCertificate().getRevocationDataSkip());
        assertEquals(Level.INFORM, aligned.getTimestamp().getBasicSignatureConstraints().getSigningCertificate()
                .getRevocationDataSkip().getLevel());
    }

    @Test
    void theAlignedPoliciesAreValidAgainstTheSchemaOfDss() throws Exception {
        for (String base : List.of(AlignedPolicy.CERTIFICATE_BASE, AlignedPolicy.DOCUMENT_BASE)) {
            ConstraintsParameters aligned = AlignedPolicy.apply(AlignedPolicy.base(base));
            String xml = ValidationPolicyFacade.newFacade().marshall(aligned, true);
            assertFalse(xml.isEmpty());
            assertEquals(aligned.getName(), ValidationPolicyFacade.newFacade().unmarshall(xml, true).getName());
        }
    }

    @Test
    void theDeltasAreIdempotent() throws Exception {
        ConstraintsParameters once = AlignedPolicy.apply(AlignedPolicy.base(AlignedPolicy.CERTIFICATE_BASE));
        String first = ValidationPolicyFacade.newFacade().marshall(once);
        String second = ValidationPolicyFacade.newFacade().marshall(AlignedPolicy.apply(once));
        assertEquals(first, second);
    }

    @Test
    void aMissingBaseIsAFailure() {
        assertThrows(IllegalStateException.class, () -> AlignedPolicy.base("/policy/absent.xml"));
    }

    @Test
    void thePoliciesHaveTheirNamesAndIdentifiers() {
        assertEquals("aligned", OraclePolicy.ALIGNED.commandName());
        assertEquals("aligned-1", OraclePolicy.ALIGNED.identifier());
        assertEquals("default", OraclePolicy.DEFAULT.commandName());
        assertEquals("default", OraclePolicy.DEFAULT.identifier());
        assertEquals(java.util.Optional.of(OraclePolicy.ALIGNED), OraclePolicy.fromCommandName("aligned"));
        assertEquals(java.util.Optional.of(OraclePolicy.DEFAULT), OraclePolicy.fromCommandName("default"));
        assertEquals(java.util.Optional.empty(), OraclePolicy.fromCommandName("Aligned"));
    }
}
