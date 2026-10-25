package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSPKUtils;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Decodes the parts of a certificate that DSS decodes during a validation and
 * the building of its reports, but not when it loads the certificate: the
 * public key, the extensions and the values of the subject name. The calls
 * are those of DSS, or of Bouncy Castle as DSS makes them, on the
 * certificate alone.
 */
final class CertificateChecks {

    private CertificateChecks() {
    }

    /**
     * Decodes a certificate as DSS later does.
     *
     * @param certificate the certificate, as DSS loaded it
     * @throws IllegalArgumentException if a part cannot be decoded, with the
     *         error of DSS or Bouncy Castle as its cause
     */
    static void decode(CertificateToken certificate) {
        PublicKey key = certificate.getPublicKey();
        if (key == null) {
            throw new IllegalArgumentException("the public key cannot be decoded");
        }
        try {
            DSSPKUtils.getPublicKeySize(key);
            CertificateExtensionsUtils.getCertificateExtensions(certificate);
            X500Principal subject = certificate.getSubject().getPrincipal();
            for (RDN rdn : X500Name.getInstance(subject.getEncoded()).getRDNs()) {
                for (AttributeTypeAndValue value : rdn.getTypesAndValues()) {
                    value.getValue().toString();
                }
            }
        } catch (DSSException | IllegalArgumentException | IllegalStateException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}
