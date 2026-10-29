package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Tests of the pairs of a certificate and its issuer for which the tool makes revocation tokens. */
class OfflineSourcesTest {

    private static final Path PKI = Path.of("..", "..", "testdata", "pki");

    private static CertificateToken load(String name) throws Exception {
        return DSSUtils.loadCertificate(Files.readAllBytes(PKI.resolve(name + ".pem")));
    }

    /** Copies of a certificate count once, as DSS keeps one certificate token for them (issue #72, case 5). */
    @Test
    void copiesOfACertificateGiveOnePairPerIssuer() throws Exception {
        CertificateToken tsa = load("tsa");
        CertificateToken ca = load("ca-ecdsa");
        CertificateToken root = load("root-ca");
        List<CertificateToken> certificates = new ArrayList<>(List.of(root, ca));
        for (int i = 0; i < 10_000; i++) {
            certificates.add(load("tsa"));
        }
        certificates.add(ca);
        Map<CertificateToken, List<CertificateToken>> issuers = OfflineSources.issuers(certificates);
        assertEquals(List.of(root, ca, tsa), List.copyOf(issuers.keySet()));
        assertEquals(List.of(ca), issuers.get(tsa));
        assertEquals(List.of(root), issuers.get(ca));
        assertEquals(List.of(root), issuers.get(root));
    }

    /** Issuers of one name count once per distinct key (issue #72). */
    @Test
    void issuersOfOneNameCountOncePerKey() throws Exception {
        CertificateToken tsa = load("tsa");
        CertificateToken ca = load("ca-ecdsa");
        CertificateToken sameKey = DSSUtils.loadCertificate(Tokens.caEcdsaWithMalformedAuthorityKeyIdentifier());
        CertificateToken otherKey = DSSUtils.loadCertificate(Tokens.otherKeyWithTheSubjectOfCaEcdsa());
        assertEquals(List.of(ca), OfflineSources.issuers(List.of(tsa, ca, sameKey)).get(tsa));
        assertEquals(List.of(ca, otherKey), OfflineSources.issuers(List.of(tsa, ca, otherKey)).get(tsa));
    }
}
