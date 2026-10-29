package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Tests of the bound on the work of the issuer closure (issue #72). */
class IssuerClosureTest {

    private static final int COUNT = 2000;

    private static List<CertificateToken> selfIssued() throws Exception {
        List<CertificateToken> certificates = new ArrayList<>();
        for (byte[] der : Tokens.selfIssuedWithTheNameAndKeyOfCaEcdsa(COUNT)) {
            certificates.add(DSSUtils.loadCertificate(der));
        }
        return certificates;
    }

    private static CertificateToken tsa() throws Exception {
        return DSSUtils.loadCertificate(Files.readAllBytes(Path.of("..", "..", "testdata", "pki", "tsa.pem")));
    }

    @Test
    void candidatesThatAllIssueTheFirstCertificateAreTriedOnce() throws Exception {
        List<CertificateToken> pool = selfIssued();
        AtomicInteger calls = new AtomicInteger();
        Set<CertificateToken> closure = IssuerClosure.of(List.of(tsa()), pool, (certificate, issuer) -> {
            calls.incrementAndGet();
            return true;
        }, certificate -> false);
        assertEquals(COUNT + 1, closure.size());
        assertEquals(COUNT, calls.get());
    }

    @Test
    void candidatesThatIssueNothingAreTriedForTheCertificatesReachedOnly() throws Exception {
        List<CertificateToken> pool = selfIssued();
        AtomicInteger calls = new AtomicInteger();
        Set<CertificateToken> closure = IssuerClosure.of(List.of(tsa()), pool, (certificate, issuer) -> {
            calls.incrementAndGet();
            return false;
        }, certificate -> false);
        assertEquals(1, closure.size());
        assertEquals(COUNT, calls.get());
    }

    @Test
    void theChainEndsWhereAsked() throws Exception {
        CertificateToken tsa = tsa();
        AtomicInteger calls = new AtomicInteger();
        Set<CertificateToken> closure = IssuerClosure.of(List.of(tsa), selfIssued(), (certificate, issuer) -> {
            calls.incrementAndGet();
            return true;
        }, tsa::equals);
        assertEquals(Set.of(tsa), closure);
        assertEquals(0, calls.get());
    }
}
