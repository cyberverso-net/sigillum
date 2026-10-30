package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.model.x509.CertificateToken;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import javax.security.auth.x500.X500Principal;

/**
 * The certificates that DSS considers when it builds the chains of some
 * certificates: those certificates and, transitively, the certificates of a
 * pool whose subject is the issuer name of one of them and that are taken as
 * its issuer. Copies count once.
 *
 * <p>Each certificate of the pool is taken at most once: once taken, it is
 * no longer a candidate for any other certificate. The work is therefore at
 * most one call of {@code issues} per pair of a certificate reached and a
 * candidate of its issuer name not yet taken, and the memory is in
 * proportion to the pool. When every candidate of a name issues the first
 * certificate that reaches it, as copies and re-encodings of one issuer do,
 * the calls are as many as the candidates.
 */
final class IssuerClosure {

    private IssuerClosure() {
    }

    /**
     * Returns the closure.
     *
     * @param certificates the certificates whose chains are built
     * @param pool the candidates for their issuers
     * @param issues whether a candidate is taken as the issuer of a certificate
     * @return the certificates and the issuers taken, each once
     */
    static Set<CertificateToken> of(Collection<CertificateToken> certificates, Collection<CertificateToken> pool,
            BiPredicate<CertificateToken, CertificateToken> issues) {
        Set<CertificateToken> taken = new LinkedHashSet<>(certificates);
        Map<X500Principal, List<CertificateToken>> candidates = new HashMap<>();
        for (CertificateToken candidate : new LinkedHashSet<>(pool)) {
            if (!taken.contains(candidate)) {
                candidates.computeIfAbsent(candidate.getSubject().getPrincipal(), subject -> new ArrayList<>())
                        .add(candidate);
            }
        }
        Set<CertificateToken> result = new LinkedHashSet<>();
        Deque<CertificateToken> pending = new ArrayDeque<>(taken);
        while (!pending.isEmpty()) {
            CertificateToken certificate = pending.removeFirst();
            result.add(certificate);
            List<CertificateToken> named = candidates.get(certificate.getIssuer().getPrincipal());
            if (named == null) {
                continue;
            }
            boolean anyTaken = false;
            for (CertificateToken candidate : named) {
                if (issues.test(certificate, candidate) && taken.add(candidate)) {
                    pending.addLast(candidate);
                    anyTaken = true;
                }
            }
            if (anyTaken) {
                // In one pass over the list, so that taking many candidates of one name stays linear.
                named.removeIf(taken::contains);
            }
        }
        return result;
    }
}
