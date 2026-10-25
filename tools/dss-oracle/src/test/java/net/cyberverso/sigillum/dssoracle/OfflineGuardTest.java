package net.cyberverso.sigillum.dssoracle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.ProxySelector;
import java.net.UnknownHostException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.spi.InetAddressResolver;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class OfflineGuardTest {

    @Test
    void blocksUrlConnections() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertFalse(guard.attempted());
            assertThrows(Exception.class,
                    () -> URI.create("https://example.invalid/crl").toURL().openConnection().connect());
            assertTrue(guard.attempted());
            assertEquals(List.of(URI.create("https://example.invalid/crl")), guard.attempts());
        }
    }

    @Test
    void blocksTheJavaHttpClient() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://example.invalid/ocsp")).build();
            assertThrows(Exception.class,
                    () -> HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.discarding()));
            assertTrue(guard.attempted());
        }
    }

    @Test
    void restoresThePreviousSelectorWhenClosed() {
        ProxySelector before = ProxySelector.getDefault();
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertFalse(before == ProxySelector.getDefault());
            assertFalse(guard.attempted());
        }
        assertTrue(before == ProxySelector.getDefault());
    }

    @Test
    void blocksNameLookups() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertThrows(UnknownHostException.class, () -> InetAddress.getByName("crl.example.invalid"));
            assertTrue(guard.attempted());
            assertEquals(List.of(URI.create("dns://crl.example.invalid")), guard.attempts());
        }
    }

    @Test
    void blocksReverseLookups() throws UnknownHostException {
        InetAddress address = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 1});
        try (OfflineGuard guard = OfflineGuard.install()) {
            String name = address.getCanonicalHostName();
            assertEquals("192.0.2.1", name);
            assertTrue(guard.attempted());
        }
    }

    /**
     * InetAddress.getLocalHost() resolves the local host name through the
     * installed resolver, except when the name is "localhost" or a result is
     * still cached. The resolver is called here directly, so that neither
     * case can hide its behaviour: during a run it refuses and records the
     * name, whatever it is, and never falls back to the built-in resolver.
     * Any name stands for the local host name, since the resolver cannot
     * tell names apart. Reverse lookups are refused and recorded too.
     */
    @Test
    void theResolverRefusesAndRecordsEveryLookupIncludingTheLocalHost() {
        InetAddressResolver builtin = new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) {
                throw new AssertionError("the built-in resolver was called for " + host);
            }

            @Override
            public String lookupByAddress(byte[] address) {
                throw new AssertionError("the built-in resolver was called");
            }
        };
        InetAddressResolver resolver = OfflineResolverProvider.resolver(builtin);
        InetAddressResolver.LookupPolicy policy = InetAddressResolver.LookupPolicy.of(
                InetAddressResolver.LookupPolicy.IPV4 | InetAddressResolver.LookupPolicy.IPV6);
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertThrows(UnknownHostException.class, () -> resolver.lookupByName("host.example", policy));
            assertThrows(UnknownHostException.class, () -> resolver.lookupByName("localhost", policy));
            assertThrows(UnknownHostException.class,
                    () -> resolver.lookupByAddress(new byte[] {(byte) 192, 0, 2, 7}));
            assertEquals(List.of(URI.create("dns://host.example"), URI.create("dns://localhost"),
                    URI.create("dns://192.0.2.7")), guard.attempts());
        }
    }

    @Test
    void recordsLookupsOfNamesThatAreNotValidInAUri() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertThrows(UnknownHostException.class, () -> InetAddress.getByName("a b"));
            assertThrows(UnknownHostException.class, () -> InetAddress.getByName("x%zz"));
            assertEquals(2, guard.attempts().size());
        }
    }

    @Test
    void refusesASecondGuard() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertThrows(IllegalStateException.class, OfflineGuard::install);
            assertTrue(OfflineResolverProvider.blocking());
            assertFalse(guard.attempted());
        }
        assertFalse(OfflineResolverProvider.blocking());
    }

    @Test
    void closingTwiceKeepsTheRestoredSelector() {
        ProxySelector before = ProxySelector.getDefault();
        OfflineGuard guard = OfflineGuard.install();
        guard.close();
        try (OfflineGuard other = OfflineGuard.install()) {
            guard.close();
            assertTrue(OfflineResolverProvider.blocking());
            assertFalse(other.attempted());
        }
        assertEquals(before, ProxySelector.getDefault());
    }

    @Test
    void lookupsAreAllowedOutsideARun() {
        try (OfflineGuard guard = OfflineGuard.install()) {
            assertFalse(guard.attempted());
        }
        assertFalse(OfflineResolverProvider.blocking());
    }
}
