package net.cyberverso.sigillum.dssoracle;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.stream.Stream;

/**
 * Name resolution for the JVM that blocks and records every lookup while an
 * {@link OfflineGuard} is installed, and otherwise uses the built-in resolver.
 * It is registered in {@code META-INF/services} and loaded by the JVM at the
 * first lookup.
 */
public final class OfflineResolverProvider extends InetAddressResolverProvider {

    /** Creates the provider; called by the service loader. */
    public OfflineResolverProvider() {
    }

    /**
     * Reports whether lookups are currently blocked.
     *
     * @return {@code true} while an {@link OfflineGuard} is installed
     */
    public static boolean blocking() {
        return OfflineGuard.current() != null;
    }

    @Override
    public InetAddressResolver get(Configuration configuration) {
        InetAddressResolver builtin = configuration.builtinResolver();
        return new InetAddressResolver() {
            @Override
            public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy)
                    throws UnknownHostException {
                OfflineGuard guard = OfflineGuard.current();
                if (guard != null) {
                    guard.recordLookup(host);
                    throw new UnknownHostException("Name lookup is not allowed: " + host);
                }
                return builtin.lookupByName(host, lookupPolicy);
            }

            @Override
            public String lookupByAddress(byte[] address) throws UnknownHostException {
                OfflineGuard guard = OfflineGuard.current();
                if (guard != null) {
                    String literal = InetAddress.getByAddress(address).getHostAddress();
                    guard.recordLookup(literal);
                    throw new UnknownHostException("Reverse lookup is not allowed: " + literal);
                }
                return builtin.lookupByAddress(address);
            }
        };
    }

    @Override
    public String name() {
        return "sigillum dss-oracle offline resolver";
    }
}
