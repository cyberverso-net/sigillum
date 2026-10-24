package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Blocks network access while a run is in progress. It replaces the JVM's
 * default proxy selector, which {@code java.net.URLConnection}, plain sockets
 * and {@code java.net.http.HttpClient} consult before connecting unless a
 * proxy is given explicitly, and it makes {@link OfflineResolverProvider}
 * refuse every name lookup. Every attempt is recorded, so that a run fails
 * even when the code that made the attempt ignores the error. NIO socket
 * channels, UDP datagram sockets, the JNDI DNS provider and connections
 * opened with an explicit {@code Proxy.NO_PROXY} are not seen. Only one
 * guard may be installed at a time.
 */
public final class OfflineGuard implements AutoCloseable {

    private static volatile OfflineGuard current;

    private final ProxySelector previous;
    private final List<URI> attempts = Collections.synchronizedList(new ArrayList<>());

    private OfflineGuard(ProxySelector previous) {
        this.previous = previous;
    }

    /**
     * Installs the guard as the default proxy selector.
     *
     * @return the installed guard, to be closed when the run ends
     * @throws IllegalStateException if a guard is already installed
     */
    public static synchronized OfflineGuard install() {
        if (current != null) {
            throw new IllegalStateException("A network guard is already installed");
        }
        OfflineGuard guard = new OfflineGuard(ProxySelector.getDefault());
        ProxySelector.setDefault(guard.new Selector());
        current = guard;
        return guard;
    }

    /**
     * Returns the guard of the run in progress.
     *
     * @return the installed guard, or {@code null} outside a run
     */
    static OfflineGuard current() {
        return current;
    }

    /**
     * Records a blocked name lookup.
     *
     * @param host the name or address that was looked up
     */
    void recordLookup(String host) {
        URI uri;
        try {
            uri = new URI("dns", "//" + host, null);
        } catch (URISyntaxException e) {
            uri = URI.create("dns:unrepresentable");
        }
        attempts.add(uri);
    }

    /**
     * Reports whether network access was attempted.
     *
     * @return {@code true} if any connection was attempted
     */
    public boolean attempted() {
        return !attempts.isEmpty();
    }

    /**
     * Returns the addresses whose access was attempted, in order.
     *
     * @return the attempted addresses
     */
    public List<URI> attempts() {
        synchronized (attempts) {
            return List.copyOf(attempts);
        }
    }

    /** Restores the proxy selector that was in place before the guard. */
    @Override
    public void close() {
        synchronized (OfflineGuard.class) {
            if (current == this) {
                ProxySelector.setDefault(previous);
                current = null;
            }
        }
    }

    private final class Selector extends ProxySelector {
        @Override
        public List<Proxy> select(URI uri) {
            attempts.add(uri);
            throw new IllegalStateException("Network access is not allowed: " + uri);
        }

        @Override
        public void connectFailed(URI uri, SocketAddress address, IOException e) {
            attempts.add(uri);
        }
    }
}
