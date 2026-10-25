package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * The identity of the oracle: the version of the tool, of DSS and of the
 * PDF backend of DSS, which together decide its results.
 */
final class Versions {

    /** The DSS module that reads PDF documents for PAdES. */
    static final String PDF_BACKEND = "dss-pades-pdfbox";

    private static final Properties PROPERTIES = load();

    private Versions() {
    }

    /** Returns the version of the tool. */
    static String tool() {
        return PROPERTIES.getProperty("tool.version");
    }

    /** Returns the version of DSS that the tool is built against. */
    static String dss() {
        return PROPERTIES.getProperty("dss.version");
    }

    /** Returns the version of Apache PDFBox, which the PDF backend of DSS uses, as PDFBox reports it. */
    static String pdfBackend() {
        return org.apache.pdfbox.util.Version.getVersion();
    }

    /**
     * Returns the identity as the member {@code oracle} of {@code summary.json}.
     *
     * @return the tool, DSS and PDF backend versions
     */
    static Map<String, Object> oracle() {
        Map<String, Object> oracle = new LinkedHashMap<>();
        oracle.put("tool-version", tool());
        oracle.put("dss-version", dss());
        oracle.put("pdf-backend", PDF_BACKEND);
        oracle.put("pdf-backend-version", pdfBackend());
        return oracle;
    }

    private static Properties load() {
        Properties properties = new Properties();
        try (InputStream in = Versions.class.getResourceAsStream("/dss-oracle.properties")) {
            if (in != null) {
                properties.load(in);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return properties;
    }
}
