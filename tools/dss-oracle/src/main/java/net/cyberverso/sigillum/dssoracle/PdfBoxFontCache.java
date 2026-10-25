package net.cyberverso.sigillum.dssoracle;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Keeps the font cache of Apache PDFBox out of the home directory. When DSS
 * renders a page that uses a font the PDF does not embed, PDFBox looks for
 * a substitute among the fonts of the host, and writes the list of those
 * fonts to {@code .pdfbox.cache} in the directory that the system property
 * {@code pdfbox.fontcache} names, by default the home directory. The tool
 * points it to a temporary directory, removed when the JVM exits.
 */
final class PdfBoxFontCache {

    /** The system property that PDFBox 3 reads. */
    static final String PROPERTY = "pdfbox.fontcache";

    private PdfBoxFontCache() {
    }

    /**
     * Points the font cache of PDFBox to a new temporary directory, unless
     * the property is already set, as by an earlier run in the same JVM.
     *
     * @throws IOException if the directory cannot be created
     */
    static synchronized void configure() throws IOException {
        if (System.getProperty(PROPERTY) != null) {
            return;
        }
        Path directory = Files.createTempDirectory("dss-oracle-pdfbox-");
        // Removed in the reverse order of registration: the cache file first, then the directory.
        directory.toFile().deleteOnExit();
        directory.resolve(".pdfbox.cache").toFile().deleteOnExit();
        System.setProperty(PROPERTY, directory.toString());
    }
}
