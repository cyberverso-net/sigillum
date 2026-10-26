package net.cyberverso.sigillum.dssoracle;

import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
import java.io.OutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * The PDFBox implementation of DSS, with a fixed seed for the file
 * identifier of every incremental update that DSS does not seed itself.
 *
 * <p>PDFBox derives the second file identifier of an incremental update
 * (ISO 32000-1:2008, clause 14.4) from a document identifier, or from the
 * clock when none is set. DSS sets one for the revision of the signature,
 * derived from the signature parameters, but not for the revision that adds
 * the document security store at B-LT. This factory sets the given seed
 * there, so that the signed corpus is reproduced byte for byte.
 */
final class FixedIdPdfObjFactory extends PdfBoxNativeObjectFactory {

    private final long documentId;

    /**
     * Creates the factory.
     *
     * @param documentId the document identifier that seeds the file identifier of a revision
     *        that DSS does not seed
     */
    FixedIdPdfObjFactory(long documentId) {
        this.documentId = documentId;
    }

    @Override
    public PDFSignatureService newPAdESSignatureService() {
        return configure(new Service(PDFServiceMode.SIGNATURE, getSignatureDrawerFactory(), documentId));
    }

    @Override
    public PDFSignatureService newSignatureTimestampService() {
        return configure(new Service(PDFServiceMode.SIGNATURE_TIMESTAMP, getSignatureDrawerFactory(), documentId));
    }

    /** The PDFBox service of DSS, which seeds the file identifier when DSS has not. */
    private static final class Service extends PdfBoxSignatureService {
        private final long documentId;

        Service(PDFServiceMode mode, PdfBoxSignatureDrawerFactory drawers, long documentId) {
            super(mode, drawers);
            this.documentId = documentId;
        }

        @Override
        public void saveDocumentIncrementally(PDDocument pdDocument, OutputStream outputStream) {
            if (pdDocument.getDocumentId() == null) {
                pdDocument.setDocumentId(documentId);
            }
            super.saveDocumentIncrementally(pdDocument, outputStream);
        }
    }
}
