package net.cyberverso.sigillum.dssoracle;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * The content of an XML document with its namespace prefixes resolved: each
 * element and attribute is named by its namespace and local name, namespace
 * declarations are left out, and text is kept as it is. Two documents that
 * differ only in their choice of prefixes have equal content. Exclusive XML
 * canonicalisation would not do: it keeps the prefixes of the document.
 */
final class XmlContent {

    private XmlContent() {
    }

    static List<String> of(Path file) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setNamespaceAware(true);
        List<String> content = new ArrayList<>();
        walk(factory.newDocumentBuilder().parse(file.toFile()).getDocumentElement(), content);
        return content;
    }

    private static void walk(Element element, List<String> content) {
        TreeMap<String, String> attributes = new TreeMap<>();
        NamedNodeMap map = element.getAttributes();
        for (int i = 0; i < map.getLength(); i++) {
            Attr attribute = (Attr) map.item(i);
            if (!XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())) {
                attributes.put("{" + attribute.getNamespaceURI() + "}" + attribute.getLocalName(),
                        attribute.getValue());
            }
        }
        content.add("<{" + element.getNamespaceURI() + "}" + element.getLocalName() + " " + attributes);
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element nested) {
                walk(nested, content);
            } else if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                content.add("text " + child.getNodeValue());
            }
        }
        content.add(">");
    }
}
