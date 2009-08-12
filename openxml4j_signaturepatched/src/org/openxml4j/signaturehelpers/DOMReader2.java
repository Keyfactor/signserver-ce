package org.openxml4j.signaturehelpers;

import org.dom4j.Document;
import org.dom4j.io.DOMReader;

/*
 * extension to DOMReader to handle reading from single node or nodelist
 */
public class DOMReader2 extends DOMReader {

	  public Document read(org.w3c.dom.NodeList domNodeList) {
	        Document document = createDocument();

	        clearNamespaceStack();

	        for (int i = 0, size = domNodeList.getLength(); i < size; i++) {
	            readTree(domNodeList.item(i), document);
	        }

	        return document;
	    }
	  
	  public Document read(org.w3c.dom.Node domNode) {
	        Document document = createDocument();

	        clearNamespaceStack();
	        readTree(domNode,document);

	        return document;
	    }
}
