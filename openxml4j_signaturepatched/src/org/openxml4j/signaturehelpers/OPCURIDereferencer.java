package org.openxml4j.signaturehelpers;

import java.io.InputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;

import org.dom4j.Document;
import org.dom4j.io.DOMWriter;
import org.dom4j.io.SAXReader;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagingURIHelper;

/*
 * implementation of URIDereferencer for OPC
 */
public class OPCURIDereferencer implements URIDereferencer {

	Package p;
	URIDereferencer defaultURIDereferencer;

	public OPCURIDereferencer(Package pPackage,
			URIDereferencer pDefaultURIDereferencer) {
		p = pPackage;
		defaultURIDereferencer = pDefaultURIDereferencer;
	}

	@Override
	public Data dereference(URIReference arg0, XMLCryptoContext arg1)
			throws URIReferenceException {

		System.out.println("trying dereferencing + " + arg0.getURI());
		// if the URI to be dereferenced does not start with '/' character then
		// it is not the package part [M1.4]
		if (!arg0.getURI().startsWith("/")) {
			return defaultURIDereferencer.dereference(arg0, arg1);
		}

		// remove ?ContenType=type_def from URI
		String partName = arg0.getURI().toString().split("\\?")[0];

		// open part for reading
		SAXReader docReader = new SAXReader();
		PackagePart part;
		try {

			part = p.getPart(PackagingURIHelper.createPartName(partName));
			InputStream is = part.getInputStream();

			if (part.isRelationshipPart()) {
				// if it is relationship part we are dereferencing then it
				// should be dereferenced as nodeset
				Document doc4jRet = docReader.read(is);

				// construct return data from doc4j document
				org.dom4j.io.DOMWriter dw = new DOMWriter();
				final org.w3c.dom.Document docRes = dw.write(doc4jRet);

				OX4JNodeSetData opcNodeSet = new OX4JNodeSetData(docRes);
				return opcNodeSet;

			} else {
				// if it is package part we are dereferencing then it should be
				// dereferenced as octetstream
				return new OctetStreamData(is);

			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			throw new URIReferenceException(e);
		}
	}

}
