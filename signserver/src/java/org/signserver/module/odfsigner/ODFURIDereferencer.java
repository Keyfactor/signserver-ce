/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.signserver.module.odfsigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;

import org.odftoolkit.odfdom.doc.OdfDocument;

/**
 * Implementation of URI Dereferencer for ODF
 * 
 * @author Aziz Göktepe
 * $Id$
 */
public class ODFURIDereferencer implements URIDereferencer {

	OdfDocument odfDoc;
	URIDereferencer defaultURIDereferencer;

	public ODFURIDereferencer(OdfDocument pOdfDocument,
			URIDereferencer pDefaultURIDereferencer) {
		odfDoc = pOdfDocument;
		defaultURIDereferencer = pDefaultURIDereferencer;
	}

	@Override
	public Data dereference(URIReference arg0, XMLCryptoContext arg1)
			throws URIReferenceException {

		String partPath = arg0.getURI().toString();

		// see if our document contains this part, if not dereference using
		// default dereferencer
		if (!odfDoc.getPackage().contains(partPath)) {
			return defaultURIDereferencer.dereference(arg0, arg1);
		}

		try {
			// return part content as octet stream data
			InputStream is = odfDoc.getPackage().getInputStream(partPath);
			int count = 0;
			byte[] buff = new byte[1024];
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			while ((count = is.read(buff, 0, buff.length)) > 0) {
				bos.write(buff, 0, count);
			}

			ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());

			OctetStreamData retData = new OctetStreamData(bis);

			return retData;

		} catch (Exception e) {
			throw new URIReferenceException(e);
		}
	}
}
