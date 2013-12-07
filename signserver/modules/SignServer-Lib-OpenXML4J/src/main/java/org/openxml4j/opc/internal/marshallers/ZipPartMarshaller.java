/* ====================================================================
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
==================================================================== 

 * Copyright (c) 2006, Wygwam
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met: 
 * 
 * - Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and/or 
 * other materials provided with the distribution.
 * - Neither the name of Wygwam nor the names of its contributors may be 
 * used to endorse or promote products derived from this software without 
 * specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.openxml4j.opc.internal.marshallers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.log4j.Logger;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.PackageNamespaces;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageRelationship;
import org.openxml4j.opc.PackageRelationshipCollection;
import org.openxml4j.opc.PackagingURIHelper;
import org.openxml4j.opc.StreamHelper;
import org.openxml4j.opc.TargetMode;
import org.openxml4j.opc.internal.PartMarshaller;
import org.openxml4j.opc.internal.ZipHelper;

/**
 * Zip part marshaller. This marshaller is use to save any part in a zip stream.
 * 
 * @author Julien Chable
 * @version 0.1
 */
public class ZipPartMarshaller implements PartMarshaller {
	private static Logger logger = Logger.getLogger("org.openxml4j");

	/**
	 * Save the specified part.
	 * 
	 * @throws OpenXML4JException
	 *             Throws if an internal exception is thrown.
	 */
	public boolean marshall(PackagePart part, OutputStream os)
			throws OpenXML4JException {
		if (!(os instanceof ZipOutputStream)) {
			logger.error("Unexpected class " + os.getClass().getName());
			throw new OpenXML4JException("ZipOutputStream expected !");
			// Normally should happen only in developpement phase, so just throw
			// exception
		}

		ZipOutputStream zos = (ZipOutputStream) os;
		ZipEntry partEntry = new ZipEntry(ZipHelper
				.getZipItemNameFromOPCName(part.getPartName().getURI()
						.getPath()));
		try {
			// Create next zip entry
			zos.putNextEntry(partEntry);

			// Saving data in the ZIP file
			InputStream ins = part.getInputStream();
			byte[] buff = new byte[ZipHelper.READ_WRITE_FILE_BUFFER_SIZE];
			while (ins.available() > 0) {
				int resultRead = ins.read(buff);
				if (resultRead == -1) {
					// End of file reached
					break;
				} else {
					zos.write(buff, 0, resultRead);
				}
			}
			zos.closeEntry();
		} catch (IOException ioe) {
			logger.error("Cannot write: " + part.getPartName() + ": in ZIP",
					ioe);
			return false;
		}

		// Saving relationship part
		if (part.hasRelationships()) {
			PackagePartName relationshipPartName = PackagingURIHelper
					.getRelationshipPartName(part.getPartName());

			marshallRelationshipPart(part.getRelationships(),
					relationshipPartName, zos);

		}
		return true;
	}

	/**
	 * Save relationships into the part.
	 * 
	 * @param rels
	 *            The relationships collection to marshall.
	 * @param relPartURI
	 *            Part name of the relationship part to marshall.
	 * @param zos
	 *            Zip output stream in which to save the XML content of the
	 *            relationships serialization.
	 */
	public static boolean marshallRelationshipPart(
			PackageRelationshipCollection rels, PackagePartName relPartName,
			ZipOutputStream zos) {
		// Building xml
		Document xmlOutDoc = DocumentHelper.createDocument();
		// make something like <Relationships
		// xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
		Namespace dfNs = Namespace.get("", PackageNamespaces.RELATIONSHIPS);
		Element root = xmlOutDoc.addElement(new QName(
				PackageRelationship.RELATIONSHIPS_TAG_NAME, dfNs));

		// <Relationship
		// TargetMode="External"
		// Id="rIdx"
		// Target="http://www.custom.com/images/pic1.jpg"
		// Type="http://www.custom.com/external-resource"/>

		URI sourcePartURI = PackagingURIHelper
				.getSourcePartUriFromRelationshipPartUri(relPartName.getURI());

		for (PackageRelationship rel : rels) {
			// L'�l�ment de la relation
			Element relElem = root
					.addElement(PackageRelationship.RELATIONSHIP_TAG_NAME);

			// L'attribut ID
			relElem.addAttribute(PackageRelationship.ID_ATTRIBUTE_NAME, rel
					.getId());

			// L'attribut Type
			relElem.addAttribute(PackageRelationship.TYPE_ATTRIBUTE_NAME, rel
					.getRelationshipType());

			// L'attribut Target
			String targetValue;
			URI uri = rel.getTargetURI();
			if (rel.getTargetMode() == TargetMode.EXTERNAL) {
				// Save the target as-is - we don't need to validate it,
				//  alter it etc
				try {
					targetValue = URLEncoder.encode(uri.toString(), "UTF-8");
				} catch (UnsupportedEncodingException e) {
					targetValue = uri.toString();
				}

				// add TargetMode attribut (as it is external link external)
				relElem.addAttribute(
						PackageRelationship.TARGET_MODE_ATTRIBUTE_NAME,
						"External");
			} else {
				targetValue = PackagingURIHelper.relativizeURI(
						sourcePartURI, rel.getTargetURI()).getPath();
			}
			relElem.addAttribute(PackageRelationship.TARGET_ATTRIBUTE_NAME,
					targetValue);
		}

		xmlOutDoc.normalize();

		// String schemaFilename = Configuration.getPathForXmlSchema()+
		// File.separator + "opc-relationships.xsd";

		// Save part in zip
		ZipEntry ctEntry = new ZipEntry(ZipHelper.getZipURIFromOPCName(
				relPartName.getURI().toASCIIString()).getPath());
		try {
			// Cr�ation de l'entr�e dans le fichier ZIP
			zos.putNextEntry(ctEntry);
			if (!StreamHelper.saveXmlInStream(xmlOutDoc, zos)) {
				return false;
			}
			zos.closeEntry();
		} catch (IOException e) {
			logger.error("Cannot create zip entry " + relPartName, e);
			return false;
		}
		return true; // success
	}
}
