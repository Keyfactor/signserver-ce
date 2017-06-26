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

package org.openxml4j.opc;

/**
 * Open Packaging Convention content types (see Annex F : Standard Namespaces
 * and Content Types).
 * 
 * @author CDubettier define some constants, Julien Chable
 * @version 0.1
 */
public class ContentTypes {

	/*
	 * Open Packaging Convention (Annex F : Standard Namespaces and Content
	 * Types)
	 */

	/**
	 * Core Properties part.
	 */
	public static final String CORE_PROPERTIES_PART = "application/vnd.openxmlformats-package.core-properties+xml";

	/**
	 * Digital Signature Certificate part.
	 */
	public static final String DIGITAL_SIGNATURE_CERTIFICATE_PART = "application/vnd.openxmlformats-package.digital-signature-certificate";

	/**
	 * Digital Signature Origin part.
	 */
	public static final String DIGITAL_SIGNATURE_ORIGIN_PART = "application/vnd.openxmlformats-package.digital-signature-origin";

	/**
	 * Digital Signature XML Signature part.
	 */
	public static final String DIGITAL_SIGNATURE_XML_SIGNATURE_PART = "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";

	/**
	 * Relationships part.
	 */
	public static final String RELATIONSHIPS_PART = "application/vnd.openxmlformats-package.relationships+xml";

	/**
	 * Custom XML part.
	 */
	public static final String CUSTOM_XML_PART = "application/vnd.openxmlformats-officedocument.customXmlProperties+xml";

	/**
	 * Plain old xml. Note - OOXML uses application/xml, and not text/xml!
	 */
	public static final String PLAIN_OLD_XML = "application/xml";

	public static final String IMAGE_JPEG = "image/jpeg";

	public static final String EXTENSION_JPG_1 = "jpg";

	public static final String EXTENSION_JPG_2 = "jpeg";

	// image/png ISO/IEC 15948:2003 http://www.libpng.org/pub/png/spec/
	public static final String IMAGE_PNG = "image/png";

	public static final String EXTENSION_PNG = "png";

	// image/gif http://www.w3.org/Graphics/GIF/spec-gif89a.txt
	public static final String IMAGE_GIF = "image/gif";

	public static final String EXTENSION_GIF = "gif";

	/**
	 * TIFF image format.
	 * 
	 * @see http://partners.adobe.com/public/developer/tiff/index.html#spec
	 */
	public static final String IMAGE_TIFF = "image/tiff";

	public static final String EXTENSION_TIFF = "tiff";

	/**
	 * Pict image format.
	 * 
	 * @see http://developer.apple.com/documentation/mac/QuickDraw/QuickDraw-2.html
	 */
	public static final String IMAGE_PICT = "image/pict";

	public static final String EXTENSION_PICT = "tiff";

	/**
	 * XML file.
	 */
	public static final String XML = "text/xml";

	public static final String EXTENSION_XML = "xml";

	/**
	 * Gets the content type of the specified filename based on its extension.
	 * 
	 * @param filename The filename to test.  
	 * 
	 * @return The known content type of the filename.  
	 */
	public static String getContentTypeFromFileExtension(String filename) {
		String extension = filename.substring(filename.lastIndexOf(".") + 1)
				.toLowerCase();
		if (extension.equals(EXTENSION_JPG_1)
				|| extension.equals(EXTENSION_JPG_2))
			return IMAGE_JPEG;
		else if (extension.equals(EXTENSION_GIF))
			return IMAGE_GIF;
		else if (extension.equals(EXTENSION_PICT))
			return IMAGE_PICT;
		else if (extension.equals(EXTENSION_PNG))
			return IMAGE_PNG;
		else if (extension.equals(EXTENSION_TIFF))
			return IMAGE_TIFF;
		else if (extension.equals(EXTENSION_XML))
			return XML;
		else
			return null;
	}
}
