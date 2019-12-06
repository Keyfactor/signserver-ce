/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Copyright 2009 IBM. All rights reserved.
 *
 * Use is subject to license terms.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.pkg.signature;

/**
 * class holding helper constants to be used during signature generation and verification for odf
 * 
 * @author aziz.goktepe (aka rayback_2)
 *
 * patch originally created for SignServer project {@link http://www.signserver.org}
 */
class Constants {

    /**
     * media type attribute name
     */
    public static final String ATTR_NAME_MEDIA_TYPE = "media-type";
    /**
     * full path attribute name
     */
    public static final String ATTR_NAME_FULL_PATH = "full-path";
    /**
     * file entry node name
     */
    public static final String NODE_NAME_FILE_ENTRY = "file-entry";
    /**
     * manifest namespace uri
     */
    public static final String NMS_URI_MANIFEST = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
    /**
     * path to META-INF directory
     */
    public static final String PATH_TO_META_INF_DIR = "META-INF/";
    /**
     * path to manifest.xml file entry
     */
    public static final String PATH_TO_MANIFEST_XML = PATH_TO_META_INF_DIR + "manifest.xml";
    /**
     * path prefix to file entry that will hold document signature information
     */
    public static final String PATH_TO_DOCUMENT_SIGNATURE_PREFIX = "META-INF/OdfDomsignatures";
    /**
     * path to file entry that holds document signatures, as required by open office 3.1
     */
    public static final String PATH_TO_DOCUMENT_SIGNATURE_OPEN_OFFICE_3_1_REQUIRED = "META-INF/documentsignatures.xml";
    /**
     * prefix for manifest namespace
     */
    public static final String NMS_PREFIX_MANIFEST = "manifest";
    /**
     * media type to identify text/xml
     */
    public static final String MEDIA_TYPE_TEXT_XML = "text/xml";
    /**
     * ID of the Signature Element in Signature Document
     */
    public static final String ID_SIGNATURE_PREFIX = "ID_OdfDomSignature";
    /**
     * ID of the Signature Property (date and time) inside
     */
    public static final String ID_SIGNATURE_PROPERTY_DATETIME_PREFIX = "ID_OdfDomDateTime";
    /**
     * date namespace URI (inside signatureproperty)
     */
    public static final String NMS_URI_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM = "http://purl.org/dc/elements/1.1/";
    /**
     * prefix for date element (inside signature properties)
     */
    public static final String NMS_PREFIX_SIGNATURE_PROPERTY_DATETIME_DATE_ELEM = "dc";
    /**
     * node name for date element (inside signature properties)
     */
    public static final String NODE_NAME_SIGNATURE_PROPERTY_DATETIME_DATE = "date";
    /**
     * the name for root node of document signature document (signature is contained within it)
     */
    public static final String NODE_NAME_DOCUMENT_SIGNATURES = "document-signatures";
    /**
     * namespace for document-signature
     */
    public static final String NMS_URI_DOCUMENT_SIGNATURES = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
    /**
     * special string that should be present in a digital signature file
     */
    public static final String SIGNATURE_FILE_IDENTIFIER_STRING = "signatures";
    /**
     * xml element fragment identifier
     */
    public static final String XML_ELEMENT_FRAGMENT_IDENTIFIER = "#";
}
