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

/**
 * class holding helper constants to be used during signature generation for odf
 * 
 * @author Aziz Göktepe
 * 
 */
public class ODFConstants {
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
	 * path to manifest.xml part
	 */
	public static final String PATH_TO_MANIFEST_XML = PATH_TO_META_INF_DIR
			+ "manifest.xml";

	/**
	 * path to part that will hold document signature information
	 */
	public static final String PATH_TO_DOCUMENT_SIGNATURE = "META-INF/documentsignatures.xml";

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
	public static final String ID_SIGNATIRE = "ID_SignServerSignature";

	/**
	 * ID of the Signature Property (date and time) inside
	 */
	public static final String ID_SIGNATURE_PROPERTY_DATETIME = "ID_SignServerSignaturePropertyDateTime";

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
	public static final String NODE_NAME_DOCUMENT_SIGNATURES ="document-signatures";
	
	/**
	 * namespace for document-signature 
	 */
	public static final String NMS_URI_DOCUMENT_SIGNATURES = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";
}
