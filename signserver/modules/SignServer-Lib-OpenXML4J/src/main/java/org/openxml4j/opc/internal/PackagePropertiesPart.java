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

package org.openxml4j.opc.internal;

import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.apache.commons.lang.time.FastDateFormat;

import org.openxml4j.exceptions.InvalidFormatException;
import org.openxml4j.exceptions.InvalidOperationException;
import org.openxml4j.exceptions.OpenXML4JException;
import org.openxml4j.opc.ContentTypes;
import org.openxml4j.opc.Package;
import org.openxml4j.opc.PackagePart;
import org.openxml4j.opc.PackagePartName;
import org.openxml4j.opc.PackageProperties;
import org.openxml4j.util.Nullable;

/**
 * Represents the core properties part of a package.
 * 
 * @author Julien Chable
 * @version 1.0
 */
public class PackagePropertiesPart extends PackagePart implements
		PackageProperties {

	public final static String NAMESPACE_DC_URI = "http://purl.org/dc/elements/1.1/";

	public final static String NAMESPACE_CP_URI = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties";

	public final static String NAMESPACE_DCTERMS_URI = "http://purl.org/dc/terms/";

	public final static String NAMESPACE_XSI_URI = "http://www.w3.org/2001/XMLSchema-instance";

	/**
	 * Constructor.
	 * 
	 * @param pack
	 *            Container package.
	 * @param partName
	 *            Name of this part.
	 * @throws InvalidFormatException
	 *             Throws if the content is invalid.
	 */
	public PackagePropertiesPart(Package pack, PackagePartName partName)
			throws InvalidFormatException {
		super(pack, partName, ContentTypes.CORE_PROPERTIES_PART);
	}

	/**
	 * A categorization of the content of this package.
	 * 
	 * [Example: Example values for this property might include: Resume, Letter,
	 * Financial Forecast, Proposal, Technical Presentation, and so on. This
	 * value might be used by an application's user interface to facilitate
	 * navigation of a large set of documents. end example]
	 */
	protected Nullable<String> category = new Nullable<String>();

	/**
	 * The status of the content.
	 * 
	 * [Example: Values might include "Draft", "Reviewed", and "Final". end
	 * example]
	 */
	protected Nullable<String> contentStatus = new Nullable<String>();

	/**
	 * The type of content represented, generally defined by a specific use and
	 * intended audience.
	 * 
	 * [Example: Values might include "Whitepaper", "Security Bulletin", and
	 * "Exam". end example] [Note: This property is distinct from MIME content
	 * types as defined in RFC 2616. end note]
	 */
	protected Nullable<String> contentType = new Nullable<String>();

	/**
	 * Date of creation of the resource.
	 */
	protected Nullable<Date> created = new Nullable<Date>();

	/**
	 * An entity primarily responsible for making the content of the resource.
	 */
	protected Nullable<String> creator = new Nullable<String>();

	/**
	 * An explanation of the content of the resource.
	 * 
	 * [Example: Values might include an abstract, table of contents, reference
	 * to a graphical representation of content, and a free-text account of the
	 * content. end example]
	 */
	protected Nullable<String> description = new Nullable<String>();

	/**
	 * An unambiguous reference to the resource within a given context.
	 */
	protected Nullable<String> identifier = new Nullable<String>();

	/**
	 * A delimited set of keywords to support searching and indexing. This is
	 * typically a list of terms that are not available elsewhere in the
	 * properties.
	 */
	protected Nullable<String> keywords = new Nullable<String>();

	/**
	 * The language of the intellectual content of the resource.
	 * 
	 * [Note: IETF RFC 3066 provides guidance on encoding to represent
	 * languages. end note]
	 */
	protected Nullable<String> language = new Nullable<String>();

	/**
	 * The user who performed the last modification. The identification is
	 * environment-specific.
	 * 
	 * [Example: A name, email address, or employee ID. end example] It is
	 * recommended that this value be as concise as possible.
	 */
	protected Nullable<String> lastModifiedBy = new Nullable<String>();

	/**
	 * The date and time of the last printing.
	 */
	protected Nullable<Date> lastPrinted = new Nullable<Date>();

	/**
	 * Date on which the resource was changed.
	 */
	protected Nullable<Date> modified = new Nullable<Date>();

	/**
	 * The revision number.
	 * 
	 * [Example: This value might indicate the number of saves or revisions,
	 * provided the application updates it after each revision. end example]
	 */
	protected Nullable<String> revision = new Nullable<String>();

	/**
	 * The topic of the content of the resource.
	 */
	protected Nullable<String> subject = new Nullable<String>();

	/**
	 * The name given to the resource.
	 */
	protected Nullable<String> title = new Nullable<String>();

	/**
	 * The version number. This value is set by the user or by the application.
	 */
	protected Nullable<String> version = new Nullable<String>();

	/*
	 * Getters and setters
	 */

	/**
	 * Get the category property.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getCategoryProperty()
	 */
	public Nullable<String> getCategoryProperty() {
		return category;
	}

	/**
	 * Get content status.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getContentStatusProperty()
	 */
	public Nullable<String> getContentStatusProperty() {
		return contentStatus;
	}

	/**
	 * Get content type.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getContentTypeProperty()
	 */
	public Nullable<String> getContentTypeProperty() {
		return contentType;
	}

	/**
	 * Get created date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getCreatedProperty()
	 */
	public Nullable<Date> getCreatedProperty() {
		return created;
	}

	/**
	 * Get created date formated into a String.
	 * 
	 * @return A string representation of the created date.
	 */
	public String getCreatedPropertyString() {
		return getDateValue(created);
	}

	/**
	 * Get creator.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getCreatorProperty()
	 */
	public Nullable<String> getCreatorProperty() {
		return creator;
	}

	/**
	 * Get description.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getDescriptionProperty()
	 */
	public Nullable<String> getDescriptionProperty() {
		return description;
	}

	/**
	 * Get identifier.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getIdentifierProperty()
	 */
	public Nullable<String> getIdentifierProperty() {
		return identifier;
	}

	/**
	 * Get keywords.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getKeywordsProperty()
	 */
	public Nullable<String> getKeywordsProperty() {
		return keywords;
	}

	/**
	 * Get the language.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getLanguageProperty()
	 */
	public Nullable<String> getLanguageProperty() {
		return language;
	}

	/**
	 * Get the author of last modifications.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getLastModifiedByProperty()
	 */
	public Nullable<String> getLastModifiedByProperty() {
		return lastModifiedBy;
	}

	/**
	 * Get last printed date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getLastPrintedProperty()
	 */
	public Nullable<Date> getLastPrintedProperty() {
		return lastPrinted;
	}

	/**
	 * Get last printed date formated into a String.
	 * 
	 * @return A string representation of the last printed date.
	 */
	public String getLastPrintedPropertyString() {
		return getDateValue(created);
	}

	/**
	 * Get modified date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getModifiedProperty()
	 */
	public Nullable<Date> getModifiedProperty() {
		return modified;
	}

	/**
	 * Get modified date formated into a String.
	 * 
	 * @return A string representation of the modified date.
	 */
	public String getModifiedPropertyString() {
		if (!modified.hasValue())
			return getDateValue(new Nullable<Date>(new Date()));
		else
			return getDateValue(modified);
	}

	/**
	 * Get revision.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getRevisionProperty()
	 */
	public Nullable<String> getRevisionProperty() {
		return revision;
	}

	/**
	 * Get subject.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getSubjectProperty()
	 */
	public Nullable<String> getSubjectProperty() {
		return subject;
	}

	/**
	 * Get title.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getTitleProperty()
	 */
	public Nullable<String> getTitleProperty() {
		return title;
	}

	/**
	 * Get version.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#getVersionProperty()
	 */
	public Nullable<String> getVersionProperty() {
		return version;
	}

	/**
	 * Set the category.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setCategoryProperty(java.lang.String)
	 */
	public void setCategoryProperty(String category) {
		this.category = setStringValue(category);
	}

	/**
	 * Set the content status.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setContentStatusProperty(java.lang.String)
	 */
	public void setContentStatusProperty(String contentStatus) {
		this.contentStatus = setStringValue(contentStatus);
	}

	/**
	 * Set the content type.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setContentTypeProperty(java.lang.String)
	 */
	public void setContentTypeProperty(String contentType) {
		this.contentType = setStringValue(contentType);
	}

	/**
	 * Set the created date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setCreatedProperty(org.openxml4j.util.Nullable)
	 */
	public void setCreatedProperty(String created) {
		try {
			this.created = setDateValue(created);
		} catch (InvalidFormatException e) {
			new IllegalArgumentException("created  : "
					+ e.getLocalizedMessage());
		}
	}

	/**
	 * Set the created date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setCreatedProperty(org.openxml4j.util.Nullable)
	 */
	public void setCreatedProperty(Nullable<Date> created) {
		if (created.hasValue())
			this.created = created;
	}

	/**
	 * Set the creator.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setCreatorProperty(java.lang.String)
	 */
	public void setCreatorProperty(String creator) {
		this.creator = setStringValue(creator);
	}

	/**
	 * Set the description.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setDescriptionProperty(java.lang.String)
	 */
	public void setDescriptionProperty(String description) {
		this.description = setStringValue(description);
	}

	/**
	 * Set identifier.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setIdentifierProperty(java.lang.String)
	 */
	public void setIdentifierProperty(String identifier) {
		this.identifier = setStringValue(identifier);
	}

	/**
	 * Set keywords.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setKeywordsProperty(java.lang.String)
	 */
	public void setKeywordsProperty(String keywords) {
		this.keywords = setStringValue(keywords);
	}

	/**
	 * Set language.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setLanguageProperty(java.lang.String)
	 */
	public void setLanguageProperty(String language) {
		this.language = setStringValue(language);
	}

	/**
	 * Set last modifications author.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setLastModifiedByProperty(java.lang.String)
	 */
	public void setLastModifiedByProperty(String lastModifiedBy) {
		this.lastModifiedBy = setStringValue(lastModifiedBy);
	}

	/**
	 * Set last printed date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setLastPrintedProperty(org.openxml4j.util.Nullable)
	 */
	public void setLastPrintedProperty(String lastPrinted) {
		try {
			this.lastPrinted = setDateValue(lastPrinted);
		} catch (InvalidFormatException e) {
			new IllegalArgumentException("lastPrinted  : "
					+ e.getLocalizedMessage());
		}
	}

	/**
	 * Set last printed date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setLastPrintedProperty(org.openxml4j.util.Nullable)
	 */
	public void setLastPrintedProperty(Nullable<Date> lastPrinted) {
		if (lastPrinted.hasValue())
			this.lastPrinted = lastPrinted;
	}

	/**
	 * Set last modification date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setModifiedProperty(org.openxml4j.util.Nullable)
	 */
	public void setModifiedProperty(String modified) {
		try {
			this.modified = setDateValue(modified);
		} catch (InvalidFormatException e) {
			new IllegalArgumentException("modified  : "
					+ e.getLocalizedMessage());
		}
	}

	/**
	 * Set last modification date.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setModifiedProperty(org.openxml4j.util.Nullable)
	 */
	public void setModifiedProperty(Nullable<Date> modified) {
		if (modified.hasValue())
			this.modified = modified;
	}

	/**
	 * Set revision.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setRevisionProperty(java.lang.String)
	 */
	public void setRevisionProperty(String revision) {
		this.revision = setStringValue(revision);
	}

	/**
	 * Set subject.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setSubjectProperty(java.lang.String)
	 */
	public void setSubjectProperty(String subject) {
		this.subject = setStringValue(subject);
	}

	/**
	 * Set title.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setTitleProperty(java.lang.String)
	 */
	public void setTitleProperty(String title) {
		this.title = setStringValue(title);
	}

	/**
	 * Set version.
	 * 
	 * @see org.openxml4j.opc.PackageProperties#setVersionProperty(java.lang.String)
	 */
	public void setVersionProperty(String version) {
		this.version = setStringValue(version);
	}

	/**
	 * Convert a strig value into a Nullable<String>
	 */
	private Nullable<String> setStringValue(String s) {
		if (s == null || s.equals(""))
			return new Nullable<String>();
		else
			return new Nullable<String>(s);
	}

	/**
	 * Convert a string value represented a date into a Nullable<Date>.
	 * 
	 * @throws InvalidFormatException
	 *             Throws if the date format isnot valid.
	 */
	private Nullable<Date> setDateValue(String s) throws InvalidFormatException {
		if (s == null || s.equals(""))
			return new Nullable<Date>();
		else {
			SimpleDateFormat df = new SimpleDateFormat(
					"yyyy-MM-dd'T'HH:mm:ss'Z'");
			Date d = df.parse(s, new ParsePosition(0));
			if (d == null)
				throw new InvalidFormatException("Date not well formated");
			return new Nullable<Date>(d);
		}
	}

	/**
	 * Convert a Nullable<Date> into a String.
	 * 
	 * @param d
	 *            The Date to convert.
	 * @return The formated date or null.
	 * @see java.util.SimpleDateFormat
	 */
	private String getDateValue(Nullable<Date> d) {
		if (d == null || d.equals(""))
			return "";
		else {
			FastDateFormat df = FastDateFormat.getInstance(
					"yyyy-MM-dd'T'HH:mm:ss'Z'");
			return df.format(d.getValue());
		}
	}

	@Override
	protected InputStream getInputStreamImpl() {
		throw new InvalidOperationException("Operation not authorized");
	}

	@Override
	protected OutputStream getOutputStreamImpl() {
		throw new InvalidOperationException(
				"Can't use output stream to set properties !");
	}

	@Override
	public boolean save(OutputStream zos) throws OpenXML4JException {
		throw new InvalidOperationException("Operation not authorized");
	}

	@Override
	public boolean load(InputStream ios) throws InvalidFormatException {
		throw new InvalidOperationException("Operation not authorized");
	}

	@Override
	public void close() {
		// Do nothing
	}

	@Override
	public void flush() {
		// Do nothing
	}
}
