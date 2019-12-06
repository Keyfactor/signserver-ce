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

import java.util.Date;

import org.openxml4j.util.Nullable;

/**
 * Represents the core properties of an OPC package.
 * 
 * @author Julien Chable
 * @version 1.0
 * @see org.openxml4j.opc.Package
 */
public interface PackageProperties {
	
	/**
	 * Dublin Core Terms URI.
	 */
	public final static String NAMESPACE_DCTERMS = "http://purl.org/dc/terms/";
	
	/**
	 * Dublin Core namespace URI.
	 */
	public final static String NAMESPACE_DC = "http://purl.org/dc/elements/1.1/";

	/* Getters and setters */

	/**
	 * Set the category of the content of this package.
	 */
	public abstract Nullable<String> getCategoryProperty();

	/**
	 * Set the category of the content of this package.
	 */
	public abstract void setCategoryProperty(String category);

	/**
	 * Set the status of the content.
	 */
	public abstract Nullable<String> getContentStatusProperty();

	/**
	 * Get the status of the content.
	 */
	public abstract void setContentStatusProperty(String contentStatus);

	/**
	 * Get the type of content represented, generally defined by a specific use
	 * and intended audience.
	 */
	public abstract Nullable<String> getContentTypeProperty();

	/**
	 * Set the type of content represented, generally defined by a specific use
	 * and intended audience.
	 */
	public abstract void setContentTypeProperty(String contentType);

	/**
	 * Get the date of creation of the resource.
	 */
	public abstract Nullable<Date> getCreatedProperty();

	/**
	 * Set the date of creation of the resource.
	 */
	public abstract void setCreatedProperty(String created);
	
	/**
	 * Set the date of creation of the resource.
	 */
	public abstract void setCreatedProperty(Nullable<Date> created);

	/**
	 * Get the entity primarily responsible for making the content of the
	 * resource.
	 */
	public abstract Nullable<String> getCreatorProperty();

	/**
	 * Set the entity primarily responsible for making the content of the
	 * resource.
	 */
	public abstract void setCreatorProperty(String creator);

	/**
	 * Get the explanation of the content of the resource.
	 */
	public abstract Nullable<String> getDescriptionProperty();

	/**
	 * Set the explanation of the content of the resource.
	 */
	public abstract void setDescriptionProperty(String description);

	/**
	 * Get an unambiguous reference to the resource within a given context.
	 */
	public abstract Nullable<String> getIdentifierProperty();

	/**
	 * Set an unambiguous reference to the resource within a given context.
	 */
	public abstract void setIdentifierProperty(String identifier);

	/**
	 * Get a delimited set of keywords to support searching and indexing. This
	 * is typically a list of terms that are not available elsewhere in the
	 * properties
	 */
	public abstract Nullable<String> getKeywordsProperty();

	/**
	 * Set a delimited set of keywords to support searching and indexing. This
	 * is typically a list of terms that are not available elsewhere in the
	 * properties
	 */
	public abstract void setKeywordsProperty(String keywords);

	/**
	 * Get the language of the intellectual content of the resource.
	 */
	public abstract Nullable<String> getLanguageProperty();

	/**
	 * Set the language of the intellectual content of the resource.
	 */
	public abstract void setLanguageProperty(String language);

	/**
	 * Get the user who performed the last modification.
	 */
	public abstract Nullable<String> getLastModifiedByProperty();

	/**
	 * Set the user who performed the last modification.
	 */
	public abstract void setLastModifiedByProperty(String lastModifiedBy);

	/**
	 * Get the date and time of the last printing.
	 */
	public abstract Nullable<Date> getLastPrintedProperty();

	/**
	 * Set the date and time of the last printing.
	 */
	public abstract void setLastPrintedProperty(String lastPrinted);
	
	/**
	 * Set the date and time of the last printing.
	 */
	public abstract void setLastPrintedProperty(Nullable<Date> lastPrinted);

	/**
	 * Get the date on which the resource was changed.
	 */
	public abstract Nullable<Date> getModifiedProperty();

	/**
	 * Set the date on which the resource was changed.
	 */
	public abstract void setModifiedProperty(String modified);
	
	/**
	 * Set the date on which the resource was changed.
	 */
	public abstract void setModifiedProperty(Nullable<Date> modified);

	/**
	 * Get the revision number.
	 */
	public abstract Nullable<String> getRevisionProperty();

	/**
	 * Set the revision number.
	 */
	public abstract void setRevisionProperty(String revision);

	/**
	 * Get the topic of the content of the resource.
	 */
	public abstract Nullable<String> getSubjectProperty();

	/**
	 * Set the topic of the content of the resource.
	 */
	public abstract void setSubjectProperty(String subject);

	/**
	 * Get the name given to the resource.
	 */
	public abstract Nullable<String> getTitleProperty();

	/**
	 * Set the name given to the resource.
	 */
	public abstract void setTitleProperty(String title);

	/**
	 * Get the version number.
	 */
	public abstract Nullable<String> getVersionProperty();

	/**
	 * Set the version number.
	 */
	public abstract void setVersionProperty(String version);
}
