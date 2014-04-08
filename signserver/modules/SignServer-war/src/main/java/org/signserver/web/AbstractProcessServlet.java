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
package org.signserver.web;

import java.io.IOException;
import java.io.StringReader;
import java.util.Properties;

import javax.servlet.http.HttpServlet;

/**
 * Abstract base class for process servlets.
 * Handles common request properties (currently REQUEST_METADATA).
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public abstract class AbstractProcessServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static final String REQUEST_METADATA_PROPERTY_NAME = "REQUEST_METADATA";
    
    // metadata properties set via the REQUEST_METADATA= syntax
    private Properties requestMetadata;
    // metadata set with REQUEST_METADATA.name=value overriding the above
    private Properties overrideRequestMetadata;

    protected void initMetaData() {
        // holds parameters set via REQUEST_METADATA= and REQUEST_METADATA.x=
        requestMetadata = new Properties();
        overrideRequestMetadata = new Properties();
    }

    /**
     * Returns true if given request field refers to a meta data property.
     * 
     * @param itemFieldName
     * @return
     */
    protected boolean isFieldMatchingMetaData(final String itemFieldName) {
        return REQUEST_METADATA_PROPERTY_NAME.equals(itemFieldName) ||
                (itemFieldName != null &&
                 itemFieldName.length() > REQUEST_METADATA_PROPERTY_NAME.length() + 1 &&
                 itemFieldName.startsWith(REQUEST_METADATA_PROPERTY_NAME + "."));
    }

    /**
     * Internal method handling a metadata property, updating appropriate
     * mappings for individually set properties and those set as a complete properties mapping.
     * 
     * @param propertyFieldName Request parameter name
     * @param propertyValue Request parameter value
     * @throws IOException
     */
    protected void handleMetaDataProperty(final String propertyFieldName, final String propertyValue) throws IOException {
        if (propertyFieldName.length() == REQUEST_METADATA_PROPERTY_NAME.length()) {
            requestMetadata.load(new StringReader(propertyValue));
        } else {
            final String propertyName = propertyFieldName.substring(REQUEST_METADATA_PROPERTY_NAME.length() + 1);
            
            overrideRequestMetadata.setProperty(propertyName, propertyValue);
        }
    }
    
    /**
     * Internal method gathering metadata from internal mapping giving precedence
     * to parameters set via individually set parameters.
     * 
     * @return Final property object with merged properties
     */
    protected Properties mergeMetadataProperties() {
        requestMetadata.putAll(overrideRequestMetadata);
        return requestMetadata;
    }
}
