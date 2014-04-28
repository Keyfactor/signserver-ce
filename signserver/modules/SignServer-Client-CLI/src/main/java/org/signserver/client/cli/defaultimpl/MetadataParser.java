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
package org.signserver.client.cli.defaultimpl;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class to handle the -metadata CLI option.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class MetadataParser {

    public static Map<String, String> parseMetadata(final String[] optionValues) 
        throws IllegalArgumentException {
        final Map<String, String> metadata = new HashMap<String, String>();
        
        for (final String value : optionValues) {
            final String[] valueSplit = value.split("=");
            
            if (valueSplit.length != 2) {
                throw new IllegalArgumentException("Meta data parameters must be specified as KEY=VALUE");
            }
            
            metadata.put(valueSplit[0].trim(),
                    valueSplit[1].trim());
        }
        
        return metadata;
    }
}
