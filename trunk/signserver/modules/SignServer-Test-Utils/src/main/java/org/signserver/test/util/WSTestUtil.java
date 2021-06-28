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
package org.signserver.test.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;

/**
 * A helper class for WS testing.
 *
 * @author Andrey Sergeev 15-jan-2021
 * @version $Id$
 */
public class WSTestUtil {

    /**
     * Converts a JAXB Annotated Object into its JSON representation.
     *
     * @param wsObject a JAXB Annotated Object
     * @return A JSON representation of the JAXB Object.
     * @throws JsonProcessingException In case of JSON creation failure.
     */
    public static String toJsonString(final Object wsObject) throws JsonProcessingException {
        final ObjectMapper mapper = new ObjectMapper();
        final AnnotationIntrospector introspector = new JaxbAnnotationIntrospector(mapper.getTypeFactory());
        mapper.setAnnotationIntrospector(introspector);
        return mapper.writeValueAsString(wsObject);
    }

}
