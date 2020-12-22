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
package org.signserver.test.signserverws;

import javax.net.ssl.SSLSocketFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.AnnotationIntrospector;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import org.signserver.testutils.ModulesTestCase;

/**
 * A help class to share artifacts/constants between SignServerWSServiceTest(s) of different versions.
 *
 * @author Andrey Sergeev 20-dec-2020
 * @version $Id$
 */
public abstract class SignServerWSServiceTestBase extends ModulesTestCase {

    /** Worker ID as defined in test-configuration.properties. **/
    protected static final int WORKER_ID_INT = 7003;
    protected static final String WORKER_ID = "" + WORKER_ID_INT;
    protected static final int REQUEST_ID = 4711;
    /** A worker ID assumed to not be existing. */
    protected static final String NON_EXISTING_WORKER_ID = "1231231";

    protected static SSLSocketFactory sslSocketFactory;

    /**
     * Converts a JAXB Annotated Object into its JSON representation.
     *
     * @param wsObject a JAXB Annotated Object
     * @return A JSON representation of the JAXB Object.
     * @throws JsonProcessingException In case of JSON creation failure.
     */
    public String toJsonString(final Object wsObject) throws JsonProcessingException {
        final ObjectMapper mapper = new ObjectMapper();
        final AnnotationIntrospector introspector = new JaxbAnnotationIntrospector(mapper.getTypeFactory());
        mapper.setAnnotationIntrospector(introspector);
        return mapper.writeValueAsString(wsObject);
    }

}
