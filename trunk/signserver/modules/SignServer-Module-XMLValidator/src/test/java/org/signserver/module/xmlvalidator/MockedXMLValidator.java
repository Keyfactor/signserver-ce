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
package org.signserver.module.xmlvalidator;

import org.signserver.common.RequestContext;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;

/**
 * Mocked version of the XMLValidator.
 *
 * @author Markus Kilås
 * @version $Id: MockedXAdESSigner.java 4704 2014-05-16 12:38:10Z netmackan $
 */
public class MockedXMLValidator extends XMLValidator {
    private final InternalProcessSessionLocal mockedWorkerSession;

    public MockedXMLValidator(final InternalProcessSessionLocal mockedWorkerSession) {
        this.mockedWorkerSession = mockedWorkerSession;
    }

    @Override
    protected InternalProcessSessionLocal getProcessSession(RequestContext requestContext) {
        return mockedWorkerSession;
    }

}
