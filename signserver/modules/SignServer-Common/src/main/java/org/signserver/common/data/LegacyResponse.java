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
package org.signserver.common.data;

import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;

/**
 * TODO.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LegacyResponse extends Response {

    private final ProcessResponse legacyResponse;

    public LegacyResponse(ProcessResponse legacyResponse) {
        this.legacyResponse = legacyResponse;
    }

    public ProcessResponse getLegacyResponse() {
        return legacyResponse;
    }
    
}
