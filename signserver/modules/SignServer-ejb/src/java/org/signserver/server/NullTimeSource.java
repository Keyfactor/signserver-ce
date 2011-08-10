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
package org.signserver.server;

import java.util.Date;
import java.util.Properties;

/**
 * Simple class implementing the ITimeSource interface but always returns null
 * for the time.
 *
 * This class can be used as time source for testing purposes.
 *
 * No defined properties.
 *
 * @author markus
 * @version  $Id$
 */
public class NullTimeSource implements ITimeSource {

    /**
     * @param props unused
     * @see org.signserver.server.ITimeSource#init(java.util.Properties)
     */
    public void init(final Properties props) {
        // No properties defined
    }

    /**
     * @return Always null simulating that the time source is not available.
     * @see org.signserver.server.ITimeSource#getGenTime()
     */
    public final Date getGenTime() {
        return null;
    }
}
