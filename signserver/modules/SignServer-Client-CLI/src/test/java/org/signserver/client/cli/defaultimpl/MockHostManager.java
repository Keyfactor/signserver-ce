/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.client.cli.defaultimpl;

import java.util.List;

/**
 * Mocked class of HostManager to be used in Unit Tests.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class MockHostManager extends HostManager {

    public MockHostManager(List<String> hosts, boolean useLoadBalancing) {
        super(hosts, useLoadBalancing);
    }

    @Override
    int getHostIndexByRandom() {
        return 1;
    }

}
