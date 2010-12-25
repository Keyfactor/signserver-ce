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
package org.signserver.adminws;

import java.io.Serializable;
import java.util.Properties;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WSWorkerConfig implements Serializable {

    /** serialVersionUID for this class. */
    private static final long serialVersionUID = 1;

    private Properties properties;

    public WSWorkerConfig() {
    }

    public WSWorkerConfig(Properties properties) {
        this.properties = properties;
    }

    public Properties getProperties() {
        return properties;
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }

}
