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
package org.signserver.admin.web;

import javax.faces.bean.ManagedBean;
import org.apache.commons.lang.time.FastDateFormat;
import org.signserver.common.CompileTimeSettings;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
public class AdminWebBean {

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    public String getVersion() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);
    }

    public String getCopyright() {
        return "Copyright © 2006–2017 PrimeKey Solutions AB";
    }

    public String getCurrentTime() {
        return FDF.format(System.currentTimeMillis());
    }
}
