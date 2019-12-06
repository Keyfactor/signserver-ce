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

import org.apache.commons.lang.time.FastDateFormat;
import org.signserver.common.ArchiveMetadata;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WebArchiveEntry {

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    private final ArchiveMetadata entry;

    public static WebArchiveEntry fromArchiveMetadata(ArchiveMetadata entry) {
        return new WebArchiveEntry(entry);
    }

    public WebArchiveEntry(ArchiveMetadata entry) {
        this.entry = entry;
    }

    public int getType() {
        return entry.getType();
    }

    public String getTypeName() {
        return ArchiveMetadata.getTypeName(entry.getType());
    }

    public int getSignerId() {
        return entry.getSignerId();
    }

    public String getUniqueId() {
        return entry.getUniqueId();
    }

    public String getArchiveId() {
        return entry.getArchiveId();
    }

    public String getTime() {
        return FDF.format(entry.getTime());
    }

    public String getRequestIssuerDN() {
        return entry.getRequestIssuerDN();
    }

    public String getRequestCertSerialNumber() {
        return entry.getRequestCertSerialNumber();
    }

    public String getRequestIP() {
        return entry.getRequestIP();
    }

}
