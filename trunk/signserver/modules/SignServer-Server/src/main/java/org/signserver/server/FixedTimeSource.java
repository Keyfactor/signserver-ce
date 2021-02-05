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

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerStatusInfo;

/**
 * Simple class implementing the ITimeSource interface always returns the
 * configured fixed time. This is mainly intended to use for testing to get a
 * predictable non-null time value.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class FixedTimeSource implements ITimeSource {

    public static final String FIXEDTIME = "FIXEDTIME";
    
    private Date time;
    
    @Override
    public void init(Properties props) {
        time = new Date(Long.parseLong(props.getProperty(FIXEDTIME, "0")));
    }

    @Override
    public Date getGenTime(final RequestContext context) {
        return time;
    }

    @Override
    public List<WorkerStatusInfo.Entry> getStatusBriefEntries() {
        return Collections.emptyList();
    }

    @Override
    public List<WorkerStatusInfo.Entry> getStatusCompleteEntries() {
        return Collections.emptyList();
    }
}
