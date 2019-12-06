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
package org.signserver.server.log;

import java.util.Map;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * WorkerLogger not logging anything at all.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NullWorkerLogger extends BaseWorkerLogger implements IWorkerLogger {

    @Override
    public void init(final int workerId, final WorkerConfig config, final SignServerContext context) {}

    @Override
    public void log(final AdminInfo adminInfo, final Map<String, Object> fields, final RequestContext context) throws WorkerLoggerException {}

}
