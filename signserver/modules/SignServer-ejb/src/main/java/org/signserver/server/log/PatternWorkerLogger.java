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

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;

/**
 * Completely configurable WorkerLogger.
 *
 * @version $Id$
 */
public class PatternWorkerLogger extends BaseWorkerLogger implements IWorkerLogger {

    private Pattern pattern;
    private String orderString;
    private static final Logger ACCOUNTLOG =
            Logger.getLogger(IWorkerLogger.class);
    private String logDateFormat;
    private String timeZone;
    private Level logLevel;

    private static final String DEFAULT_LOGPATTERN =
            "\\$\\{(.+?)\\}";

    private static final String DEFAULT_LOGORDER =
            "AUDIT; DefaultTimeStampLogger; "
                + "LOG_ID: ${LOG_ID}; "
                + "CLIENT_IP: ${CLIENT_IP}; "
                + "REQUEST_FULLURL: ${REQUEST_FULLURL}; "
                + "RequestTime: ${LOG_TIME}; "
                + "ResponseTime: ${REPLY_TIME}; "
                + "EXCEPTION: ${EXCEPTION}";

    private static final String DEFAULT_LOGDATEFORMAT =
            "yyyy-MM-dd:HH:mm:ss:z";

    private static final String DEFAULT_LOGTIMEZONE = "GMT";
    
    private static final String DEFAULT_LOGLEVEL = "INFO";

    public PatternWorkerLogger() {
    }

    @Override
    public void init(final int workerId, final WorkerConfig config, final SignServerContext context) {
        this.pattern = Pattern.compile(config.getProperty("LOGPATTERN",
                DEFAULT_LOGPATTERN));
        this.orderString = config.getProperty("LOGORDER", DEFAULT_LOGORDER);
        this.logDateFormat = config.getProperty("LOGDATEFORMAT", DEFAULT_LOGDATEFORMAT);
        this.timeZone = config.getProperty("LOGTIMEZONE", DEFAULT_LOGTIMEZONE);
        this.logLevel = Level.toLevel(config.getProperty("LOGLEVEL_DEFAULT",
        		DEFAULT_LOGLEVEL), Level.INFO);
    }

    @Override
    public void log(final AdminInfo adminInfo, final Map<String, Object> fields, final RequestContext context) throws WorkerLoggerException {
        final EjbcaPatternLogger pl = new EjbcaPatternLogger(this.pattern.matcher(
                this.orderString), this.orderString, ACCOUNTLOG,
                this.logDateFormat, this.timeZone, this.logLevel);
        final Map<String, String> map = new HashMap<String, String>();
        for (final Map.Entry<String, Object> entrySet : fields.entrySet()) {
            map.put(entrySet.getKey(), String.valueOf(entrySet.getValue()));
        }
        pl.putAll(map);
        pl.writeln();
        pl.flush();
    }
    
}
