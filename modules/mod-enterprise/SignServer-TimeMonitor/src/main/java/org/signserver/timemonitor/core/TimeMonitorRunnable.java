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
package org.signserver.timemonitor.core;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import org.apache.log4j.Logger;
import org.signserver.timemonitor.common.LeapState;
import org.signserver.timemonitor.common.ReportState;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;
import org.signserver.timemonitor.common.TimeState;
import org.signserver.timemonitor.ntp.NTPDateCommand;
import org.signserver.timemonitor.ntp.NTPDateResult;
import org.signserver.timemonitor.ntp.NTPQCommand;
import org.signserver.timemonitor.ntp.NTPQResult;

/**
 * The main monitoring and reporting task.
 *
 * Performs the following steps:
 * <ol>
 *  <li>Calculate the time difference between the local time and the time of the 
 *      time server by invoking the 'ntpdate' command.</li>
 *  <li>The result is compared with the configured allowed time difference and if 
 *      the time is within the interval the time is considered in sync.</li>
 *   <li>The status is then published to SignServer using HTTP.</li>
 * </ol>
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorRunnable.java 5900 2013-09-19 12:19:40Z netmackan $
 */
@SuppressWarnings("PMD.DoNotUseThreads") // This is not a JEE webapp
public class TimeMonitorRunnable implements Runnable, StateHolder {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorRunnable.class);

    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");

    private volatile boolean continueRun = true;
    private volatile boolean finished;
    private volatile TimeState oldTimeState;
    private volatile ReportState oldReportState;
    private volatile LeapState oldLeapState;
    private volatile long lastUpdated;
    private long lastTrustedTime;
    private String lastReportResponseError;

    private final TimeMonitorAppConfig appConfig;

    /** The current config. */
    private TimeMonitorRuntimeConfig runConfig;

    /** The config to use for the next round. */
    private TimeMonitorRuntimeConfig newRunConfig;

    /** Rotating buffer with the last n log entries. */
    private final LogBuffer logBuffer;

    /**
     * Flag indicating if anything was added to the logBuffer since it was last
     * sent.
     */
    private boolean logChanged;

    private NTPDateCommand ntpDateCommand;
    private final NTPQCommand ntpQCommand;

    private String lastCommandErrorMessage;
    private String lastServerErrorMessage;

    private final URL processURL;
    private final String workerName;
    private final String statusName;

    private String statusNameLeapState;

    private long offset;
    private long oldOffset;
    private long oldQueryTime1;
    private long oldQueryTime2;
    private long oldReportTime;

    private static final long DISABLED_MIN_RUNTIME = 15000;
    private static final long DISABLED_STATUS_EXPIRE_TIME = 30000;

    private final long disabledMinRunTime;
    
    private boolean gotRateLimiting;

    /**
     * Flag indicating if this is the first query and we should thus log
     * errors even if the previous state was the same (ie. UNKNOWN).
     */
    private boolean firstQuery = true;

    public TimeMonitorRunnable(final TimeMonitorAppConfig appConfig, final TimeMonitorRuntimeConfig runConfig) {
        this(appConfig, runConfig, null, null, DISABLED_MIN_RUNTIME);
    }

    protected TimeMonitorRunnable(final TimeMonitorAppConfig appConfig, final TimeMonitorRuntimeConfig runConfig, final NTPDateCommand ntpDateCommand, final NTPQCommand ntpQCommand, final long disabledBinRunTime) {
        this.appConfig = appConfig;
        this.runConfig = runConfig;
        this.newRunConfig = runConfig;
        this.ntpDateCommand = ntpDateCommand;
        if (ntpDateCommand == null && !appConfig.isSignServerManagedConfig()) {
            this.ntpDateCommand = new NTPDateCommand(appConfig.getTimeServerNtpdateCommand(), runConfig.getTimeServerHost(),
                runConfig.getTimeServerSendSamples(), runConfig.getTimeServerTimeout());
        }
        if (ntpQCommand == null) {
            this.ntpQCommand = new NTPQCommand(appConfig.getTimeServerNtpqCommand(), 0);
        } else {
            this.ntpQCommand = ntpQCommand;
        }
        this.disabledMinRunTime = disabledBinRunTime;
        this.processURL = appConfig.getSignServerProcessUrl();
        this.workerName = appConfig.getSignServerStatusPropertiesWorkerName();
        this.statusName = appConfig.getSignServerStatusPropertyName();
        this.statusNameLeapState = appConfig.getSignServerLeapStatusPropertyName();
        this.logBuffer = new LogBuffer(10);
        this.gotRateLimiting = false;
    }

    @Override
    public void run() {
        logInfo("Started");

        while (continueRun) {
            runRound();
        }
    }

    protected void runRound() {
        final long currentTime = System.currentTimeMillis();

        // Use the latest config
        if (runConfig != newRunConfig) {
            logInfo("Config changed to: " + newRunConfig.getVersion());
            ntpDateCommand = createNTPDateCommand();
            // reset rate-limiting status
            gotRateLimiting = false;
        }
        runConfig = newRunConfig;

        long queryTime1 = 0;
        long queryTime2 = 0;
        long queryTime = 0;
        TimeState timeState = TimeState.UNKNOWN;
        LeapState leapState = LeapState.UNKNOWN;
        long startTime = System.nanoTime();

        // Only query if we have a proper config
        if (!runConfig.isOriginal() || !appConfig.isSignServerManagedConfig()) {
            if (!runConfig.isDisabled() && !gotRateLimiting) {
                // Query NTP
                final NTPDateResult result = queryTask();
                queryTime1 = TimeUnit.NANOSECONDS.toMillis(Math.abs(System.nanoTime()) - Math.abs(startTime));
                long startTime2 = System.nanoTime();
                final NTPQResult queryResult = leapSecondQueryTask();
                queryTime2 = TimeUnit.NANOSECONDS.toMillis(Math.abs(System.nanoTime()) - Math.abs(startTime2));
                queryTime = queryTime1 + queryTime2;

                // Determine the results
                timeState = timeTask(result, firstQuery);
                leapState = leapTask(queryResult);
                firstQuery = false;
            }
        }

        // Report results
        final long reportBaseTime = currentTime + queryTime;
        lastUpdated = reportBaseTime;
        ReportState reportState = reportTask(timeState, leapState, reportBaseTime);
        final long reportTime = TimeUnit.NANOSECONDS.toMillis(Math.abs(System.nanoTime()) - Math.abs(startTime)) - queryTime;

        // Check total runtime
        if (!runConfig.isOriginal() || !appConfig.isSignServerManagedConfig()) {
            final long runTime = queryTime + reportTime;
            if (runTime > runConfig.getWarnRunTime() && reportState.equals(ReportState.REPORTED)) {
                reportState = ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT;
                if (!ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT.equals(oldReportState)) {
                    logError("Monitoring took too long to execute: " + runTime + " (" + queryTime1 + "+" + queryTime2 + "+" + reportTime + ") > " + runConfig.getWarnRunTime());
                }
            }
        }

        if (TimeState.INSYNC.equals(timeState) || TimeState.SOON_OUT_OF_SYNC.equals(timeState)) {
            lastTrustedTime = currentTime;
        }

        // Log time status
        if (!timeState.equals(oldTimeState) || !leapState.equals(oldLeapState) || !reportState.equals(oldReportState)) {
            logInfo("State changed to: " + timeState + "," + reportState + "," + leapState.name());

            // If state changes from INSYNC or SOON_OUT_OF_SYNC to either OUT_OF_SYNC or UNKNOWN 
            // we should log the last time we were sure about the time
            if ((TimeState.OUT_OF_SYNC.equals(timeState) || TimeState.UNKNOWN.equals(timeState)) && (TimeState.INSYNC.equals(oldTimeState) || TimeState.SOON_OUT_OF_SYNC.equals(oldTimeState))) {
                logInfo("Last trusted time was: " + SDF.format(new Date(lastTrustedTime)));
            }
        }

        // Save state
        oldTimeState = timeState;
        oldReportState = reportState;
        oldLeapState = leapState;

        // Save timings
        oldOffset = offset;
        oldQueryTime1 = queryTime1;
        oldQueryTime2 = queryTime2;
        oldReportTime = reportTime;

        // Log run times
        if (LOG.isTraceEnabled()) {
            LOG.trace(new StringBuilder().append("Times:").append(queryTime1).append(";").append(queryTime2).append(";").append(reportTime).toString());
        }

        // Slow things down
        final long totalRunTime = TimeUnit.NANOSECONDS.toMillis(Math.abs(System.nanoTime()) - Math.abs(startTime));
        final long sleep;
        if (runConfig.isDisabled()) {
            sleep = disabledMinRunTime - totalRunTime;
        } else {
            sleep = runConfig.getMinRunTime() - totalRunTime;
        }

        if (sleep > 0) {
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException ex)  {
                logInfo("Interrupted: " + ex.getMessage());
            }
        }
    }

    protected NTPDateCommand createNTPDateCommand() {
        return new NTPDateCommand(appConfig.getTimeServerNtpdateCommand(), newRunConfig.getTimeServerHost(),
                newRunConfig.getTimeServerSendSamples(), newRunConfig.getTimeServerTimeout());
    }

    protected String createReportBody(boolean insync, LeapState leapState, long expiration, long leapExpiration, long stateExpiration)
            throws UnsupportedEncodingException, IOException {

        final StringWriter out = new StringWriter();
        final Properties report = new Properties();
        report.setProperty(statusName + ".VALUE", String.valueOf(insync));
        report.setProperty(statusName + ".EXPIRATION", String.valueOf(expiration));

        if (leapState != LeapState.UNKNOWN) {
            report.setProperty(statusNameLeapState + ".VALUE", leapState.name());
            report.setProperty(statusNameLeapState + ".EXPIRATION", String.valueOf(leapExpiration));
        }

        // State
        report.setProperty("TIMEMONITOR_STATE.VALUE", getStateLine().toString());
        report.setProperty("TIMEMONITOR_STATE.EXPIRATION", String.valueOf(stateExpiration));

        // Request configuration
        if (appConfig.isSignServerManagedConfig()) {
            report.setProperty("CONFIG", runConfig.getVersion());
        }

        // Post log if it has changed
        if (logChanged) {
            final StringBuilder sb = new StringBuilder();
            final Iterator iterator = logBuffer.iterator();
            while (iterator.hasNext()) {
                sb.append(iterator.next()).append("\n");
            }

            report.setProperty("TIMEMONITOR_LOG.VALUE", sb.toString());
            logChanged = false;
        }

        report.store(out, null);

        final StringBuilder body = new StringBuilder();
        body.append("workerName=").append(workerName).append("&")
                .append("data=").append(URLEncoder.encode(out.toString(), "ISO-8859-1"));
        return body.toString();
    }

    protected void reportInSync(boolean insync, LeapState leapState, long expiration, long leapExpiration, long stateExpiration)
            throws UnsupportedEncodingException, MalformedURLException, IOException {

        final String report = createReportBody(insync, leapState, expiration, leapExpiration, stateExpiration);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Send post to " + processURL + " with body: " + report);
        }

        final byte[] response = postReport(report);

        // Only update the config if the configuration allows it
        if (response != null && response.length > 0 && appConfig.isSignServerManagedConfig()) {
            Properties newProperties = new Properties();
            newProperties.load(new ByteArrayInputStream(response));
            final String newConfigVersion = newProperties.getProperty("CONFIG");
            if (newConfigVersion != null) {
                final LinkedList<String> errors = new LinkedList<>();
                newRunConfig = runConfig.update(newProperties, newConfigVersion, errors);
                if (!errors.isEmpty()) {
                    newRunConfig = runConfig.disable(newConfigVersion);
                    final StringBuilder mess = new StringBuilder();
                    mess.append("Incorrect configuration received: ").append(newConfigVersion).append(", will disable TimeMonitor:\n");
                    for (String error : errors) {
                        mess.append(error).append("\n");
                    }
                    logError(mess.toString());
                }
            }
        }
    }

    protected byte[] postReport(final String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
        final byte[] result;
        InputStream in = null;
        PrintWriter out = null;
        InputStream err = null;
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) processURL.openConnection();
            conn.setRequestMethod("POST");
            conn.setAllowUserInteraction(false);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            out = new PrintWriter(conn.getOutputStream());
            out.print(body);
            out.close();

            if (LOG.isDebugEnabled()) {
                LOG.debug("Response (" + conn.getResponseCode() + "): " + conn.getResponseMessage());
            }

            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                lastReportResponseError = null;

                // Read body
                in = conn.getInputStream();
                byte[] bout = readBody(in, conn.getContentLength()); // Note: Important to read body
                if (LOG.isDebugEnabled()) {
                    final String response = new String(bout);
                    LOG.debug("response: " + response);
                }

                result = bout;
            } else {
                final String reportResponseError = "Unexpected response code from server (" + conn.getResponseCode() + "): " + conn.getResponseMessage();
                if (!reportResponseError.equals(lastReportResponseError)) {
                    logError(reportResponseError);
                    lastReportResponseError = reportResponseError;
                }

                // Read error body
                err = conn.getErrorStream();
                if (err != null) {
                    final byte[] berr = readBody(err, conn.getContentLength()); // Note: Important to read body
                    if (LOG.isDebugEnabled()) {
                        String errResponse = new String(berr);
                        LOG.debug("Error response: " + errResponse);
                    }
                }
                result = null;
            }
        } finally {
            if (out != null) {
                out.close();
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (err != null) {
                try {
                    err.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (conn != null) {
                conn.disconnect();
            }
        }
        return result;
    }

    /**
     * Flag that the thread should stop running after the current round.
     * This method is thread-safe as the variable storing the state is volatile.
     */
    public void stopRunning() {
        continueRun = false;
    }

    /**
     * Checks if the thread has finished.
     * This method is thread-safe as the variable storing the state is volatile.
     * @return True if the thread has finished
     */
    public boolean isFinished() {
        return finished;
    }

    /**
     * Query ntpdate.
     * @return The results (could be null if it could not be obtained)
     */
    protected NTPDateResult queryTask() {
        NTPDateResult result = null;
        try {
            result = (NTPDateResult) ntpDateCommand.execute();
        } catch (IOException ex) {
            if (ex.getMessage() == null || !ex.getMessage().equals(lastCommandErrorMessage)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to execute command", ex);
                }
                lastCommandErrorMessage = ex.getMessage();
                logError("Failed to execute command: " + lastCommandErrorMessage);
            }
        }
        return result;
    }

    /**
     * Query ntpq for leap second status
     * @return the result
     */
    protected NTPQResult leapSecondQueryTask() {
        NTPQResult result = null;

        try {
            result = (NTPQResult) ntpQCommand.execute();
        } catch (IOException ex) {
            if (ex.getMessage() == null || !ex.getMessage().equals(lastCommandErrorMessage)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to execute command", ex);
                }
                lastCommandErrorMessage = ex.getMessage();
                logError("Failed to execute command: " + lastCommandErrorMessage);
            }
        }

        return result;
    }

    /**
     * Get the new time state based on the ntpdate result.
     * @param ntpDate the ntpdate result
     * @param forceLogging indicates that an error should be logged even if the
     * state did not change. This is an exception so we don't miss to log the
     * first error.
     * @return The new timestate
     */
    protected TimeState timeTask(final NTPDateResult ntpDate,
            final boolean forceLogging) {
        final TimeState timeState;
        if (ntpDate == null) {
            timeState = TimeState.UNKNOWN;
        } else if (ntpDate.isRateLimited()) {
            logError("Server responded with a rate-limiting kiss-of-death, stopping until next configuration update");
            timeState = TimeState.UNKNOWN;
            gotRateLimiting = true;
        } else if (ntpDate.getExitCode() != 0 || ntpDate.getStratum() == 0) {
            timeState = TimeState.UNKNOWN;
            if (!TimeState.UNKNOWN.equals(oldTimeState) && (ntpDate.getErrorMessage() == null || !ntpDate.getErrorMessage().equals(lastCommandErrorMessage)) || forceLogging) {
                logError("Command failed (stratum: " + ntpDate.getStratum() + ", exit: " + ntpDate.getExitCode() + "): " + ntpDate.getErrorMessage());
            }
        } else {
            offset = (long) Math.abs(ntpDate.getOffset() * 1000.0);

            if (offset > runConfig.getMaxAcceptedOffset()) {
                timeState = TimeState.OUT_OF_SYNC;
                if (!TimeState.OUT_OF_SYNC.equals(oldTimeState) || forceLogging) {
                    logError("Time out of calibration: offset abs(" + offset + ") > max accepted offset " + runConfig.getMaxAcceptedOffset());
                }
            } else if (offset >= runConfig.getWarnOffset()) {
                timeState = TimeState.SOON_OUT_OF_SYNC;
                if (!TimeState.SOON_OUT_OF_SYNC.equals(oldTimeState) || forceLogging) {
                    logError("Time soon out of calibration: offset abs(" + offset + ") > " + runConfig.getWarnOffset() + " (max accepted offset " + runConfig.getMaxAcceptedOffset() + ")");
                }
            } else {
                timeState = TimeState.INSYNC;
                if (!TimeState.INSYNC.equals(oldTimeState) || forceLogging) {
                    logInfo("Time back in calibration: offset abs(" + offset + ") < max accepted offset " + runConfig.getMaxAcceptedOffset());
                }
            }
        }
        return timeState;
    }

    /**
     * Calculate the leap state transition given old state and new state
     * as reported by the NTP client, including a precaution margin to
     * avoid changing back too early.
     *
     * @param date
     * @param fromLeapState
     * @param newLeapState
     * @return
     */
    protected LeapState calculateLeapStateTransition(final Date date, final LeapState fromLeapState, final LeapState newLeapState) {
        // in case time is close to midnight (UTC) and leap second status
        // changed from POSITIVE/NEGATIVE to NONE/UNKNOWN return the old status
        // to avoid going back to early (will get updated in the next run)

        if ((fromLeapState == LeapState.POSITIVE || fromLeapState == LeapState.NEGATIVE) &&
            (newLeapState == LeapState.NONE || newLeapState == LeapState.UNKNOWN)) {
            final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

            cal.setTime(date);
            final int h = cal.get(Calendar.HOUR_OF_DAY);
            final int m = cal.get(Calendar.MINUTE);

            if ((h == 23 && m == 59) || (h == 0 && m < 1)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Leap second status changed back too early, keep old state a while...");
                }
                return fromLeapState;
            }
        }

        return newLeapState;
    }

    protected LeapState leapTask(final NTPQResult ntpQ) {
        final LeapState result;
        if (ntpQ == null) {
            result = LeapState.UNKNOWN;
        } else {
            result = calculateLeapStateTransition(new Date(), oldLeapState, ntpQ.getLeapState());
        }
        return result;
    }

    protected ReportState reportTask(final TimeState timeState, final LeapState leapState, final long reportBaseTime) {
        ReportState reportState = ReportState.FAILED_TO_REPORT;
        try {
            final boolean insync;
            final long expire;
            final long leapExpire;
            final long stateExpire;

            // If config is managed but hasn't got an update yet use 'disabled' expire times
            // otherwise use the configured expire times
            if (runConfig.isDisabled() || (runConfig.isOriginal() && appConfig.isSignServerManagedConfig()) ) {
                leapExpire = stateExpire = reportBaseTime + DISABLED_STATUS_EXPIRE_TIME;
            } else {
                leapExpire = reportBaseTime + runConfig.getLeapStatusExpireTime();
                stateExpire = reportBaseTime + runConfig.getStatusExpireTime();
            }


            switch (timeState) {
                case SOON_OUT_OF_SYNC:
                case INSYNC: {
                    insync = true;
                    if (runConfig == null || runConfig.isDisabled()) {
                        expire = reportBaseTime + DISABLED_STATUS_EXPIRE_TIME;
                    } else {
                        expire = reportBaseTime + runConfig.getStatusExpireTime();
                    }
                    break;
                }
                case UNKNOWN:
                case OUT_OF_SYNC: 
                default: {
                    insync = false;
                    expire = 0;
                }
            }
            reportInSync(insync, leapState, expire, leapExpire, stateExpire);
            reportState = ReportState.REPORTED;
        } catch (IOException ex) {
            if (ex.getMessage() == null || !ex.getMessage().equals(lastServerErrorMessage)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Failed to update status property", ex);
                }
                lastServerErrorMessage = ex.getMessage();
                logError("Failed to update status property: " + lastServerErrorMessage);
            }
        }
        return reportState;
    }

    /**
     * Reads the complete body from the input stream. If contentLength != -1 it 
     * will try to read contentLength bytes. 
     */
    private byte[] readBody(final InputStream in, final int contentLength) throws IOException {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (in != null ) {
            int n;
            byte[] data = new byte[1024];
            while ((contentLength == -1 || baos.size() < contentLength) && (n = in.read(data, 0, data.length)) != -1) {
                baos.write(data, 0, n);
            }
        }
        return baos.toByteArray();
    }

    /**
     * Constructs the current state.
     * This method is thread-safe as the variables storing the state are all
     * volatile.
     * @return the state
     */
    @Override
    public StringBuilder getStateLine() {
        return getStateLine(lastUpdated, oldTimeState, oldReportState, oldLeapState, runConfig.getVersion(),
                oldOffset,
                oldQueryTime1, oldQueryTime2, oldReportTime);
    }

    protected static StringBuilder getStateLine(long lastUpdated, TimeState timeState, ReportState reportState, LeapState leapState, String configVersion, long offset, long queryTime1, long queryTime2, long reportTime) {
        if (timeState == null) {
            timeState = TimeState.UNKNOWN;
        }
        if (leapState == null) {
            leapState = LeapState.UNKNOWN;
        }
        if (reportState == null) {
            reportState = ReportState.FAILED_TO_REPORT;
        }

        final StringBuilder buff = new StringBuilder();
        buff.append(lastUpdated).append(",")
                .append(timeState).append(",")
                .append(reportState).append(",")
                .append(leapState.name()).append(",")
                .append(configVersion).append(",")
                .append(offset).append(",")
                .append(queryTime1).append(",")
                .append(queryTime2).append(",")
                .append(reportTime);
        return buff;
    }

    /**
     * Log the message at ERROR level both to Log4j and the log buffer.
     * @param message to log
     */
    private void logError(String message) {
        LOG.error(message);
        logBuffer.add(SDF.format(new Date()) + " ERROR " + message);
        logChanged = true;
    }

    /**
     * Log the message at INFO level both to Log4j and the log buffer.
     * @param message to log
     */
    private void logInfo(String message) {
        LOG.info(message);
        logBuffer.add(SDF.format(new Date()) + " INFO  " + message);
        logChanged = true;
    }

}
