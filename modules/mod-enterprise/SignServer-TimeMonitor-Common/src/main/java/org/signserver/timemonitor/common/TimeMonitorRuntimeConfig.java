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
package org.signserver.timemonitor.common;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/**
 * The TimeMonitor configuration.
 *
 * Reads and parses the configuration from a Properties file.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeMonitorRuntimeConfig {

    public static final String PREFIX_TIMESERVER = "TIMESERVER";
    public static final String PREFIX_TIMEMONITOR = "TIMEMONITOR";

    public static final String PROPERTY_TIMESERVER_HOST = "TIMESERVER.HOST";
    public static final String PROPERTY_TIMESERVER_SENDSAMPLES = "TIMESERVER.SENDSAMPLES";
    public static final String PROPERTY_TIMESERVER_TIMEOUT = "TIMESERVER.TIMEOUT";
    public static final String PROPERTY_MAX_ACCEPTED_OFFSET = "TIMEMONITOR.MAXACCEPTEDOFFSET";
    public static final String PROPERTY_WARN_OFFSET = "TIMEMONITOR.WARNOFFSET";
    public static final String PROPERTY_STATUS_EXPIRE_TIME = "TIMEMONITOR.STATUSEXPIRETIME";
    public static final String PROPERTY_LEAPSTATUS_EXPIRE_TIME = "TIMEMONITOR.LEAPSTATUSEXPIRETIME";
    public static final String PROPERTY_MIN_RUN_TIME = "TIMEMONITOR.MINRUNTIME";
    public static final String PROPERTY_WARN_RUN_TIME = "TIMEMONITOR.WARNRUNTIME";

    public static final String PROPERTY_DISABLED = "TIMEMONITOR.DISABLED";
    public static final String PROPERTY_CONFIG = "CONFIG";

    private static final Set<String> REQUIRED_PROPERTY_NAMES = Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(
                PROPERTY_TIMESERVER_HOST,
                PROPERTY_TIMESERVER_SENDSAMPLES,
                PROPERTY_TIMESERVER_TIMEOUT,
                PROPERTY_MAX_ACCEPTED_OFFSET,
                PROPERTY_WARN_OFFSET,
                PROPERTY_STATUS_EXPIRE_TIME,
                PROPERTY_LEAPSTATUS_EXPIRE_TIME,
                PROPERTY_MIN_RUN_TIME,
                PROPERTY_WARN_RUN_TIME
            )));

    private final boolean original;
    private final String version;
    private final boolean disabled;

    private final String timeServerHost;
    private final int timeServerSendSamples;
    private final double timeServerTimeout;

    private final long maxAcceptedOffset;
    private final long warnOffset;
    private final long statusExpireTime;
    private final long leapStatusExpireTime;
    private final long minRunTime;
    private final long warnRunTime;

    public static Collection<String> getPropertyNames() {
        return REQUIRED_PROPERTY_NAMES;
    }

    public TimeMonitorRuntimeConfig() {
        this(true, "0000", true, "", 0, 0, 0, 0, 0, 0, 0, 0);
    }

    public TimeMonitorRuntimeConfig(boolean original, String version, boolean disabled, String timeServerHost, int timeServerSendSamples, double timeServerTimeout, long maxAcceptedOffset, long warnOffset, long statusExpireTime, long leapStatusExpireTime, long minRunTime, long warnRunTime) {
        this.original = original;
        this.version = version;
        this.disabled = disabled;
        this.timeServerHost = timeServerHost;
        this.timeServerSendSamples = timeServerSendSamples;
        this.timeServerTimeout = timeServerTimeout;
        this.maxAcceptedOffset = maxAcceptedOffset;
        this.warnOffset = warnOffset;
        this.statusExpireTime = statusExpireTime;
        this.leapStatusExpireTime = leapStatusExpireTime;
        this.minRunTime = minRunTime;
        this.warnRunTime = warnRunTime;
    }

    /**
     * Loads the TimeMonitor configuration from the given Properties.
     * @param config Properties to load from
     * @param errors list to insert errors found during load in
     * @return the new config object
     * @throws IllegalArgumentException In case required properties were missing 
     * or had incorrect values
     */
    public static TimeMonitorRuntimeConfig load(final Properties config, final List<String> errors) {
        final TimeMonitorRuntimeConfig result;

        // Check that all required properties are available
        if (!config.keySet().containsAll(REQUIRED_PROPERTY_NAMES)) {
            HashSet<Object> missing = new HashSet<Object>(REQUIRED_PROPERTY_NAMES);
            missing.removeAll(config.keySet());
            final String message = "Missing required properties: " + missing.toString();
            errors.add(message);
        }

        String timeServerHost = getPropertyAsString(config, PROPERTY_TIMESERVER_HOST, "");
        int timeServerSendSamples = getPropertyAsInt(config, PROPERTY_TIMESERVER_SENDSAMPLES, 0, errors);
        double timeServerTimeout = getPropertyAsDouble(config, PROPERTY_TIMESERVER_TIMEOUT, 0d, errors);

        long maxAcceptedOffset = getPropertyAsLong(config, PROPERTY_MAX_ACCEPTED_OFFSET, 0l, errors);
        long warnOffset = getPropertyAsLong(config, PROPERTY_WARN_OFFSET, 0l, errors);
        long statusExpireTime = getPropertyAsLong(config, PROPERTY_STATUS_EXPIRE_TIME, 0l, errors);
        long leapStatusExpireTime = getPropertyAsLong(config, PROPERTY_LEAPSTATUS_EXPIRE_TIME, 0l, errors);
        long minRunTime = getPropertyAsLong(config, PROPERTY_MIN_RUN_TIME, 0l, errors);
        long warnRunTime = getPropertyAsLong(config, PROPERTY_WARN_RUN_TIME, 0l, errors);
        boolean disabled = getOptionalPropertyAsBoolean(config, PROPERTY_DISABLED, false, errors);

        result = new TimeMonitorRuntimeConfig(
                    true,
                    "0",
                    disabled,
                    timeServerHost,
                    timeServerSendSamples,
                    timeServerTimeout,
                    maxAcceptedOffset,
                    warnOffset,
                    statusExpireTime,
                    leapStatusExpireTime,
                    minRunTime,
                    warnRunTime
            );

        return result;
    }

    // TODO: Mostly duplicate of load
    public TimeMonitorRuntimeConfig update(final Properties config, String version, final List<String> errors) {
        final TimeMonitorRuntimeConfig result;

        // Check that all required properties are available
        if (!config.keySet().containsAll(REQUIRED_PROPERTY_NAMES)) {
            HashSet<Object> missing = new HashSet<Object>(REQUIRED_PROPERTY_NAMES);
            missing.removeAll(config.keySet());
            errors.add("Missing required properties: " + missing.toString());
        }

        String overriddenTimeServerHost = getPropertyAsString(config, PROPERTY_TIMESERVER_HOST, "");
        int overriddenTimeServerSendSamples = getPropertyAsInt(config, PROPERTY_TIMESERVER_SENDSAMPLES, 0, errors);
        double overriddenTimeServerTimeout = getPropertyAsDouble(config, PROPERTY_TIMESERVER_TIMEOUT, 0d, errors);

        long overriddenMaxAcceptedOffset = getPropertyAsLong(config, PROPERTY_MAX_ACCEPTED_OFFSET, 0l, errors);
        long overriddenWarnOffset = getPropertyAsLong(config, PROPERTY_WARN_OFFSET, 0l, errors);
        long overriddenStatusExpireTime = getPropertyAsLong(config, PROPERTY_STATUS_EXPIRE_TIME, 0l, errors);
        long overriddenLeapStatusExpireTime = getPropertyAsLong(config, PROPERTY_LEAPSTATUS_EXPIRE_TIME, 0l, errors);
        long overriddenMinRunTime = getPropertyAsLong(config, PROPERTY_MIN_RUN_TIME, 0l, errors);
        long overriddenWarnRunTime = getPropertyAsLong(config, PROPERTY_WARN_RUN_TIME, 0l, errors);
        boolean overriddenDisabled = getOptionalPropertyAsBoolean(config, PROPERTY_DISABLED, false, errors);

        result = new TimeMonitorRuntimeConfig(
                false,
                version,
                overriddenDisabled,
                overriddenTimeServerHost,
                overriddenTimeServerSendSamples,
                overriddenTimeServerTimeout,
                overriddenMaxAcceptedOffset,
                overriddenWarnOffset,
                overriddenStatusExpireTime,
                overriddenLeapStatusExpireTime,
                overriddenMinRunTime,
                overriddenWarnRunTime
        );

        return result;
    }

    public TimeMonitorRuntimeConfig disable(final String newVersion) {
        return new TimeMonitorRuntimeConfig(
                false,
                newVersion,
                true,
                timeServerHost,
                timeServerSendSamples,
                timeServerTimeout,
                maxAcceptedOffset,
                warnOffset,
                statusExpireTime,
                leapStatusExpireTime,
                minRunTime,
                warnRunTime
        );
    }

    private static String getPropertyAsString(final Properties config, final String property, final String errorValue) {
        String value = config.getProperty(property);
        return value == null ? errorValue : value;
    }

    private static long getPropertyAsLong(final Properties config, final String property, final long errorValue, final List<String> errors) {
        long result;
        try {
            String value = config.getProperty(property);
            if (value == null) {
                result = errorValue;
            } else {
                result = Integer.parseInt(value);
            }
        } catch (NumberFormatException ex) {
            final String message = "Invalid value for property " + property + ": " + ex.getLocalizedMessage();
            errors.add(message);
            result = errorValue;
        }
        return result;
    }

    private static boolean getOptionalPropertyAsBoolean(final Properties config, final String property, final boolean defaultValue, final List<String> errors) {
        boolean result;
        final String value = config.getProperty(property);
        if (value == null) {
            result = defaultValue;
        } else if ("true".equalsIgnoreCase(value)) {
            result = true;
        } else if ("false".equalsIgnoreCase(value)) {
            result = false;
        } else {
            errors.add("Invalid value for property " + property + ": " + value);
            result = defaultValue;
        }
        return result;
    }

    private static double getPropertyAsDouble(final Properties config, final String property, final double errorValue, final List<String> errors) {
        double result;
        try {
            final String value = config.getProperty(property);
            if (value == null) {
                result = errorValue;
            } else {
                result = Double.parseDouble(value);
            }
        } catch (NumberFormatException ex) {
            errors.add("Invalid value for property " + property + ": " + ex.getLocalizedMessage());
            return errorValue;
        }
        return result;
    }

    private static int getPropertyAsInt(final Properties config, final String property, final int errorValue, final List<String> errors) {
        int result;
        try {
            final String value = config.getProperty(property);
            if (value == null) {
                result = errorValue;
            } else {
                result = Integer.parseInt(value);
            }
        } catch (NumberFormatException ex) {
            errors.add("Invalid value for property " + property + ": " + ex.getLocalizedMessage());
            return errorValue;
        }
        return result;
    }

    /**
     * @return True if this is an original configuration (created using 'load'
     * or false if it is derived from a call to 'update').
     */
    public boolean isOriginal() {
        return original;
    }

    public String getVersion() {
        return version;
    }

    public boolean isDisabled() {
        return disabled;
    }

    /**
     * @return Hostname or IP address of the time server that should be queried.
     */
    public String getTimeServerHost() {
        return timeServerHost;
    }

    /**
     * @return Number of samples (NTP packets) to send to the time server.
     */
    public int getTimeServerSendSamples() {
        return timeServerSendSamples;
    }

    /**
     * @return Maximum wait time for response from the time server.
     */
    public double getTimeServerTimeout() {
        return timeServerTimeout;
    }

    /**
     * @return Maximum difference (in milliseconds) for the local time
     * as compared to the time server for the time status to still be INSYNC.
     */
    public long getMaxAcceptedOffset() {
        return maxAcceptedOffset;
    }

    /**
     * @return Difference (in milliseconds) for the local time as
     * compared to the time server when the state changes to
     * SOON_OUT_OF_SYNC.
     */
    public long getWarnOffset() {
        return warnOffset;
    }

    /**
     * @return Expire time (in milliseconds) to set when publishing the status 
     * to SignServer.
     */
    public long getStatusExpireTime() {
        return statusExpireTime;
    }

    /**
     * @return Expire time (in milliseconds) to set when publishing the leap second status
     */
    public long getLeapStatusExpireTime() {
        return leapStatusExpireTime;
    }

    /**
     * @return Minimum time for one round by the TimeMonitor. If checking the 
     * time and publishing the status is performed in shorter time than this 
     * value (in milliseconds), TimeMonitor will sleep for the remaining time.
     */
    public long getMinRunTime() {
        return minRunTime;
    }

    /**
     * @return If performing one round of checking the time and 
     * publishing the status takes longer time then this (in milliseconds) 
     * change the report state to REPORTED_BUT_EXPIRE_TIME_SHORT.
     */
    public long getWarnRunTime() {
        return warnRunTime;
    }

}
