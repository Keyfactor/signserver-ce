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

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * The static TimeMonitor configuration.
 *
 * Reads and parses the configuration from a Properties file.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorConfig.java 4518 2012-12-06 10:24:14Z marcus $
 */
public class TimeMonitorAppConfig {

    public static final String PROPERTY_TIMESERVER_NTPDATECOMMAND = "TIMESERVER.NTPDATECOMMAND";
    public static final String PROPERTY_TIMESERVER_NTPQCOMMAND = "TIMESERVER.NTPQCOMMAND";

    public static final String PROPERTY_STATEWEB_ENABLED = "TIMEMONITOR.STATEWEB.ENABLED";
    public static final String PROPERTY_STATEWEB_BINDADDRESS = "TIMEMONITOR.STATEWEB.BINDADDRESS";
    public static final String PROPERTY_STATEWEB_PORT = "TIMEMONITOR.STATEWEB.PORT";
    public static final String PROPERTY_STATEWEB_BACKLOG = "TIMEMONITOR.STATEWEB.BACKLOG";
    public static final String PROPERTY_STATEWEB_THREADS = "TIMEMONITOR.STATEWEB.THREADS";

    public static final String PROPERTY_SIGNSERVER_PROCESS_URL = "SIGNSERVER.PROCESS.URL";
    public static final String PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME = "SIGNSERVER.STATUSPROPERTIESWORKER.NAME";
    public static final String PROPERTY_SIGNSERVER_STATUSPROPERTY_NAME = "SIGNSERVER.STATUSPROPERTY.NAME";
    public static final String PROPERTY_SIGNSERVER_LEAPSTATUSPROPERTY_NAME = "SIGNSERVER.LEAPSTATUSPROPERTY.NAME";
    public static final String PROPERTY_SIGNSERVER_MANAGEDCONFIG = "SIGNSERVER.MANAGEDCONFIG";

    private static final boolean DEFAULT_SIGNSERVER_MANAGEDCONFIG = false;

    private static final Set<String> REQUIRED_PROPERTY_NAMES = Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList(
                PROPERTY_TIMESERVER_NTPDATECOMMAND,
                PROPERTY_TIMESERVER_NTPQCOMMAND,

                PROPERTY_STATEWEB_ENABLED,
                PROPERTY_STATEWEB_BINDADDRESS,
                PROPERTY_STATEWEB_PORT,
                PROPERTY_STATEWEB_BACKLOG,
                PROPERTY_STATEWEB_THREADS,

                PROPERTY_SIGNSERVER_PROCESS_URL,
                PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME,
                PROPERTY_SIGNSERVER_STATUSPROPERTY_NAME,
                PROPERTY_SIGNSERVER_LEAPSTATUSPROPERTY_NAME
            )));

    private final String timeServerNtpdateCommand;
    private final String timeServerNtpqCommand;

    private final boolean statuswebEnabled;
    private final InetAddress statuswebBindAddress;
    private final int statuswebPort;
    private final int statuswebBacklog;
    private final int statuswebThreads;

    private final URL signServerProcessUrl;
    private final String signServerStatusPropertiesWorkerName;
    private final String signServerStatusPropertyName;
    private final String signServerStatusPropertyNameLeapState;
    private final boolean signServerManagedConfig;

    public TimeMonitorAppConfig(String timeServerNtpdateCommand, String timeServerNtpqCommand, boolean statuswebEnabled, InetAddress statuswebBindAddress, int statuswebPort, int statuswebBacklog, int statuswebThreads, URL signServerProcessUrl, String signServerStatusPropertiesWorkerName, String signServerStatusPropertyName, String signServerStatusPropertyNameLeapState, boolean signServerManagedConfig) {
        this.timeServerNtpdateCommand = timeServerNtpdateCommand;
        this.timeServerNtpqCommand = timeServerNtpqCommand;
        this.statuswebEnabled = statuswebEnabled;
        this.statuswebBindAddress = statuswebBindAddress;
        this.statuswebPort = statuswebPort;
        this.statuswebBacklog = statuswebBacklog;
        this.statuswebThreads = statuswebThreads;
        this.signServerProcessUrl = signServerProcessUrl;
        this.signServerStatusPropertiesWorkerName = signServerStatusPropertiesWorkerName;
        this.signServerStatusPropertyName = signServerStatusPropertyName;
        this.signServerStatusPropertyNameLeapState = signServerStatusPropertyNameLeapState;
        this.signServerManagedConfig = signServerManagedConfig;
    }

    /**
     * Loads the TimeMonitor configuration from the given Properties.
     * @param config Properties to load from
     * @return the new config object
     * @throws IllegalArgumentException In case required properties were missing 
     * or had incorrect values
     */
    public static TimeMonitorAppConfig load(final Properties config) throws IllegalArgumentException {
        // Check that all required properties are available
        if (!config.keySet().containsAll(REQUIRED_PROPERTY_NAMES)) {
            HashSet<Object> missing = new HashSet<Object>(REQUIRED_PROPERTY_NAMES);
            missing.removeAll(config.keySet());
            throw new IllegalArgumentException("Missing required properties: " + missing.toString());
        }

        final TimeMonitorAppConfig result;
        String timeServerNtpdateCommand = config.getProperty(PROPERTY_TIMESERVER_NTPDATECOMMAND);
        String timeServerNtpqCommand = config.getProperty(PROPERTY_TIMESERVER_NTPQCOMMAND);
        final String url = config.getProperty(PROPERTY_SIGNSERVER_PROCESS_URL);
        URL signServerProcessUrl;
        try {
            signServerProcessUrl = new URL(url);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Illegal URL value for property: " + PROPERTY_SIGNSERVER_PROCESS_URL, ex);
        }
        String signServerStatusPropertiesWorkerName = config.getProperty(PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME);
        String signServerStatusPropertyName = config.getProperty(PROPERTY_SIGNSERVER_STATUSPROPERTY_NAME);
        String signServerStatusPropertyNameLeapState = config.getProperty(PROPERTY_SIGNSERVER_LEAPSTATUSPROPERTY_NAME);

        boolean statuswebEnabled = getBooleanProperty(config, PROPERTY_STATEWEB_ENABLED);
        InetAddress statuswebBindAddress;
        try {
            statuswebBindAddress = InetAddress.getByName(config.getProperty(PROPERTY_STATEWEB_BINDADDRESS));
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Illegal host name or address for property: " + PROPERTY_STATEWEB_BINDADDRESS + ": " + ex.getLocalizedMessage());
        }
        int statuswebPort = getIntegerProperty(config, PROPERTY_STATEWEB_PORT);
        int statuswebBacklog = getIntegerProperty(config, PROPERTY_STATEWEB_BACKLOG);
        int statuswebThreads = getIntegerProperty(config, PROPERTY_STATEWEB_THREADS);

        boolean signServerManagedConfig = getOptionalBooleanProperty(config, PROPERTY_SIGNSERVER_MANAGEDCONFIG, DEFAULT_SIGNSERVER_MANAGEDCONFIG);

        result = new TimeMonitorAppConfig(
                timeServerNtpdateCommand,
                timeServerNtpqCommand,
                statuswebEnabled,
                statuswebBindAddress,
                statuswebPort,
                statuswebBacklog,
                statuswebThreads,
                signServerProcessUrl,
                signServerStatusPropertiesWorkerName,
                signServerStatusPropertyName,
                signServerStatusPropertyNameLeapState,
                signServerManagedConfig
            );

        return result;
    }

    private static int getIntegerProperty(final Properties config, final String property) throws IllegalArgumentException {
        final int result;
        try {
            result = Integer.parseInt(config.getProperty(property));
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Illegal integer value for property: " + property, ex);
        }
        return result;
    }

    private static boolean getBooleanProperty(final Properties config, final String property) throws IllegalArgumentException {
        final String value = config.getProperty(property);
        final boolean result;
        if (value.trim().equalsIgnoreCase("TRUE")) {
            result = true;
        } else if (value.trim().equalsIgnoreCase("FALSE")) {
            result = false;
        } else {
            throw new IllegalArgumentException("Illegal boolean value for property: " + property);
        }
        return result;
    }
    
    private static boolean getOptionalBooleanProperty(final Properties config, final String property, final boolean defaultValue) throws IllegalArgumentException {
        final String value = config.getProperty(property);
        final boolean result;
        if (value == null) {
            result = defaultValue;
        } else if (value.trim().equalsIgnoreCase("TRUE")) {
            result = true;
        } else if (value.trim().equalsIgnoreCase("FALSE")) {
            result = false;
        } else {
            throw new IllegalArgumentException("Illegal boolean value for property: " + property);
        }
        return result;
    }

    /**
     * @return The ntpdate command executable file name
     */
    public String getTimeServerNtpdateCommand() {
        return timeServerNtpdateCommand;
    }

    public String getTimeServerNtpqCommand() {
        return timeServerNtpqCommand;
    }

    /**
     * @return URL to the SignServer process that will handle the status update.
     */
    public URL getSignServerProcessUrl() {
        return signServerProcessUrl;
    }

    /**
     * @return Name of the StatusPropertiesWorker that will handle the status 
     * update.
     */
    public String getSignServerStatusPropertiesWorkerName() {
        return signServerStatusPropertiesWorkerName;
    }

    /**
     * @return Name of the status property to update.
     */
    public String getSignServerStatusPropertyName() {
        return signServerStatusPropertyName;
    }

    /**
     * @return Name of the status property to update for leap second state.
     */
    public String getSignServerLeapStatusPropertyName() {
        return signServerStatusPropertyNameLeapState;
    }

    /**
     * @return If the state web server (Health check).
     */
    public boolean isStatuswebEnabled() {
        return statuswebEnabled;
    }

    /**
     * @return IP address the server should bind to.
     */
    public InetAddress getStatuswebBindAddress() {
        return statuswebBindAddress;
    }

    /**
     * @return TCP port to offer state information (HTTP) on.
     */
    public int getStatuswebPort() {
        return statuswebPort;
    }

    /**
     * @return Maximum number of queued incoming connections to allow.
     */
    public int getStatuswebBacklog() {
        return statuswebBacklog;
    }

    /**
     * @return Number of threads in the thread pool handling incoming 
     * connections.
     */
    public int getStatuswebThreads() {
        return statuswebThreads;
    }

    public boolean isSignServerManagedConfig() {
        return signServerManagedConfig;
    }

}
