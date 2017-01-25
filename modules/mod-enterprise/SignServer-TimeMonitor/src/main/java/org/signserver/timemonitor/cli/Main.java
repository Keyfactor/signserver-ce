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
package org.signserver.timemonitor.cli;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;
import org.signserver.timemonitor.core.TimeMonitorAppConfig;
import org.signserver.timemonitor.core.TimeMonitorRunnable;
import org.signserver.timemonitor.status.StateWebServer;

/**
 * The main class of the TimeMonitor application.
 *
 * @author Markus Kilås
 * @version $Id: Main.java 5918 2013-09-27 14:50:57Z anatom $
 */
@SuppressWarnings("PMD.DoNotUseThreads") // This is not a JEE webapp
public class Main {

    /**
     * Starts the TimeMonitor application.
     *
     * @param args the command line arguments
     * @throws java.io.IOException
     */
    public static void main(String[] args) throws IOException {

        // Use our custom log4j configuration file name
        final URL conf = Main.class.getResource("/timemonitor-log4j.properties");
        if (conf != null) {
            System.out.println("Loading log configuration from " + conf);
            PropertyConfigurator.configure(conf);
        } else {
            System.err.println("No timemonitor-log4j.properties");
        }
        final Logger LOG = Logger.getLogger(TimeMonitorRunnable.class);

        if (args.length != 0) {
            System.err.println("USAGE: timemonitor");
            System.exit(1);
        }

        // Load configuration
        Properties origProperties = new Properties();
        final InputStream in = TimeMonitorRunnable.class.getResourceAsStream("/timemonitor.properties");
        if (in == null) {
            System.err.println("Error: No timemonitor.properties on the classpath!");
            System.exit(1);
        }
        origProperties.load(in);

        // Make all properties upper case from now on
        // This makes it easier to support SignServer where all properties are
        // upper case already. For backwards compatibility we still need to
        // support mixed case properties in timemonitor.properties.
        Properties properties = new Properties();
        for (String origKey : origProperties.stringPropertyNames()) {
            properties.setProperty(origKey.toUpperCase(Locale.ENGLISH),
                    origProperties.getProperty(origKey));
        }
        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(properties);
        final TimeMonitorRuntimeConfig runConfig;
        if (appConfig.isSignServerManagedConfig()) {
            runConfig = new TimeMonitorRuntimeConfig();
            if (!Collections.disjoint(TimeMonitorRuntimeConfig.getPropertyNames(), properties.keySet())) {
                throw new IllegalArgumentException("The following properties are not allowed when " + TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG + " = true: " + TimeMonitorRuntimeConfig.getPropertyNames());
            }
        } else {
            final LinkedList<String> errors = new LinkedList<>();
            runConfig = TimeMonitorRuntimeConfig.load(properties, errors);
            if (!errors.isEmpty()) {
                System.err.println("Configuration errors:");
                for (String error : errors) {
                    System.err.println(error);
                }
                System.exit(1);
            }
        }

        final TimeMonitorRunnable timeMonitorTask = new TimeMonitorRunnable(appConfig, runConfig);

        // State web
        final StateWebServer stateWeb;
        if (appConfig.isStatuswebEnabled()) {
            stateWeb = new StateWebServer(timeMonitorTask, appConfig.getStatuswebBindAddress(), appConfig.getStatuswebPort(), appConfig.getStatuswebBacklog(), appConfig.getStatuswebThreads());
        } else {
            stateWeb = null;
        }

        // Start state web
        if (stateWeb != null) {
            stateWeb.start();
        }

        // Install shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread("Shutdown TimeMonitor") {
            @Override
            public void run() {
                LOG.info("TimeMonitor will shutdown in a moment");
                timeMonitorTask.stopRunning();

                // Give the other thread some time to finish
                try {
                    for (int i = 0; i < 2 && !timeMonitorTask.isFinished(); i++) {
                        Thread.sleep(1000);
                    }
                } catch (InterruptedException ex) {
                    LOG.info("Interrupted");
                }
            }
        });

        // Install uncaught exception handler
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(final Thread t, final Throwable e) {
                LOG.error("An uncaught exception occured in thread " + t, e);
                System.exit(1);
            }
        });

        // Start the monitor
        timeMonitorTask.run();
    }
}
