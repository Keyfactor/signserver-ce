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
package org.signserver.test.performance.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.test.performance.FailureCallback;
import org.signserver.test.performance.WorkerThread;

/**
 * Performance test tool
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class Main {
    /** Logger for this class */
    private static Logger LOG = Logger.getLogger(Main.class);

    private static final String TEST_SUITE = "testsuite";
    private static final String TIME_LIMIT = "timelimit";
    private static final Options OPTIONS;
    
    private static final String NL = System.getProperty("line.separator");
    private static final String COMMAND = "stresstest";
    
    private static int exitCode;
    
    private enum TestSuites {
        TimeStamp1,
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(TEST_SUITE, true, "Test suite to run. Any of " + Arrays.asList(TestSuites.values()) + ".");
        OPTIONS.addOption(TIME_LIMIT, true, "Optional. Only run for the specified time (in milliseconds).");
    }

    private static void printUsage() {
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
                .append("Sample usages:").append(NL)
                .append("a) ").append(COMMAND).append(" -testsuite TimeStamp1").append(NL);
                
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        PrintWriter pw = new PrintWriter(bout);
        formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, COMMAND + " <options>", "Random testing tool", OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        pw.close();
        LOG.info(bout.toString());
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws RemoteException, InvalidWorkerIdException {
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("(Debug logging is enabled)");
            }
            
            final CommandLine commandLine = new GnuParser().parse(OPTIONS, args);

            // Test suite
            final TestSuites ts;
            if (commandLine.hasOption(TEST_SUITE)) {
                ts = TestSuites.valueOf(commandLine.getOptionValue(TEST_SUITE));
            } else {
                throw new ParseException("Missing option: -" + TEST_SUITE);
            }
            
            // Time limit
            final long limitedTime;
            if (commandLine.hasOption(TIME_LIMIT)) {
                limitedTime = Long.parseLong(commandLine.getOptionValue(TIME_LIMIT));
            } else {
                limitedTime = -1;
            }
  
            final LinkedList<WorkerThread> threads = new LinkedList<WorkerThread>();
            final FailureCallback callback = new FailureCallback() {

                @Override
                public void failed(WorkerThread thread, String message) {
                    // Stop
                    for (WorkerThread w : threads) {
                        w.stopIt();
                    }
                    
                    // Wait until all stoped
                    try {
                        for (WorkerThread w : threads) {
                            w.join(1000);
                        }
                    } catch (InterruptedException ex) {
                        LOG.error("Interrupted: " + ex.getMessage());
                    }
                    
                    // Print message
                    LOG.error(thread + ": " + message);
                    exitCode = -1;
                }
            };
            Thread.UncaughtExceptionHandler handler = new Thread.UncaughtExceptionHandler() {

                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    LOG.error("Uncaught exception from t", e);
                    callback.failed((WorkerThread) t, "Uncaught exception: " + e.getMessage());
                }
            };

            try {
                switch (ts) {
                case TimeStamp1:
                    runTimeStamp1(threads);
                    break;
                default:
                    throw new Exception("Unsupported test suite");
                }
                
                // Wait 1 second to start
                Thread.sleep(1000);
            
                // Start all threads
                for (WorkerThread w : threads) {
                    w.setUncaughtExceptionHandler(handler);
                    w.start();
                }

                // If time limited
                if (limitedTime > 0) {
                    try {
                        Thread.sleep(limitedTime);
                    } catch (InterruptedException ex) {
                        LOG.error("Interrupted: " + ex.getMessage());
                    }
                    // Stop all threads
                    for (WorkerThread w : threads) {
                        w.stopIt();
                    }
                }
            

                // Wait until all stopped
                try {
                    for (WorkerThread w : threads) {
                        w.join();
                        LOG.info(w + ": Operations performed: " + w.getOperationsPerformed());
                    }
                } catch (InterruptedException ex) {
                    LOG.error("Interrupted: " + ex.getMessage());
                }
            
            } catch (Exception ex) {
                LOG.error("Failed: " + ex.getMessage(), ex);
                exitCode = -1;
            }

            System.exit(exitCode);
        } catch (ParseException ex) {
            LOG.error("Parse error: " + ex.getMessage());
            printUsage();
            System.exit(-2);
        }
    }
    
    private static void runTimeStamp1(final List<WorkerThread> threads) throws Exception {
        
    }
}
