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

import java.io.*;
import java.rmi.RemoteException;
import java.util.*;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.test.performance.FailureCallback;
import org.signserver.test.performance.WorkerThread;
import org.signserver.test.performance.impl.DocumentSignerThread;
import org.signserver.test.performance.impl.TimeStampThread;

/**
 * Performance test tool.
 *
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class Main {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(Main.class);

    private static final String TEST_SUITE = "testsuite";
    private static final String TIME_LIMIT = "timelimit";
    private static final String THREADS = "threads";
    private static final String TSA_URL = "tsaurl";
    private static final String PROCESS_URL = "processurl";
    private static final String WORKER_URL = "workerurl";
    private static final String WORKER_NAME_OR_ID = "worker";
    private static final String MAX_WAIT_TIME = "maxwaittime";
    private static final String WARMUP_TIME = "warmuptime";
    private static final String STAT_OUTPUT_DIR = "statoutputdir";
    private static final String INFILE = "infile";
    private static final String DATA = "data";
    private static final Options OPTIONS;
    private static final String USERPREFIX = "userprefix";
    private static final String USERSUFFIXMIN = "usersuffixmin";
    private static final String USERSUFFIXMAX = "usersuffixmax";

    private static final String NL = System.getProperty("line.separator");
    private static final String COMMAND = "stresstest";

    private static final int DEFUALT_MAX_WAIT_TIME = 100;

    private static int exitCode;
    private static long startTime;
    private static long warmupTime;

    private static File infile;
    private static byte[] bytes;

    private static String userPrefix;
    private static Integer usersuffixMin;
    private static Integer usersuffixMax;

    private enum TestSuites {
        TimeStamp1,
        TimeStamp2,
        DocumentSigner1,
        DocumentValidator1,
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(TEST_SUITE, true, "Test suite to run. Any of " + Arrays.asList(TestSuites.values()) + ".");
        OPTIONS.addOption(TIME_LIMIT, true, "Optional. Only run for the specified time (in milliseconds).");
        OPTIONS.addOption(THREADS, true, "Number of threads requesting time stamps.");
        OPTIONS.addOption(TSA_URL, true, "URL to timestamp worker to use.");
        OPTIONS.addOption(PROCESS_URL, true, "URL to process servlet (for the DocumentSigner/Validator1 test suites).");
        OPTIONS.addOption(WORKER_URL, true, "URL to worker servlet (for the DocumentSigner/Validator1 test suites).");
        OPTIONS.addOption(WORKER_NAME_OR_ID, true, "Worker name or ID to use (with the DocumentSigner/Validator1 test suites).");
        OPTIONS.addOption(MAX_WAIT_TIME, true, "Maximum number of milliseconds for a thread to wait until issuing the next time stamp. Default=100");
        OPTIONS.addOption(WARMUP_TIME, true,
                "Don't count number of signings and response times until after this time (in milliseconds). Default=0 (no warmup time).");
        OPTIONS.addOption(STAT_OUTPUT_DIR, true,
                "Optional. Directory to output statistics to. If set, each thread creates a file in this directory to output its response times to. The directory must exist.");
        OPTIONS.addOption(INFILE, true, "Input file used for DocumentSigner/Validator1 testsuites.");
        OPTIONS.addOption(DATA, true, "Input data to be used with the DocumentSigner/Validator1 testsuites using an XMLSigner.");
        OPTIONS.addOption(USERPREFIX, true, "Prefix for usernames.");
        OPTIONS.addOption(USERSUFFIXMIN, true, "Lowest suffix for usernames in form of an integer value (inclusive).");
        OPTIONS.addOption(USERSUFFIXMAX, true, "Highest suffix for usernames in form of an integer value (inclusive).");
    }

    /**
     * Print usage message.
     */
    private static void printUsage() {
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
                .append("Sample usages:").append(NL)
                .append("a) ").append(COMMAND)
                .append(" -testsuite TimeStamp2 -threads 4 -tsaurl http://localhost:8080/signserver/tsa?workerId=1").append(NL)
                .append("b) ").append(COMMAND)
                .append(" -testsuite TimeStamp1 -threads 4 -maxwaittime 100 -statoutputdir ./statistics/ -tsaurl http://localhost:8080/signserver/tsa?workerId=1").append(NL)
                .append("c) ").append(COMMAND)
                .append(" -testsuite DocumentSigner1 -threads 4 -processurl http://localhost:8080/signserver/process -worker PDFSigner -infile test.pdf").append(NL)
                .append("d) ").append(COMMAND)
                .append(" -testsuite DocumentSigner1 -threads 4 -processurl http://localhost:8080/signserver/process -worker XMLSigner -data \"<root/>\"").append(NL)
                .append("e) ").append(COMMAND)
                .append(" -testsuite DocumentSigner1 -threads 4 -processurl http://localhost:8080/signserver/process -worker XMLSigner -data \"<root/>\" -userprefix user -usersuffixmin 1 -usersuffixmax 50").append(NL)
                .append("f) ").append(COMMAND)
                .append(" -testsuite DocumentValidator1 -threads 4 -processurl http://localhost:8080/signserver/process -worker DemoXMLValidator -infile signed.xml").append(NL);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        try (PrintWriter pw = new PrintWriter(bout)) {
            formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, COMMAND + " <options>", "Performance testing tool", OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        }
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

            final int numThreads;
            if (commandLine.hasOption(THREADS)) {
                numThreads = Integer.parseInt(commandLine.getOptionValue(THREADS));
            } else {
                throw new ParseException("Missing option: -" + THREADS);
            }

            final int maxWaitTime;
            if (commandLine.hasOption(MAX_WAIT_TIME)) {
                maxWaitTime = Integer.parseInt(commandLine.getOptionValue(MAX_WAIT_TIME));
            } else {
                maxWaitTime = DEFUALT_MAX_WAIT_TIME;
            }

            final String url;
            boolean useWorkerServlet = false;
            if (commandLine.hasOption(TSA_URL)) {
                if (!ts.name().startsWith("TimeStamp")) {
                    throw new ParseException("Option " + TSA_URL + " can only be used with the TimeStamp test suites.");
                }
                url = commandLine.getOptionValue(TSA_URL);
            } else if (commandLine.hasOption(PROCESS_URL)) {
                if (!ts.equals(TestSuites.DocumentSigner1) && !ts.equals(TestSuites.DocumentValidator1)) {
                    throw new ParseException("Option " + PROCESS_URL + " can only be used with the " +
                            TestSuites.DocumentSigner1.toString() + " or " + TestSuites.DocumentValidator1.toString() + " test suites.");
                }
                url = commandLine.getOptionValue(PROCESS_URL);
                useWorkerServlet = false;
            } else if (commandLine.hasOption(WORKER_URL)) {
                if (!ts.equals(TestSuites.DocumentSigner1)) {
                    throw new ParseException("Option " + WORKER_URL + " can only be used with the " +
                            TestSuites.DocumentSigner1.toString() + " or " + TestSuites.DocumentValidator1.toString() + " test suites.");
                }
                url = commandLine.getOptionValue(WORKER_URL);
                useWorkerServlet = true;
            } else {
                if (ts.equals(TestSuites.TimeStamp1)) {
                    throw new ParseException("Missing option: -" + TSA_URL);
                } else {
                    throw new ParseException("Missing option: -" + PROCESS_URL);
                }
            }

            String workerNameOrId = null;
            if (commandLine.hasOption(WORKER_NAME_OR_ID)) {
                workerNameOrId = commandLine.getOptionValue(WORKER_NAME_OR_ID);
            } else if (ts.equals(TestSuites.DocumentSigner1)) {
                throw new ParseException("Must specify worker name or ID.");
            }

            if (commandLine.hasOption(INFILE)) {
                final String file = commandLine.getOptionValue(INFILE);
                infile = new File(file);
            } else if (commandLine.hasOption(DATA)) {
                bytes = commandLine.getOptionValue(DATA).getBytes();
            } else if (ts.equals(TestSuites.DocumentSigner1)) {
                throw new ParseException("Must specify an input file.");
            }

            if (commandLine.hasOption(WARMUP_TIME)) {
                warmupTime = Long.parseLong(commandLine.getOptionValue(WARMUP_TIME));
            } else {
                warmupTime = 0;
            }

            // Time limit
            final File statFolder;
            if (commandLine.hasOption(STAT_OUTPUT_DIR)) {
                statFolder = new File(commandLine.getOptionValue(STAT_OUTPUT_DIR));
                if (!statFolder.exists() || !statFolder.isDirectory()) {
                    throw new ParseException("Option -" + STAT_OUTPUT_DIR + " must be an existing directory");
                }
            } else {
                statFolder = null;
            }

            // Support for sending requests with (optionally random) username specified
            userPrefix = commandLine.getOptionValue(USERPREFIX, null);
            final String userSuffixMinValue = commandLine.getOptionValue(USERSUFFIXMIN, null);
            final String userSuffixMaxValue = commandLine.getOptionValue(USERSUFFIXMAX, null);
            final String userNameDescription;
            if (userPrefix == null) {
                if (userSuffixMinValue != null || userSuffixMaxValue != null) {
                    throw new ParseException(USERSUFFIXMIN + " and " + USERSUFFIXMAX + " requires a " + USERPREFIX + " option");
                }
                userNameDescription = "n/a";
            } else {
                if ((userSuffixMinValue == null && userSuffixMaxValue != null)
                        || (userSuffixMinValue != null && userSuffixMaxValue == null)) {
                    throw new ParseException("Specify either both or none of " + USERSUFFIXMIN + " and " + USERSUFFIXMAX);
                } else {
                    if (userSuffixMinValue != null) {
                        usersuffixMin = Integer.parseInt(userSuffixMinValue);
                        usersuffixMax = Integer.parseInt(userSuffixMaxValue);
                        userNameDescription = "[" + userPrefix + usersuffixMin + ", " + userPrefix + usersuffixMax + "]";
                    } else {
                        userNameDescription = userPrefix;
                    }
                }
            }

            // Print info
            LOG.info(String.format(
                  "-- Configuration -----------------------------------------------------------%n"
                + "   Start time:              %s%n"
                + "   Test suite:              %s%n"
                + "   Threads:                 %10d%n"
                + "   Warm up time:            %10d ms%n"
                + "   Max wait time:           %10d ms%n"
                + "   Time limit:              %10d ms%n"
                + "   URL:                     %s%n"
                + "   Username(s):             %s%n"
                + "   Output statistics:       %s%n"
                + "-------------------------------------------------------------------------------%n", new Date(), ts.name(), numThreads, warmupTime, maxWaitTime, limitedTime, url, userNameDescription, statFolder == null ? "no" : statFolder.getAbsolutePath()));

            final LinkedList<WorkerThread> threads = new LinkedList<>();
            final FailureCallback callback = new FailureCallback() {

                @Override
                public void failed(WorkerThread thread, String message) {
                    for (WorkerThread w : threads) {
                        w.stopIt();
                    }

                    // Print message
                    LOG.error("   " + message);
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

            Thread shutdownHook = new Thread() {
                @Override
                public void run() {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Shutdown hook called");
                    }
                    shutdown(threads);
                }
            };

            Runtime.getRuntime().addShutdownHook(shutdownHook);

            try {
                switch (ts) {
                case TimeStamp1:
                    timeStamp1(threads, numThreads, callback, url, maxWaitTime, warmupTime, limitedTime, statFolder);
                    break;
                case TimeStamp2:
                    timeStamp2(threads, numThreads, callback, url, maxWaitTime, warmupTime, limitedTime, statFolder);
                    break;
                case DocumentSigner1:
                    documentSigner1(threads, numThreads, callback, url, useWorkerServlet, workerNameOrId, maxWaitTime, warmupTime, limitedTime, statFolder, userPrefix, usersuffixMin, usersuffixMax);
                    break;
                case DocumentValidator1:
                    documentValidator1(threads, numThreads, callback, url, useWorkerServlet, workerNameOrId, maxWaitTime, warmupTime, limitedTime, statFolder, userPrefix, usersuffixMin, usersuffixMax);
                    break;
                default:
                    throw new Exception("Unsupported test suite");
                }

                // Wait 1 second to start
                Thread.sleep(1000);

                // Start all threads
                startTime = System.currentTimeMillis();
                for (WorkerThread w : threads) {
                    w.setUncaughtExceptionHandler(handler);
                    w.start();
                }

                // Wait for the threads to finish
                try {
                    for (WorkerThread w : threads) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Waiting for thread " + w.getName());
                        }
                        w.join();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Thread " + w.getName() + " stopped");
                        }
                    }
                } catch (InterruptedException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Interupted when waiting for thread: " + ex.getMessage());
                    }
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

    /**
     * Shutdown worker threads.
     *
     * @param threads
     */
    private static void shutdown(final List<WorkerThread> threads) {
        for (WorkerThread w : threads) {
            w.stopIt();
        }

        // Total statistics
        long totalRunTime = System.currentTimeMillis() - startTime - warmupTime;
        long totalOperationsPerformed = 0;
        long totalResponseTime = 0;
        double totalAverageResponseTime;
        long totalMaxResponseTime = 0;
        long totalMinResponseTime = Long.MAX_VALUE;

        // Wait until all stopped
        try {
            for (WorkerThread w : threads) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Waiting for thread " + w.getName() + " to finish.");
                }
                w.join();

                final long operationsPerformed = w.getOperationsPerformed();
                final long maxResponseTime = w.getMaxResponseTime();
                final long minResponseTime = w.getMinResponseTime();
                totalOperationsPerformed += operationsPerformed;
                totalResponseTime += w.getResponseTimeSum();

                totalMaxResponseTime = Math.max(totalMaxResponseTime, maxResponseTime);
                totalMinResponseTime = Math.min(totalMinResponseTime, minResponseTime);
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted: " + ex.getMessage());
        }

        if (totalOperationsPerformed > 0) {
            totalAverageResponseTime = totalResponseTime / (double) totalOperationsPerformed;
        } else {
            totalAverageResponseTime = Double.NaN;
        }
        final double tps;
        if (totalRunTime > 1000) {
            tps = totalOperationsPerformed / (totalRunTime / 1000d);
        } else {
            tps = Double.NaN;
        }
        if (totalMinResponseTime == Long.MAX_VALUE) {
            totalMinResponseTime = 0;
        }
        if (totalRunTime < 0) {
            totalRunTime = 0;
        }

        LOG.info(String.format(
                  "%n-- Summary -------------------------------------------------------------------%n"
                + "   End time:                %s%n"
                + "   Operations performed:    %10d%n"
                + "   Minimum response time:   %10d   ms%n"
                + "   Average response time:   %12.1f ms%n"
                + "   Maximum response time:   %10d   ms%n"
                + "   Run time:                %10d   ms%n"
                + "   Transactions per second: %12.1f tps%n"
                + "------------------------------------------------------------------------------%n", new Date(), totalOperationsPerformed, totalMinResponseTime, totalAverageResponseTime, totalMaxResponseTime, totalRunTime, tps));
    }


    /**
     * Initialize the worker thread list for the time stamp test suite.
     *
     * @param threads A list to hold the worker threads. This list is filled by the method.
     * @param numThreads Number of threads to create.
     * @param failureCallback Callback to handle failures.
     * @param url Time stamp signer URL.
     * @param maxWaitTime Maximum waiting time between generated requests.
     * @param warmupTime Warmup time, if set to > 0, will add a warmup period where no stats are collected.
     * @param limitedTime Maximum run time, if set to -1, threads will run until interrupted.
     * @param statFolder Output folder for statistics.
     * @throws Exception
     */
    private static void timeStamp1(final List<WorkerThread> threads, final int numThreads, final FailureCallback failureCallback,
            final String url, int maxWaitTime, long warmupTime, final long limitedTime, final File statFolder) throws Exception {
        final Random random = new Random();
        for (int i = 0; i < numThreads; i++) {
            final String name = "TimeStamp1-" + i;
            final File statFile;
            if (statFolder == null) {
                statFile = null;
            } else {
                statFile = new File(statFolder, name + ".csv");
            }
            threads.add(new TimeStampThread(name, failureCallback, url, maxWaitTime, random.nextInt(),
                    warmupTime, limitedTime, statFile, new byte[20], TSPAlgorithms.SHA1));
        }
    }
    
    /**
     * Initialize the worker thread list for the time stamp test suite using SHA-256.
     *
     * @param threads A list to hold the worker threads. This list is filled by the method.
     * @param numThreads Number of threads to create.
     * @param failureCallback Callback to handle failures.
     * @param url Time stamp signer URL.
     * @param maxWaitTime Maximum waiting time between generated requests.
     * @param warmupTime Warmup time, if set to > 0, will add a warmup period where no stats are collected.
     * @param limitedTime Maximum run time, if set to -1, threads will run until interrupted.
     * @param statFolder Output folder for statistics.
     * @throws Exception
     */
    private static void timeStamp2(final List<WorkerThread> threads, final int numThreads, final FailureCallback failureCallback,
            final String url, int maxWaitTime, long warmupTime, final long limitedTime, final File statFolder) throws Exception {
        final Random random = new Random();
        for (int i = 0; i < numThreads; i++) {
            final String name = "TimeStamp2-" + i;
            final File statFile;
            if (statFolder == null) {
                statFile = null;
            } else {
                statFile = new File(statFolder, name + ".csv");
            }
            threads.add(new TimeStampThread(name, failureCallback, url, maxWaitTime, random.nextInt(),
                    warmupTime, limitedTime, statFile, new byte[32], TSPAlgorithms.SHA256));
        }
    }

    /**
     * Initialize the worker thread list for the document signer test suite.
     *
     * @param threads A list to hold the worker threads. This list is filled by the method.
     * @param numThreads Number of threads to create.
     * @param failureCallback Callback to handle failures.
     * @param url Base process URL.
     * @param workerNameOrId Worker name of worker ID.
     * @param maxWaitTime Maximum waiting time between generated requests.
     * @param warmupTime Warmup time, if set to > 0, will add a warmup period where no stats are collected.
     * @param limitedTime Maximum run time, if set to -1, threads will run until interrupted.
     * @param statFolder Output folder for statistics.
     * @throws Exception
     */
    private static void documentSigner1(final List<WorkerThread> threads, final int numThreads,
            final FailureCallback failureCallback, final String url, final boolean useWorkerServlet,
            final String workerNameOrId, int maxWaitTime, long warmupTime,
            final long limitedTime, final File statFolder,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax) throws Exception {
        documentSignerOrValidator1(threads, numThreads, failureCallback, url, useWorkerServlet, workerNameOrId, maxWaitTime, warmupTime, limitedTime, statFolder, userPrefix, userSuffixMin, userSuffixMax, "DocumentSigner1-", "signDocument");
    }

    /**
     * Initialize the worker thread list for the document validator test suite.
     *
     * @param threads A list to hold the worker threads. This list is filled by the method.
     * @param numThreads Number of threads to create.
     * @param failureCallback Callback to handle failures.
     * @param url Base process URL.
     * @param workerNameOrId Worker name of worker ID.
     * @param maxWaitTime Maximum waiting time between generated requests.
     * @param warmupTime Warmup time, if set to > 0, will add a warmup period where no stats are collected.
     * @param limitedTime Maximum run time, if set to -1, threads will run until interrupted.
     * @param statFolder Output folder for statistics.
     * @throws Exception
     */
    private static void documentValidator1(final List<WorkerThread> threads, final int numThreads,
            final FailureCallback failureCallback, final String url, final boolean useWorkerServlet,
            final String workerNameOrId, int maxWaitTime, long warmupTime,
            final long limitedTime, final File statFolder,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax) throws Exception {
        documentSignerOrValidator1(threads, numThreads, failureCallback, url, useWorkerServlet, workerNameOrId, maxWaitTime, warmupTime, limitedTime, statFolder, userPrefix, userSuffixMin, userSuffixMax, "DocumentValidator1-", "validateDocument");
    }

    private static void documentSignerOrValidator1(final List<WorkerThread> threads, final int numThreads,
            final FailureCallback failureCallback, final String url, final boolean useWorkerServlet,
            final String workerNameOrId, int maxWaitTime, long warmupTime,
            final long limitedTime, final File statFolder,
            final String userPrefix, final Integer userSuffixMin, final Integer userSuffixMax,
            final String workerNamePrefix, final String processType) throws Exception {
        final Random random = new Random();
        for (int i = 0; i < numThreads; i++) {
            final String name = workerNamePrefix + i;
            final File statFile;
            if (statFolder == null) {
                statFile = null;
            } else {
                statFile = new File(statFolder, name + ".csv");
            }
            threads.add(new DocumentSignerThread(name, failureCallback, url, useWorkerServlet, bytes, infile, workerNameOrId, processType, maxWaitTime,
                    random.nextInt(), warmupTime, limitedTime, statFile,
                    userPrefix, userSuffixMin, userSuffixMax));
        }
    }
}
