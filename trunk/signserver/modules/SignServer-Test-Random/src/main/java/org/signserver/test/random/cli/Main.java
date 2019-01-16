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
package org.signserver.test.random.cli;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.rmi.RemoteException;
import java.util.*;
import org.apache.commons.cli.*;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.test.random.*;
import org.signserver.test.random.impl.IncrementProperty;
import org.signserver.test.random.impl.IncrementPropertyThread;
import org.signserver.test.random.impl.RenewSigner;
import org.signserver.test.random.impl.RequestContextPreProcessor;
import org.signserver.test.random.impl.SigningThread;
import org.signserver.ejb.interfaces.WorkerSessionRemote;

/**
 * Command line interface for random tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Main {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(IncrementProperty.class);
    
    private static final String TIME_LIMIT = "timelimit";
    private static final String RANDOM_SEED = "randomseed";
    private static final String WORKER_GROUP_1 = "workergroup1";
    private static final String WORKER_GROUP_2 = "workergroup2";
    private static final String WORKER_GROUP_3 = "workergroup3";
    private static final String TEST_SUITE = "testsuite";
    private static final String THREAD_GROUP_1 = "threadgroup1";
    private static final String THREAD_GROUP_2 = "threadgroup2";
    private static final String USERPREFIX = "userprefix";
    private static final String USERSUFFIXMIN = "usersuffixmin";
    private static final String USERSUFFIXMAX = "usersuffixmax";
    
    private static final String NL = System.getProperty("line.separator");
    private static final String COMMAND = "randomtest";
    
    private static int exitCode;
    private static final Options OPTIONS;

    private static void printUsage() {
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
                .append("Sample usages:").append(NL)
                .append("a) ").append(COMMAND).append(" -testsuite signWhileUpdatingConfig -workergroup1 5678/xml,5679/tsa,5680/xml -threadgroup1 4 -workergroup2 5677/xml,5678/xml,5679/tsa -threadgroup2 3 -timelimit 30000").append(NL)
                .append("b) ").append(COMMAND).append(" -testsuite signAndCountSignings -workergroup1 5678/xml,5679/tsa,5680/xml -threadgroup1 10 -timelimit 30000").append(NL)
                .append("c) ").append(COMMAND).append(" -testsuite signWhileRenewing -workergroup1 300/xml -workergroup2 301/xml,302/xml -threadgroup1 5 -workergroup3 309/renew -timelimit 20000")
                .append("d) ").append(COMMAND).append(" -testsuite signWithRandomUsers -workergroup1 300/xml -threadgroup1 5 -timelimit 20000 -userprefix testuser -usersuffixmin 1 -usersuffixmax 100")
                .append(NL)
                .append("Available worker types:").append(NL)
                .append(" - workerType can be any of ").append(Arrays.asList(WorkerType.values())).append(NL)
                .append("Test suite: signAndCountSignings").append(NL)
                .append(" - Signs documents with the workers from group 1 with the number of threads defined for group 1").append(NL)
                .append(" - Pauses signings and counts performed signings a compares to the key usage counter value").append(NL)
                .append(" - Notice that it is assumed that all workers use the same key-pair").append(NL)
                .append("Test suite: signWhileUpdatingConfig").append(NL)
                .append(" - Signs documents with the workers from group 1 with the number of threads defined for group 1").append(NL)
                .append(" - Increases a counter in the configuration of group 2").append(NL)
                .append(" - Notice that the size of thread group 2 must be equal to the number of workers in group 2").append(NL)
                .append("Test suite: signWhileRenewing").append(NL)
                .append(" - Signs documents with the workers from group 1 with the number of threads defined for group 1").append(NL)
                .append(" - Renews signers from group 2 using the one renewal worker in group 3").append(NL)
                .append(" - Notice that group 3 should only include one renewal worker").append(NL)
                .append("Test suite: signWithRandomUsers").append(NL)
                .append(" - Signs documents with the workers from group 1 with the number of threads defined for group 1").append(NL)
                .append(" - Sends requests from usernames starting with the supplied 'userprefix' and ends with a random number between 'usersuffixmin' and 'usersuffixmax'").append(NL);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        try (PrintWriter pw = new PrintWriter(bout)) {
            formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, COMMAND + " <options>", "Random testing tool", OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        }
        LOG.info(bout.toString());
    }
    
    private enum TestSuites {
        signWhileUpdatingConfig,
        signAndCountSignings,
        signWhileRenewing,
        signWithRandomUsers,
    }
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(TEST_SUITE, true, "Test suite to run. Any of " + Arrays.asList(TestSuites.values()) + ".");
        OPTIONS.addOption(TIME_LIMIT, true, "Optional. Only run for the specified time (in milliseconds).");
        OPTIONS.addOption(RANDOM_SEED, true, "Optional. Seed to initialize the pseudo random generator with.");
        OPTIONS.addOption(WORKER_GROUP_1, true, "First group of workers. Comma separated list of workerId/workerType.");
        OPTIONS.addOption(WORKER_GROUP_2, true, "Second group of workers. Comma separated list of workerId/workerType");
        OPTIONS.addOption(WORKER_GROUP_3, true, "Third group of workers. Comma separated list of workerId/workerType");
        OPTIONS.addOption(THREAD_GROUP_1, true, "Number of threads in group 1.");
        OPTIONS.addOption(THREAD_GROUP_2, true, "Number of threads in group 2.");
        OPTIONS.addOption(USERPREFIX, true, "Prefix for usernames.");
        OPTIONS.addOption(USERSUFFIXMIN, true, "Lowest suffix for usernames in form of an integer value (inclusive).");
        OPTIONS.addOption(USERSUFFIXMAX, true, "Highest suffix for usernames in form of an integer value (inclusive).");
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
            
            // Random seed
            final long seed;
            if (commandLine.hasOption(RANDOM_SEED)) {
                seed = Long.parseLong(commandLine.getOptionValue(RANDOM_SEED));
            } else {
                seed = new Random().nextLong();
            }
            final Random masterRandom = new Random(seed);
            
            // Worker group 1
            final List<WorkerSpec> workerGroup1;
            if (commandLine.hasOption(WORKER_GROUP_1)) {
                workerGroup1 = new LinkedList<>();
                final String list = commandLine.getOptionValue(WORKER_GROUP_1);
                String[] ids = list.split(",");
                for (String id : ids) {
                    workerGroup1.add(WorkerSpec.fromString(id.trim()));
                }
            } else {
                workerGroup1 = null;
            }
            
            // Worker group 2
            final List<WorkerSpec> workerGroup2;
            if (commandLine.hasOption(WORKER_GROUP_2)) {
                workerGroup2 = new LinkedList<>();
                final String list = commandLine.getOptionValue(WORKER_GROUP_2);
                String[] ids = list.split(",");
                for (String id : ids) {
                    workerGroup2.add(WorkerSpec.fromString(id.trim()));
                }
            } else {
                workerGroup2 = null;
            }
            
            // Worker group 3
            final List<WorkerSpec> workerGroup3;
            if (commandLine.hasOption(WORKER_GROUP_3)) {
                workerGroup3 = new LinkedList<>();
                final String list = commandLine.getOptionValue(WORKER_GROUP_3);
                String[] ids = list.split(",");
                for (String id : ids) {
                    workerGroup3.add(WorkerSpec.fromString(id.trim()));
                }
            } else {
                workerGroup3 = null;
            }
            
            // Thread group 1
            final Integer threadGroup1;
            if (commandLine.hasOption(THREAD_GROUP_1)) {
                threadGroup1 = Integer.parseInt(commandLine.getOptionValue(THREAD_GROUP_1));
            } else {
                threadGroup1 = null;
            }
            
            // Thread group 2
            final Integer threadGroup2;
            if (commandLine.hasOption(THREAD_GROUP_2)) {
                threadGroup2 = Integer.parseInt(commandLine.getOptionValue(THREAD_GROUP_2));
            } else {
                threadGroup2 = null;
            }
            
            final AdminCommandHelper helper = new AdminCommandHelper();
            final WorkerSessionRemote workerSession = helper.getWorkerSession();
            final ProcessSessionRemote processSession = helper.getProcessSession();
            final LinkedList<WorkerThread> threads = new LinkedList<>();
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

            // Init context
            final TestContext context = new TestContext();
            context.setCallback(callback);
            context.setMasterRandom(masterRandom);
            context.setWorkerSession(workerSession);
            context.setProcessSession(processSession);
            context.setPauser(new Pauser());
            context.setWorkerGroup1(workerGroup1);
            context.setThreadsGroup1(threadGroup1);
            context.setWorkerGroup2(workerGroup2);
            context.setThreadsGroup2(threadGroup2);
            context.setWorkerGroup3(workerGroup3);
            
            // Output information
            final StringBuilder buff = new StringBuilder();
            buff.append("SignServer Random Test\n")
                    .append("----------------------\n")
                    .append("Random seed:          ").append(seed).append("\n")
                    .append("Time limit:           ").append(limitedTime < 0 ? "unlimited" : limitedTime).append(" ms").append("\n")
                    .append("Test suite:           ").append(ts).append("\n")
                    .append("Worker group 1:       ").append(context.getWorkerGroup1()).append("\n")
                    .append("Worker group 2:       ").append(context.getWorkerGroup2()).append("\n")
                    .append("Worker group 3:       ").append(context.getWorkerGroup3()).append("\n")
                    .append("Thread group 1:       ").append(context.getThreadsGroup1() == null ? "unspecified" : context.getThreadsGroup1()).append("\n")
                    .append("Thread group 2:       ").append(context.getThreadsGroup2() == null ? "unspecified" : context.getThreadsGroup2()).append("\n");
            LOG.info(buff.toString());
            
            try {
                // First check all workers
                if (context.getWorkerGroup1() == null) {
                    if (context.getThreadsGroup1() == null) {
                        throw new ParseException("Missing -workergroup1");
                    }
                }
                Collection<WorkerSpec> allWorkers = new LinkedList<>(context.getWorkerGroup1());
                if (context.getWorkerGroup2() != null) {
                    allWorkers.addAll(context.getWorkerGroup2());
                }
                if (context.getWorkerGroup3() != null) {
                    allWorkers.addAll(context.getWorkerGroup3());
                }
                for (WorkerSpec worker : allWorkers) {
                    List<String> fatalErrors = context.getWorkerSession().getStatus(new WorkerIdentifier(worker.getWorkerId())).getFatalErrors();
                    if (!fatalErrors.isEmpty()) {
                        System.err.println();
                        throw new FailedException("Worker " + worker + ": " + fatalErrors);
                    }
                }
                
                // Init test suite
                switch (ts) {
                    case signWhileUpdatingConfig:
                        signWhileUpdatingConfig(threads, context);
                        break;
                    case signAndCountSignings:
                        signAndCountSignings(threads, context);
                        break;
                    case signWhileRenewing:
                        signWhileRenewing(threads, context);
                        break;
                    case signWithRandomUsers: {
                        final String userPrefix = commandLine.getOptionValue(USERPREFIX, null);
                        if (userPrefix == null) {
                            throw new ParseException("Missing required option: " + USERPREFIX);
                        }
                        final String userSuffixMin = commandLine.getOptionValue(USERSUFFIXMIN, null);
                        if (userSuffixMin == null) {
                            throw new ParseException("Missing required option: " + USERSUFFIXMIN);
                        }
                        final String userSuffixMax = commandLine.getOptionValue(USERSUFFIXMAX, null);
                        if (userSuffixMax == null) {
                            throw new ParseException("Missing required option: " + USERSUFFIXMAX);
                        }
                        signWithRandomUsers(threads, context, userPrefix, Integer.parseInt(userSuffixMin), Integer.parseInt(userSuffixMax));
                        break;
                    }
                    default:
                        throw new Exception("Unsupported test suite: " + ts);
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
    
        /**
     * Creates one group of signing threads and one "pauser" thread. The signing threads
     * signs documents and holds a counter for how many signings they have performed.
     * The pauser thread pauses the other threads every 5 seconds and checks and
     * summarizes all performed signings and compares with the key usage counter 
     * value in the database.
     * 
     * Notice: It is assumed that all signers use the same key.
     * 
     * The goals with the test are:
     * a) Test that no updates to key usage counter is missed
     * 
     */
    private static void signAndCountSignings(final List<WorkerThread> threads, final TestContext context) throws Exception {
        final LinkedList<SigningThread> signingThreads = new LinkedList<>();
        
        if (context.getThreadsGroup1() == null) {
            throw new ParseException("Missing -threadgroup1");
        }
        
        // Threads signing documents
        // Group 1: Threads signing documents with the workers in group 1
        for (int i = 0; i < context.getThreadsGroup1(); i++) {
            final WorkerSpec worker = context.getWorkerGroup1().get(i % context.getWorkerGroup1().size());
            final SigningThread signingThread = new SigningThread("Signer-" + i + "-" + worker.getWorkerId(), context.getCallback(), context.getPauser(), context.getMasterRandom().nextLong(), worker, context.getProcessSession(), null);
            signingThreads.add(signingThread);
        }
        threads.addAll(signingThreads);
        
        final int workerId = context.getWorkerGroup1().get(0).getWorkerId();
        
        final long startValue = context.getWorkerSession().getKeyUsageCounterValue(new WorkerIdentifier(workerId));
        
        // Thread pausing signings
        WorkerThread pauseThread = new WorkerThread("Pause", context.getCallback()) {
            @Override
            public void run() {
                final Pauser pauser = context.getPauser();
                try {
                    while (!isStop()) {
                        try {
                            Thread.sleep(5000);
                            pauser.startPause();
                            Thread.sleep(5000);

                            long signings = 0;
                            for (SigningThread w : signingThreads) {
                                signings += w.getOperationsPerformed();
                            }
                            long expected = startValue + signings;
                            long actual = context.getWorkerSession().getKeyUsageCounterValue(new WorkerIdentifier(workerId));
                            if (expected != actual) {
                                fireFailure("Key usage counter value incorrect. Expected " + expected + ", actual " + actual);
                                break;
                            }
                            increaseOperationsPerformed();
                        }  finally {
                            pauser.stopPause();
                        }
                    }
                } catch (CryptoTokenOfflineException ex) {
                    fireFailure("Worker offline: " + ex.getMessage());
                } catch (InterruptedException ex) {
                    LOG.error("Interrupted: " + ex.getMessage());
                }
            }
        };
        threads.add(pauseThread);
    }
    
    /**
     * Creates two groups of threads, one performing signings and the other updating
     * the worker configurations.
     * 
     * There can be any number of workers and threads in group 1.
     * In group 2 the number of threads should be equal to the number of workers 
     * so that no two threads update the configuration of the same worker on the 
     * same time.
     * 
     * The goals with the test are:
     * a) Test that it is possible to sign at the same time as the signers configuration is updated.
     * b) Test that updating the configuration of different workers at the same time does not infer with each other
     * c) No configuration update is missed
     * 
     * The test reads a counter value from a worker property, increases it with one
     * and updates the configuration with the new value. Every 10th iteration 
     * the value is read from the configuration and checked that it equals the
     * expected value.
     * 
     */
    private static void signWhileUpdatingConfig(final List<WorkerThread> threads, final TestContext context) throws Exception {
        
        if (context.getThreadsGroup1() == null) {
            throw new ParseException("Missing -threadgroup1");
        }
        
        // As updating a counter in the worker configuration can not be done automically
        // we only allow one thread to update each worker otherwise the tests will fail
        if (context.getThreadsGroup2() == null) {
            context.setThreadsGroup2(context.getWorkerGroup2().size());
        } else if (context.getThreadsGroup2() != context.getWorkerGroup2().size()) {
            throw new ParseException("Size of thread group 2 must be equal to size of worker group 2");
        }
        
        // Group 1: Threads signing documents with the workers in group 1
        for (int i = 0; i < context.getThreadsGroup1(); i++) {
            final WorkerSpec worker = context.getWorkerGroup1().get(i%context.getWorkerGroup1().size());
            final SigningThread signingThread = new SigningThread("Signer-" + i + "-" + worker.getWorkerId(), context.getCallback(), null, context.getMasterRandom().nextLong(), worker, context.getProcessSession(), null);
            threads.add(signingThread);
        }
        
        // Group 2: Threads updating the configuration of the workers in group 2
        for (int i = 0; i < context.getThreadsGroup2(); i++) {
            final int workerId = context.getWorkerGroup2().get(i%context.getWorkerGroup2().size()).getWorkerId();
            final IncrementPropertyThread incr = new IncrementPropertyThread("ConfUpdater-" + i + "-" + workerId, context.getCallback(), context.getMasterRandom().nextLong(), workerId, "PROPERTY", context.getWorkerSession());
            threads.add(incr);
        }
    }
    
    /**
     * Creates two groups of threads, one performing signings and the other 
     * renewing the signers.
     * 
     * There can be any number of workers and threads in group 1 performing signings.
     * 
     * Group 2 is the workers that will be renewed by the renewalworker in group 3.
     * 
     * The goals with the test are:
     * a) Test that it is possible to sign at the same time as the signers are renewed.
     *
     * - Notice that for instance a FirstActiveDispatcher might have to be used 
     *   in order to be able to sign while some of the workers are being renewed
     *   as there is a time for which the worker will be offline during renewal.
     */
    private static void signWhileRenewing(final List<WorkerThread> threads, final TestContext context) throws Exception {
        
        if (context.getThreadsGroup1() == null) {
            throw new ParseException("Missing -threadgroup1");
        }
        
        if (context.getWorkerGroup3() == null) {
            throw new ParseException("Missing -workergroup3");
        }
        
        if (context.getWorkerGroup3().size() != 1) {
            throw new ParseException("Only one (renewal) worker allowed (worker group 3)");
        }
        
        if (!context.getWorkerGroup3().get(0).getWorkerType().equals(WorkerType.renew)) {
            throw new ParseException("The worker in group 3 must be of type " + WorkerType.renew + ".");
        }
        
        // Group 1: Threads signing documents with the workers in group 1
        for (int i = 0; i < context.getThreadsGroup1(); i++) {
            final WorkerSpec worker = context.getWorkerGroup1().get(i%context.getWorkerGroup1().size());
            final SigningThread signingThread = new SigningThread("Signer-" + i + "-" + worker.getWorkerId(), context.getCallback(), null, context.getMasterRandom().nextLong(), worker, context.getProcessSession(), null);
            threads.add(signingThread);
        }
        
        // Group 3: Threads updating the configuration of the workers in group 2
        final int workerId = context.getWorkerGroup3().get(0).getWorkerId();
        final List<WorkerSpec> renewees = context.getWorkerGroup2();
        final List<RenewSigner> renewers = new LinkedList<>();
        for (WorkerSpec renewee : renewees) {
            renewers.add(new RenewSigner(workerId, renewee.getWorkerId(), context.getProcessSession()));
        }

        final long seed = context.getMasterRandom().nextLong();
        final WorkerThread renewals = new WorkerThread("Renewal-" + workerId, context.getCallback()) {

            @Override
            public void run() {
                final Pauser pauser = context.getPauser();
                final Random random = new Random(seed);
                try {
                    while (!isStop()) {
                        for (final RenewSigner renewer : renewers) {
                            if (pauser != null) {
                                pauser.pause();
                            }
                            try {
                                renewer.run();
                            } catch (FailedException ex) {
                                fireFailure("WORKER" + workerId + " renewing of " + renewer.getReneweeId() + " failed after " + getOperationsPerformed() + " signings: " + ex.getMessage());
                                break;
                            }
                            // Sleep
                            Thread.sleep((int) (random.nextDouble() * 500.0));
                            increaseOperationsPerformed();
                        }
                    }
                } catch (InterruptedException ex) {
                    LOG.error("Interrupted: " + ex.getMessage());
                }
            }

        };
        threads.add(renewals);
    }

    /**
     * Creates one group of threads performing signings and sends the request
     * with usernames as specified.
     * @param threads to run
     * @param context for the tests
     * @param userPrefix Prefix for the username
     * @param userSuffixMin Minimum username number
     * @param userSuffixMax Maximum username number
     * @throws Exception in case of errors
     */
    private static void signWithRandomUsers(final List<WorkerThread> threads, final TestContext context, final String userPrefix, final int userSuffixMin, final int userSuffixMax) throws Exception {

        if (context.getThreadsGroup1() == null) {
            throw new ParseException("Missing -threadgroup1");
        }

        // Group 1: Threads signing documents with the workers in group 1
        for (int i = 0; i < context.getThreadsGroup1(); i++) {
            final WorkerSpec worker = context.getWorkerGroup1().get(i%context.getWorkerGroup1().size());
            final SigningThread signingThread = new SigningThread("Signer-" + i + "-" + worker.getWorkerId(), context.getCallback(), null, context.getMasterRandom().nextLong(), worker, context.getProcessSession(), new RequestContextPreProcessor() {

                @Override
                public void preProcess(RemoteRequestContext requestContext) {
                    final String username = userPrefix + (userSuffixMin + context.getMasterRandom().nextInt(userSuffixMax - userSuffixMin + 1));
                    requestContext.setUsername(username);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Username: " + username);
                    }
                }
            });
            threads.add(signingThread);
        }
    }

}

