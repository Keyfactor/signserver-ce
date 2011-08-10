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
package org.signserver.cli;

import java.io.PrintStream;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;

/**
 * Base for Commands, contains useful functions
 *
 * @version $Id$
 */
public abstract class BaseCommand implements IAdminCommand {

    /** Log4j instance for actual class */
    private Logger log;
    
    /** Where print output of commands */
    private PrintStream outStream = System.out;
    
    /** holder of argument array */
    protected String[] args = null;
    private CommonAdminInterface commonAdminInterface;

    /**
     * Creates a new default instance of the class
     *
     */
    public BaseCommand(String[] args) {
        init(args, System.out);
        SignServerUtil.installBCProvider();
    }

    protected void printAuthorizedClients(WorkerConfig config) {
        Iterator<AuthorizedClient> iter = new ProcessableConfig(config).getAuthorizedClients().iterator();
        while (iter.hasNext()) {
            AuthorizedClient client = (AuthorizedClient) iter.next();
            this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
        }
    }

    /**
     * Initialize a new instance of BaseCommand
     *
     * @param args command line arguments
     * @param outStream stream where commands write its output
     */
    protected void init(String[] args, PrintStream outStream) {
        //log = Logger.getLogger(this.getClass());

        this.args = args;
        if (outStream != null) {
            this.outStream = outStream;
        }
    }

    /**
     * Logs a message with priority DEBUG
     *
     * @param msg Message
     */
    public void debug(String msg) {
        log.debug(msg);
    }

    /**
     * Logs a message and an exception with priority DEBUG
     *
     * @param msg Message
     * @param t Exception
     */
    public void debug(String msg, Throwable t) {
        log.debug(msg, t);
    }

    /**
     * Logs a message with priority INFO
     *
     * @param msg Message
     */
    public void info(String msg) {
        log.info(msg);
    }

    /**
     * Logs a message and an exception with priority INFO
     *
     * @param msg Message
     * @param t Exception
     */
    public void info(String msg, Throwable t) {
        log.info(msg, t);
    }

    /**
     * Logs a message with priority ERROR
     *
     * @param msg Message
     */
    public void error(String msg) {
        log.error(msg);
    }

    /**
     * Logs a message and an exception with priority ERROR
     *
     * @param msg Message
     * @param t Exception
     */
    public void error(String msg, Throwable t) {
        log.error(msg, t);
    }

    /**
     * Return the PrintStream used to print output of commands
     *
     */
    public PrintStream getOutputStream() {
        return outStream;
    }

    /**
     * Set the PrintStream used to print output of commands
     *
     * @param outStream stream where commands write its output
     */
    public void setOutputStream(PrintStream outStream) {
        if (outStream == null) {
            this.outStream = System.out;
        } else {
            this.outStream = outStream;
        }
    }

    /**
     * Help Method that retrieves the id of a worker given either
     * it's id in string format or the name of a worker
     * @throws Exception 
     * @throws RemoteException 
     */
    protected int getWorkerId(String workerIdOrName, String hostname) throws RemoteException, Exception {
        int retval = 0;

        if (workerIdOrName.substring(0, 1).matches("\\d")) {
            retval = Integer.parseInt(workerIdOrName);
        } else {
            retval = getCommonAdminInterface(hostname).getWorkerId(workerIdOrName);
            if (retval == 0) {
                throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
            }
        }

        return retval;
    }

    /**
     * Help method that checks that the current worker is a signer
     * @throws Exception 
     * @throws RemoteException 
     */
    public void checkThatWorkerIsProcessable(int signerid, String hostname) throws RemoteException, Exception {
        Collection<Integer> signerIds = getCommonAdminInterface(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_PROCESSABLE);
        if (!signerIds.contains(new Integer(signerid))) {
            throw new IllegalAdminCommandException("Error: given workerId doesn't seem to point to any processable worker in the system.");
        }

    }

    /** Gets GlobalConfigurationSession Remote
     *@return SignServerSession
     */
    protected CommonAdminInterface getCommonAdminInterface(String hostname) throws Exception {

        if (commonAdminInterface == null) {
            commonAdminInterface = new CommonAdminInterface(hostname);
        }

        return commonAdminInterface;
    }
} //BaseCommand
