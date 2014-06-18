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
package org.signserver.common;

import java.io.PrintStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Common base class used to report the status of a signer or service. Should
 * be inherited by all workers.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public abstract class WorkerStatus implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Status value for a token or worker that is active. */
    public static final int STATUS_ACTIVE = 1;

    /** Status value for a token or worker that is offline. */
    public static final int STATUS_OFFLINE = 2;

    public static final String INDENT1 = "          ";
    public static final String INDENT2 = "   ";
    
    protected static final String[] signTokenStatuses = {"", "Active", "Offline"};
    protected String hostname = null;
    protected WorkerConfig activeconfig = null;
    protected int workerId;
    
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
    
    private List<String> fatalErrors = new LinkedList<String>();

    public WorkerStatus() {
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            hostname = "unknown";
        }
    }

    public void setActiveconfig(WorkerConfig activeconfig) {
        this.activeconfig = activeconfig;
    }

    public void setWorkerId(int workerId) {
        this.workerId = workerId;
    }

    /** 
     * @deprecated Use the constructor taking a list of errors
     */
    @Deprecated
    public WorkerStatus(int workerId, WorkerConfig config) {
       this(workerId, Collections.<String>emptyList(), config); 
    }
    
    public WorkerStatus(int workerId, List<String> fatalErrors, WorkerConfig config) {
        this.workerId = workerId;
        this.fatalErrors.addAll(fatalErrors);
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            hostname = "unknown";
        }
        activeconfig = config;
        
    }

    /**
     * @return Returns the workerId.
     */
    public int getWorkerId() {
        return workerId;
    }

    /**
     * @return Returns the hostname.
     */
    public String getHostname() {
        return hostname;
    }

    public WorkerConfig getActiveSignerConfig() {
        return activeconfig;
    }

    /**
     * Old method previously used by Health check.
     * The result from this method if overridden by sub-classes is still being
     * included in the list of fatal errors for backwards compatibility.
     * 
     * New implementations should provide a list of fatal errors that could then 
     * be retrieved using the getFatalErrors() method.
     * 
     * @return null of everything is OK, otherwise an descriptive error message of the problem.
     * @deprecated Workers should add all errors using the list in the constructor. Healtch check
     * and status services should use the getFatalErrors() method.
     */
    @Deprecated
    public String isOK() {
        return null;
    }

    /**
     * Method all inheriting workers must implement. It responsible for writing the status for that specific
     * type of worker in the CLI
     */
    public abstract void displayStatus(int workerId, PrintStream out, boolean complete);

    public static void printCert(X509Certificate cert, PrintStream out) {
        out.println(INDENT1 + INDENT2 + "Subject DN:     " + cert.getSubjectDN().toString());
        out.println(INDENT1 + INDENT2 + "Serial number:  " + cert.getSerialNumber().toString(16));
        out.println(INDENT1 + INDENT2 + "Issuer DN:      " + cert.getIssuerDN().toString());
        out.println(INDENT1 + INDENT2 + "Valid from:     " + SDF.format(cert.getNotBefore()));
        out.println(INDENT1 + INDENT2 + "Valid until:    " + SDF.format(cert.getNotAfter()));
    }
    
    /**
     * Checks if the worker is disabled. 
     * A disabled worker can not perform any processing and might not be included 
     * in the Health check.
     * @return True if the worker is configured to be disabled
     */
    public boolean isDisabled() {
        final boolean result = "TRUE".equalsIgnoreCase(getActiveSignerConfig().getProperties().getProperty(SignServerConstants.DISABLED));
        return result;
    }

    /**
     * Checks if the worker reports anything that would lead to it not to be 
     * able to work. 
     * If the returned list is non-empty means that the worker should be 
     * considered offline.
     * 
     * This method is the preferred method to use from an Health check service
     * and for displaying the status of a worker.
     * 
     * @return An unmodifiable list of errors preventing this worker from working
     * or empty if it is "ALLOK".
     */
    @SuppressWarnings("deprecation")
    public List<String> getFatalErrors() {
        final List<String> results;
        
        // For backwards compatibility read the isOK
        String legacyStatus = isOK();
        if (legacyStatus == null) {
            results = fatalErrors;
        } else {
            results = new LinkedList<String>(fatalErrors);
            results.add(legacyStatus);
        }
        
        return Collections.unmodifiableList(results);
    }
}
