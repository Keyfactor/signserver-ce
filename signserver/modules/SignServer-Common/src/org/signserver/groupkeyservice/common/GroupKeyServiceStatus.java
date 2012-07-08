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
package org.signserver.groupkeyservice.common;

import java.io.PrintStream;
import java.util.Date;
import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.WorkerConfig;

/**
 * Class used to display the status of a GroupKeyService such as 
 * keys in database etc.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class GroupKeyServiceStatus extends CryptoTokenStatus {

    private static final long serialVersionUID = 1L;
    private long numOfUnassignedKeys;
    private long numOfKeys;
    private long numOfAssignedKeys;
    private String currentEncKeyRef;
    private long currentEncKeyNumEncryptions;
    private Date currentEncKeyStartDate;

    public GroupKeyServiceStatus(int workerId, int tokenStatus, WorkerConfig config, long numOfUnassignedKeys,
            long numOfKeys, long numOfAssignedKeys, String currentEncKeyRef,
            long currentEncKeyNumEncryptions, Date currentEncKeyStartDate) {
        super(workerId, tokenStatus, config);
        this.numOfUnassignedKeys = numOfUnassignedKeys;
        this.numOfKeys = numOfKeys;
        this.numOfAssignedKeys = numOfAssignedKeys;
        this.currentEncKeyRef = currentEncKeyRef;
        this.currentEncKeyNumEncryptions = currentEncKeyNumEncryptions;
        this.currentEncKeyStartDate = currentEncKeyStartDate;
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        
        out.println(INDENT1 + "Crypto token: " + signTokenStatuses[getTokenStatus()]);
        out.println();

        if (complete) {
            out.println(INDENT1 + "Total number of generated keys in database : " + numOfKeys);
            out.println(INDENT1 + "Number of assigned keys in database : " + numOfAssignedKeys);
            out.println(INDENT1 + "Number of unassigned keys in database : " + numOfUnassignedKeys);
            out.println();
            out.println();
            if (currentEncKeyRef != null) {
                out.println(INDENT1 + "Currently used encryption key reference is : " + currentEncKeyRef);
                out.println(INDENT1 + "Currently used encryption key count : " + currentEncKeyNumEncryptions);
                out.println(INDENT1 + "Currently used encryption key start date : " + currentEncKeyStartDate.toString());
            } else {
                out.println(INDENT1 + "No encryption key have been initialized.");
            }
        }

    }

    public long getNumOfUnassignedKeys() {
        return numOfUnassignedKeys;
    }

    public long getNumOfKeys() {
        return numOfKeys;
    }

    public long getNumOfAssignedKeys() {
        return numOfAssignedKeys;
    }

    public String getCurrentEncKeyRef() {
        return currentEncKeyRef;
    }

    /**
     * @return the currentEncKeyNumEncryptions
     */
    public long getCurrentEncKeyNumEncryptions() {
        return currentEncKeyNumEncryptions;
    }

    /**
     * @return the currentEncKeyStartDate
     */
    public Date getCurrentEncKeyStartDate() {
        return currentEncKeyStartDate;
    }

    @Override
    protected String getType() {
        return "Group key service";
    }
    
}
