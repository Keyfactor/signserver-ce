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
package org.signserver.cli.groupkeyservice;

import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.groupkeyservice.common.RemoveGroupKeyResponse;
import org.signserver.groupkeyservice.common.TimeRemoveGroupKeyRequest;

/**
 * Command used to tell a group key service to remove a specific
 * set of group keys.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class RemoveGroupKeysCommand extends BaseGroupKeyServiceCommand {

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public RemoveGroupKeysCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 6) {
            throw new IllegalAdminCommandException("Usage: signserver groupkeyservice removegroupkeys <workerId or name> <type> <start date> <end date>\n"
                    + "  Where: <type> one of CREATED FIRSTUSED LASTFETCHED\n"
                    + "  Tip: Use \" around dates requiring spaces.\n"
                    + "Example: signserver groupkeyservice removegroupkeys GroupKeyService1 LASTFETCHED \"2007-12-01 00:00\" \"2007-12-31 00:00\"\n\n");
        }
        try {
            int workerId = getWorkerId(args[2], hostname);
            isWorkerGroupKeyService(hostname, workerId);

            int type = getType(args[3]);
            Date startDate = getDate(args[4], "Error: Start date parameter " + args[4] + " have bad format. Format should be " + dateFormat.toLocalizedPattern());
            Date endDate = getDate(args[5], "Error: End date parameter " + args[5] + " have bad format. Format should be " + dateFormat.toLocalizedPattern());

            this.getOutputStream().println("Removing group keys between " + startDate + " and " + endDate);
            TimeRemoveGroupKeyRequest req = new TimeRemoveGroupKeyRequest(type, startDate, endDate);
            RemoveGroupKeyResponse resp = (RemoveGroupKeyResponse) getCommonAdminInterface(hostname).processRequest(workerId, req);

            this.getOutputStream().println("\n " + resp.getNumOfKeysRemoved() + " Group keys removed successfully\n");

        } catch (CryptoTokenOfflineException e) {
            throw new IllegalAdminCommandException("Error, Group key service " + args[2] + " : Crypotoken is off-line.");
        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private Date getDate(String dateString, String errorMessage) throws IllegalAdminCommandException {
        Date retval = dateFormat.parse(dateString, new ParsePosition(0));
        if (retval == null) {
            throw new IllegalAdminCommandException(errorMessage);
        }
        return retval;
    }

    private int getType(String typeString) throws IllegalAdminCommandException {
        if (typeString.equalsIgnoreCase("CREATED")) {
            return TimeRemoveGroupKeyRequest.TYPE_CREATIONDATE;
        } else if (typeString.equalsIgnoreCase("FIRSTUSED")) {
            return TimeRemoveGroupKeyRequest.TYPE_FIRSTUSEDDATE;
        } else if (typeString.equalsIgnoreCase("LASTFETCHED")) {
            return TimeRemoveGroupKeyRequest.TYPE_LASTFETCHEDDATE;
        } else {
            throw new IllegalAdminCommandException("Error: the type parameter '" + typeString + "' must be either CREATED FIRSTUSED LASTFETCHED");
        }
    }

    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
    // execute
}
