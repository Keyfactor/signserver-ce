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
package org.signserver.admin.cli.defaultimpl.groupkeyservice;

import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.RequestContext;
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

    @Override
    public String getDescription() {
        return "Remove a specific set of group keys";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver groupkeyservice removegroupkeys <workerId or name> <type> <start date> <end date>\n"
                    + "  Where: <type> one of CREATED FIRSTUSED LASTFETCHED\n"
                    + "  Tip: Use \" around dates requiring spaces.\n"
                    + "Example: signserver groupkeyservice removegroupkeys GroupKeyService1 LASTFETCHED \"2007-12-01 00:00\" \"2007-12-31 00:00\"\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 4) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            int workerId = getWorkerId(args[0]);
            isWorkerGroupKeyService(workerId);

            int type = getType(args[1]);
            Date startDate = getDate(args[2], "Error: Start date parameter " + args[2] + " have bad format. Format should be " + dateFormat.toLocalizedPattern());
            Date endDate = getDate(args[3], "Error: End date parameter " + args[3] + " have bad format. Format should be " + dateFormat.toLocalizedPattern());

            this.getOutputStream().println("Removing group keys between " + startDate + " and " + endDate);
            TimeRemoveGroupKeyRequest req = new TimeRemoveGroupKeyRequest(type, startDate, endDate);
            RemoveGroupKeyResponse resp = (RemoveGroupKeyResponse) getWorkerSession().process(workerId, req, new RequestContext(true));

            this.getOutputStream().println("\n " + resp.getNumOfKeysRemoved() + " Group keys removed successfully\n");
            return 0;
        } catch (CryptoTokenOfflineException e) {
            throw new CommandFailureException("Error, Group key service " + args[0] + " : Crypotoken is off-line.");
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

    private Date getDate(String dateString, String errorMessage) throws IllegalCommandArgumentsException {
        Date retval = dateFormat.parse(dateString, new ParsePosition(0));
        if (retval == null) {
            throw new IllegalCommandArgumentsException(errorMessage);
        }
        return retval;
    }

    private int getType(String typeString) throws IllegalCommandArgumentsException {
        if (typeString.equalsIgnoreCase("CREATED")) {
            return TimeRemoveGroupKeyRequest.TYPE_CREATIONDATE;
        } else if (typeString.equalsIgnoreCase("FIRSTUSED")) {
            return TimeRemoveGroupKeyRequest.TYPE_FIRSTUSEDDATE;
        } else if (typeString.equalsIgnoreCase("LASTFETCHED")) {
            return TimeRemoveGroupKeyRequest.TYPE_LASTFETCHEDDATE;
        } else {
            throw new IllegalCommandArgumentsException("Error: the type parameter '" + typeString + "' must be either CREATED FIRSTUSED LASTFETCHED");
        }
    }
}
