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

import org.signserver.cli.ErrorAdminCommandException;
import org.signserver.cli.IllegalAdminCommandException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyResponse;

/**
 * Command used to tell a group key service to switch the encryption key 
 * used to protect the group keys.
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class SwitchEncKeyCommand extends BaseGroupKeyServiceCommand {

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public SwitchEncKeyCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 3) {
            throw new IllegalAdminCommandException("Usage: signserver groupkeyservice switchenckey <workerId or name>\n"
                    + "Example: signserver groupkeyservice switchenckey GroupKeyService1\n\n");
        }
        try {
            int workerId = getWorkerId(args[2], hostname);
            isWorkerGroupKeyService(hostname, workerId);

            this.getOutputStream().println("Switching encryption key for group key service : " + args[2]);
            SwitchEncKeyRequest req = new SwitchEncKeyRequest();
            SwitchEncKeyResponse resp = (SwitchEncKeyResponse) getCommonAdminInterface(hostname).processRequest(workerId, req);

            this.getOutputStream().println("\nEncryption key switched successfully, new key id is : " + resp.getNewKeyIndex() + "\n");

        } catch (CryptoTokenOfflineException e) {
            throw new IllegalAdminCommandException("Error, Group key service " + args[2] + " : Crypotoken is off-line.");
        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
    // execute
}
