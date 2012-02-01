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

import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.RequestContext;
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

    @Override
    public String getDescription() {
        return "Switch the encryption key used to protect the group keys";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Usage: signserver groupkeyservice switchenckey <workerId or name>\n"
                    + "Example: signserver groupkeyservice switchenckey GroupKeyService1\n\n");
        }
        try {
            int workerId = getWorkerId(args[0]);
            isWorkerGroupKeyService(workerId);

            this.getOutputStream().println("Switching encryption key for group key service : " + args[0]);
            SwitchEncKeyRequest req = new SwitchEncKeyRequest();
            SwitchEncKeyResponse resp = (SwitchEncKeyResponse) getWorkerSession().process(workerId, req, new RequestContext(true));

            this.getOutputStream().println("\nEncryption key switched successfully, new key id is : " + resp.getNewKeyIndex() + "\n");
            return 0;
        } catch (CryptoTokenOfflineException e) {
            throw new CommandFailureException("Error, Group key service " + args[0] + " : Crypotoken is off-line.");
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }
}
