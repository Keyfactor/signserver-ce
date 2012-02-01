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
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysResponse;

/**
 * Command used to tell a group key service to pregenerate a number of keys. 
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class PregenerateKeyCommand extends BaseGroupKeyServiceCommand {

    private static final int NUMBEROFKEYSPERREQUESTS = 100;

    @Override
    public String getDescription() {
        return "Pregenerate group keys";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 2) {
            throw new IllegalCommandArgumentsException("Usage: signserver groupkeyservice pregeneratekeys <workerId or name> <number of keys>\n"
                    + "Example: signserver groupkeyservice pregeneratekeys GroupKeyService1 1000\n\n");
        }
        try {
            int workerId = helper.getWorkerId(args[0]);
            isWorkerGroupKeyService(workerId);

            int numberOfKeys = 0;
            try {
                numberOfKeys = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                throw new IllegalCommandArgumentsException("Error: Parameter specifying the number of keys to generate '" + args[1] + "' can only contain digits.");
            }

            int keysGenerated = 0;
            while (keysGenerated < numberOfKeys) {
                int keysToGenerate = NUMBEROFKEYSPERREQUESTS;
                if ((numberOfKeys - keysGenerated) < NUMBEROFKEYSPERREQUESTS) {
                    keysToGenerate = (numberOfKeys - keysGenerated);
                }
                out.println("Pregenerating keys " + (keysGenerated + 1) + " to " + (keysGenerated + keysToGenerate));
                PregenerateKeysRequest req = new PregenerateKeysRequest(keysToGenerate);
                PregenerateKeysResponse res = (PregenerateKeysResponse) helper.getWorkerSession().process(workerId, req, new RequestContext(true));
                if (res.getNumberOfKeysGenerated() != keysToGenerate) {
                    throw new IllegalCommandArgumentsException("Error requested number of keys '" + keysToGenerate + "' wasn't pregenerated only '" + res.getNumberOfKeysGenerated() + "' were generated.");
                }
                keysGenerated += keysToGenerate;
            }
            out.println("\n\n" + keysGenerated + " Pregenerated successfully.\n");


        } catch (CryptoTokenOfflineException e) {
            throw new CommandFailureException("Error, Group key service " + args[0] + " : Crypotoken is off-line.");
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
        return 0;
    }
   
}
