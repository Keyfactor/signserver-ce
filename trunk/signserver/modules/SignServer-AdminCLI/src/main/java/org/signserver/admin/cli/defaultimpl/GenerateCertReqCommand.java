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
package org.signserver.admin.cli.defaultimpl;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerIdentifier;

/**
 * Commands that requests a signer to generate a PKCS10 certificate request 
 *
 * @version $Id$
 */
public class GenerateCertReqCommand extends AbstractAdminCommand {

    private static final String HELP = "Usage: signserver generatecertreq <workerid> <dn> <signature algorithm>  <cert-req-filename> [-explicitecc] [-alias <key alias>|-nextkey]\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA256WithRSA\" /home/user/certtreq.pem\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA256WithRSA\" /home/user/certtreq.pem -nextkey\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\" \"SHA256WithRSA\" /home/user/certreq.pem -alias user1\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA256WithECDSA\" /home/user/certreq.pem -explicitecc\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA256WithECDSA\" /home/user/certreq.pem -explicitecc -nextkey\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\" \"SHA256WithECDSA\" /home/user/certreq.pem -explicitecc -alias user1\n\n";
    private static final String FAIL = "Error: No worker with the given name could be found";
    private static final String SUCCESS = "PKCS10 Request successfully written to file ";

    @Override
    public String getDescription() {
        return "Requests a signer to generate a PKCS#10 certificate request";
    }
    
    @Override
    public String getUsages() {
        return HELP;
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length < 4 || args.length > 7) {
            throw new IllegalCommandArgumentsException(HELP);
        }
        try {

            final String workerid = args[0];
            final String dn = args[1];
            final String sigAlg = args[2];
            final String filename = args[3];
            boolean defaultKey = true;
            boolean explicitecc = false;
            String keyAlias = null;
            
            if (args.length > 4) {
                if ("-nextkey".equals(args[4])) {
                    defaultKey = false;
                } else if ("-explicitecc".equals(args[4])) {
                    explicitecc = true;
                } else if ("-alias".equals(args[4])) {
                    if (args.length > 5) {
                        keyAlias = args[5];
                    } else {
                        getErrorStream().println("Missing argument for -alias");
                        throw new IllegalCommandArgumentsException(HELP);
                    }
                } else {
                    getErrorStream().println("Unknown argument: " + args[4]);
                    throw new IllegalCommandArgumentsException(HELP);
                }

                if (args.length > 5) {
                    if ("-nextkey".equals(args[5])) {
                        defaultKey = false;
                    } else if ("-explicitecc".equals(args[5])) {
                        explicitecc = true;
                    } else if ("-alias".equals(args[5])) {
                        if (args.length > 6) {
                            keyAlias = args[6];
                        } else {
                            getErrorStream().println("Missing argument for -alias");
                            throw new IllegalCommandArgumentsException(HELP);
                        }
                    } else if (keyAlias == null) {
                        getErrorStream().println("Unknown argument: " + args[5]);
                        throw new IllegalCommandArgumentsException(HELP);
                    }
                }
              
                if (args.length > 6) {
                    // the argument following -alias could only be -explitecc
                    if ("-explicitecc".equals(args[6])) {
                        explicitecc = true;
                    } else if (keyAlias == null) {
                        getErrorStream().println("Unknown argument: " + args[6]);
                        throw new IllegalCommandArgumentsException(HELP);
                    }
                }
            }

            final WorkerIdentifier id = WorkerIdentifier.createFromIdOrName(workerid);

            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg, dn, null);
            final AbstractCertReqData reqData;
            
            if (keyAlias != null) {
                reqData = (AbstractCertReqData) getWorkerSession().getCertificateRequest(id, certReqInfo, explicitecc, keyAlias);
            } else {
                reqData = (AbstractCertReqData) getWorkerSession().getCertificateRequest(id, certReqInfo, explicitecc, defaultKey);
            }
   
            if (reqData == null) {
                throw new Exception("Base64SignerCertReqData returned was null. Unable to generate certificate request.");
            }
            try (FileOutputStream fos = new FileOutputStream(filename)) {
                fos.write(reqData.toArmoredForm().getBytes(StandardCharsets.UTF_8));
            }

            getOutputStream().println(SUCCESS + filename);
            return 0;
        } catch (InvalidWorkerIdException | FileNotFoundException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (CryptoTokenOfflineException e) {
             throw new CommandFailureException("Crypto token is offline: " + e.getLocalizedMessage());
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }


}
