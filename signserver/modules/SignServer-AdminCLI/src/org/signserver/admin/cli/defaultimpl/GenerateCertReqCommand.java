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
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.PKCS10CertReqInfo;

/**
 * Commands that requests a signer to generate a PKCS10 certificate request 
 *
 * @version $Id$
 */
public class GenerateCertReqCommand extends AbstractAdminCommand {

    private static final String HELP = "Usage: signserver generatecertreq <workerid> <dn> <signature algorithm>  <cert-req-filename> [-explicitecc] [-nextkey]\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithRSA\" /home/user/certtreq.pem\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithRSA\" /home/user/certtreq.pem -nextkey\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithECDSA\" /home/user/certtreq.pem -explicitecc\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\"  \"SHA1WithECDSA\" /home/user/certtreq.pem -explicitecc -nextkey\n\n";
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

    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length < 4 || args.length > 6) {
            throw new IllegalCommandArgumentsException(HELP);
        }
        try {

            final String workerid = args[0];
            final String dn = args[1];
            final String sigAlg = args[2];
            final String filename = args[3];
            boolean defaultKey = true;
            boolean explicitecc = false;

            if (args.length > 4) {
                if ("-nextkey".equals(args[4])) {
                    defaultKey = false;
                } else if ("-explicitecc".equals(args[4])) {
                    explicitecc = true;
                } else {
                    throw new IllegalCommandArgumentsException(HELP);
                }
                if (args.length > 5) {
                    if ("-nextkey".equals(args[5])) {
                        defaultKey = false;
                    } else if ("-explicitecc".equals(args[5])) {
                        explicitecc = true;
                    } else {
                        throw new IllegalCommandArgumentsException(HELP);
                    }
                }
            }

            final int id;
            if (workerid.substring(0, 1).matches("\\d")) {
                id = Integer.parseInt(workerid);
            } else {
                // named worker is requested
                id = getWorkerSession().getWorkerId(workerid);
                if (id == 0) {
                    throw new IllegalCommandArgumentsException(FAIL);
                }
            }

            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg, dn, null);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(id, certReqInfo, explicitecc, defaultKey);
            if (reqData == null) {
                throw new Exception("Base64SignerCertReqData returned was null. Unable to generate certificate request.");
            }
            FileOutputStream fos = new FileOutputStream(filename);
            fos.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
            fos.write(reqData.getBase64CertReq());
            fos.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
            fos.close();

            getOutputStream().println(SUCCESS + filename);
            return 0;
        } catch (InvalidWorkerIdException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (FileNotFoundException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }


}
