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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.util.encoders.Base64;
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
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\" \"SHA256WithECDSA\" /home/user/certreq.pem -explicitecc -alias user1\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\" \"SHA256WithRSA\" /home/user/certreq.pem -alias user1 -email user@mail.com\n"
            + "Example: signserver generatecertreq 1 \"CN=TestCertReq\" \"SHA256WithRSA\" /home/user/certreq.pem -alias user1 -email user@mail.com -email other@domain.org\n\n";
    private static final String FAIL = "Error: No worker with the given name could be found";
    private static final String SUCCESS = "PKCS10 Request successfully written to file ";

    private boolean defaultKey = true;
    private boolean explicitecc = false;
    private String keyAlias = null;
    private String[] emailAddresses = null;

    private static final String NEXTKEY = "nextkey";
    private static final String EXPLICITECC = "explicitecc";
    private static final String ALIAS = "alias";
    private static final String EMAIL = "email";

    private static final Options OPTIONS;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(NEXTKEY, false, "Use next key alias");
        OPTIONS.addOption(EXPLICITECC, false, "Use explicit ECC");
        OPTIONS.addOption(ALIAS, true, "Key alias/name");
        OPTIONS.addOption(EMAIL, true, "Subject alternative name e-mail address");
    }
    
    @Override
    public String getDescription() {
        return "Requests a signer to generate a PKCS#10 certificate request";
    }
    
    @Override
    public String getUsages() {
        return HELP;
    }

    private String getEmailSanAttribute(final String[] emailAddresses) throws IOException {
        final ExtensionsGenerator eg = new ExtensionsGenerator();
        
        for (final String emailAddress : emailAddresses) {
            final GeneralName g = new GeneralName(GeneralName.rfc822Name,
                                                  emailAddress);
            final GeneralNames gn = new GeneralNames(g);
            eg.addExtension(Extension.subjectAlternativeName, false, gn);
        }

        final Attribute a =
                new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                              new DERSet(eg.generate()));

        return Base64.toBase64String(new DERSet(a).getEncoded());
    }

    private void parseCommandLine(final CommandLine line)
            throws IllegalCommandArgumentsException {
        if (line.hasOption(NEXTKEY)) {
            defaultKey = false;

            if (line.hasOption(ALIAS)) {
                throw new IllegalCommandArgumentsException("Can not specify -alias with -nextkey");
            }
        }

        if (line.hasOption(EXPLICITECC)) {
            explicitecc = true;
        }

        if (line.hasOption(ALIAS)) {
            keyAlias = line.getOptionValue(ALIAS);
        }

        if (line.hasOption(EMAIL)) {
            emailAddresses = line.getOptionValues(EMAIL);
        }
    }
    
    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length < 4) {
            throw new IllegalCommandArgumentsException("Missing arguments");
        }
        try {

            final String workerid = args[0];
            final String dn = args[1];
            final String sigAlg = args[2];
            final String filename = args[3];

            try {
                // Parse the command line
                parseCommandLine(new DefaultParser().parse(OPTIONS, args));
            } catch (ParseException ex) {
                throw new IllegalCommandArgumentsException(ex.getMessage());
            }

            final WorkerIdentifier id = WorkerIdentifier.createFromIdOrName(workerid);

            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(sigAlg, dn, null);
            final AbstractCertReqData reqData;

            if (emailAddresses != null) {
                certReqInfo.setBase64Attributes(getEmailSanAttribute(emailAddresses));
            }
            
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
