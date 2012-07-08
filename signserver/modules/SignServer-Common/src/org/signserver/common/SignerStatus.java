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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import org.ejbca.util.CertTools;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific signer.
 *
 * FIXME: This feature should be re-designed. See DSS-304.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class SignerStatus extends CryptoTokenStatus {
	
    private static final long serialVersionUID = 2L;
    
    private transient Certificate signerCertificate;
    private byte[] signerCertificateBytes;
    
    private WorkerStatusInformation info;

    private long keyUsageCounterValue;
	
	/** 
	 * Main constructor
	 */
	public SignerStatus(int workerId, int tokenStatus, ProcessableConfig config, Certificate signerCertificate){
        super(workerId, tokenStatus, config.getWorkerConfig());
        this.signerCertificate = signerCertificate;
        try {
            this.signerCertificateBytes = signerCertificate == null ? null 
                    : signerCertificate.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
	}

    public SignerStatus(final int workerId, final int status,
            final ProcessableConfig config, final Certificate signerCertificate,
            final long counter) {
        this(workerId, status, config, signerCertificate);
        this.keyUsageCounterValue = counter;
    }

    public SignerStatus(int workerId, int tokenStatus, ProcessableConfig config, Certificate signerCertificate, WorkerStatusInformation info, long keyUsageCounterValue) {
        this(workerId, tokenStatus, config, signerCertificate, info);
        this.keyUsageCounterValue = keyUsageCounterValue;
    }
    
    public SignerStatus(int workerId, int tokenStatus, ProcessableConfig config, Certificate signerCertificate, WorkerStatusInformation info) {
        this(workerId, tokenStatus, config, signerCertificate);
        this.info = info;
    }
    
    /**
     * Method used to retrieve the currently used signercertficate.
     * Use this method when checking status and not from config, since the cert isn't always in db.
     */
    public Certificate getSignerCertificate() {
        if (signerCertificate == null && signerCertificateBytes != null) {
            try {
                signerCertificate = CertTools.getCertfromByteArray(signerCertificateBytes);
            } catch (CertificateException ex) {
                throw new RuntimeException(ex);
            }
        }
        return signerCertificate;
    }

	@Override
	public void displayStatus(int workerId, PrintStream out, boolean complete) {
		out.println(INDENT1 + "Crypto token: " + signTokenStatuses[getTokenStatus()]);
        out.print(INDENT1 + "Signings: " + keyUsageCounterValue);
        long keyUsageLimit = -1;
        try {
            keyUsageLimit = Long.valueOf(getActiveSignerConfig()
                .getProperty(SignServerConstants.KEYUSAGELIMIT));
        } catch(NumberFormatException ignored) {}
        if (keyUsageLimit >= 0) {
            out.print(" of " + keyUsageLimit);
        }
        out.println();
        
        final String error = isOK();
        if (error != null) {
            out.print(INDENT1);
            out.println(error);
        }

        if (info != null) {
            String briefText = info.getBriefText();
            if (briefText != null) {
                out.println("  ");
                out.println(briefText);
            }
            out.println();
        }

		if (complete) { 
            if (info != null) {
                String completeText = info.getCompleteText();
                if (completeText != null) {
                    out.println(completeText);
                    out.println();
                }
            }
            out.println();

            displayAuthorizedClients(out, new ProcessableConfig(getActiveSignerConfig()));
            
            out.print(INDENT1);
            out.println("Signer certificate:");
			if (getSignerCertificate() == null) {
                out.print(INDENT1 + INDENT2);
				out.println("(Error: no signer certificate has been uploaded to this signer)");
			} else {
				printCert((X509Certificate) getSignerCertificate(), out);
			}
            out.println();
		}
        
        out.println();
	}
    
    protected static void displayAuthorizedClients(PrintStream out, ProcessableConfig config) {
        out.print(INDENT1);
        out.println("Authorized clients (Certificate serial number, Issuer DN):");
        Collection<AuthorizedClient> clients = config.getAuthorizedClients();

        if (clients.size() > 0) {
            for (AuthorizedClient client : clients) {
                out.print(INDENT1 + INDENT2);
                out.println(client.getCertSN() + ", " + client.getIssuerDN() + "\n");
            }
        } else {
            out.print(INDENT1 + INDENT2);
            out.println("(No clients configured)");
        }
        out.println();
    }

    @Override
    public String isOK() {
        String result = super.isOK();
        if (result == null) {
            if (info != null && info.getOfflineText() != null) {
                result = info.getOfflineText();
            } else {
                result = null;
            }
            return result;
        }
        return result;
    }

    @Override
    protected String getType() {
        return "Signer";
    }

}
