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
import java.util.Enumeration;
import java.util.Iterator;
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
		out.println("Status of Signer with Id " + workerId + " is :\n" +
				"  SignToken Status : "+signTokenStatuses[isOK() == null ? 1 : 2]);
        final String error = isOK();
        if (error != null) {
            out.print("  ");
            out.println(error);
        }

                out.print("  Signings: " + keyUsageCounterValue);

                long keyUsageLimit = -1;
                try {
                    keyUsageLimit = Long.valueOf(getActiveSignerConfig()
                        .getProperty(SignServerConstants.KEYUSAGELIMIT));
                } catch(NumberFormatException ignored) {}
                if (keyUsageLimit >= 0) {
                    out.print(" of " + keyUsageLimit);
                }
                out.println();
                
                if (info != null) {
                    String briefText = info.getBriefText();
                    if (briefText != null) {
                        out.println("  ");
                        out.println(briefText);
                    }
                }

                out.println("\n\n");

		if(complete){
            
            if (info != null) {
                String completeText = info.getCompleteText();
                if (completeText != null) {
                    out.println(completeText);
                    out.println();
                }
            }
            
			out.println("Active Properties are :");


			if(getActiveSignerConfig().getProperties().size() == 0){
				out.println("  No properties exists in active configuration\n");
			}

			Enumeration<?> propertyKeys = getActiveSignerConfig().getProperties().keys();
			while(propertyKeys.hasMoreElements()){
				String key = (String) propertyKeys.nextElement();
				out.println("  " + key + "=" + getActiveSignerConfig().getProperties().getProperty(key) + "\n");
			}        		

			out.println("\n");

			out.println("Active Authorized Clients are are (Cert DN, IssuerDN):");
			Iterator<?> iter =  new ProcessableConfig(getActiveSignerConfig()).getAuthorizedClients().iterator();
			while(iter.hasNext()){
				AuthorizedClient client = (AuthorizedClient) iter.next();
				out.println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
			}
			if(getSignerCertificate() == null){
				out.println("Error: No Signer Certificate have been uploaded to this signer.\n");	
			}else{
				out.println("The current configuration use the following signer certificate : \n");
				printCert((X509Certificate) getSignerCertificate(),out );
			}
		}		
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

}
