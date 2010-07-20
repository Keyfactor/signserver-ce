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
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific signer
 * @author Philip Vendil
 *
 * $Id$
 */

public class SignerStatus extends CryptoTokenStatus{


	
	private static final long serialVersionUID = 1L;


	private Certificate signerCertificate = null;

        private long keyUsageCounterValue;
	
	/** 
	 * Main constructor
	 */
	public SignerStatus(int workerId, int tokenStatus, ProcessableConfig config, Certificate signerCertificate){
		super(workerId, tokenStatus, config.getWorkerConfig());
	
	    this.signerCertificate = signerCertificate;
	}

    public SignerStatus(final int workerId, final int status,
            final ProcessableConfig config, final Certificate signerCertificate,
            final long counter) {
        super(workerId, status, config.getWorkerConfig());
        this.signerCertificate = signerCertificate;
        this.keyUsageCounterValue = counter;
    }



	 
	/**
	 * Method used to retrieve the currently used signercertficate.
	 * Use this method when checking status and not from config, since the cert isn't always in db.
	 */
	public Certificate getSignerCertificate(){
		return signerCertificate;
	}

	@Override
	public void displayStatus(int workerId, PrintStream out, boolean complete) {
		out.println("Status of Signer with Id " + workerId + " is :\n" +
				"  SignToken Status : "+signTokenStatuses[getTokenStatus()]);

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

                out.println("\n\n");

		if(complete){
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
		
	
}
