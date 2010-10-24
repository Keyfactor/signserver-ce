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

package org.signserver.cli.mailsigner.vo;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;

/**
 * Class containing data used in a activation file
 * such as type of original registration data
 * and the certificate chain.
 * 
 * 
 * @author Philip Vendil 23 Nov 2008
 *
 * @version $Id$
 */

public class ActivationFile implements Externalizable{
	private static Logger log = Logger.getLogger(ActivationFile.class);

	private static int VERSION = 1;
	
	private RegistrationFile orginalRegistrationFile;
	private List<Certificate> authCertificateChain;
	
	/**
	 * Constructor used to create an activation file manually.
	 * 
	 * @param orginalRegistrationFile the original registration file
	 * used for the registration.
	 * 
	 * @param authCertificateChain the certificate chain issued for the
	 * authentication key.
	 */
	public ActivationFile(RegistrationFile orginalRegistrationFile,
			List<Certificate> authCertificateChain) {
		super();
		this.orginalRegistrationFile = orginalRegistrationFile;
		this.authCertificateChain = authCertificateChain;
	}

    /**
     * Constructor used when de-serializing object. 
     */
	public ActivationFile() {
		super();
	}


	/**
	 * @return the original registration file
	 * used for the registration.
	 */
	public RegistrationFile getOrginalRegistrationFile() {
		return orginalRegistrationFile;
	}

	/**
	 * @return the certificate chain issued for the
	 * authentication key.
	 */
	public List<Certificate> getAuthCertificateChain() {
		return authCertificateChain;
	}
	
	public void readExternal(ObjectInput in) throws IOException,
	ClassNotFoundException {
		in.readInt(); // VERSION
		
       orginalRegistrationFile = (RegistrationFile) in.readObject();
       try {
    	   int chainSize = in.readInt();
    	   this.authCertificateChain = new ArrayList<Certificate>();
    	   for(int i=0;i<chainSize;i++){
    		   int dataLen = in.readInt();
    		   byte[] data = new byte[dataLen];
    		   in.readFully(data);
    		   Certificate cert = CertTools.getCertfromByteArray(data);
    		   authCertificateChain.add(cert);
    	   }

		} catch (CertificateException e) {
			log.error("Error when serializing certificates " + e.getMessage(),e);
			throw new IOException(e.getMessage());
		}
	}


	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(VERSION);
		
		out.writeObject(orginalRegistrationFile);

		try{
			out.writeInt(authCertificateChain.size());
			for(Certificate cert : authCertificateChain){
				byte[] data = cert.getEncoded();
				out.writeInt(data.length);
				out.write(data,0,data.length);	
			}
		}catch(CertificateException e){
			log.error("Error when serializing certificates " + e.getMessage(),e);
			throw new IOException(e.getMessage());
		}

}

}
