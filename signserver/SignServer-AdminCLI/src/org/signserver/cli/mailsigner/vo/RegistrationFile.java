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

import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Class containing data used in a registration file
 * such as type of registration and PKCS10 data.
 * 
 * 
 * @author Philip Vendil 23 Nov 2008
 *
 * @version $Id$
 */

public class RegistrationFile implements Externalizable {
	
	private static int VERSION = 1;

	public enum RegistrationType{
		REGISTRATION,
		RENEWAL
	}
	
	public enum KeyStoreType{
		MAINTAINEDSIGNENC // The sign and encryption key stores are stored in the server backend.
	}
	
	private RegistrationType registrationType;
	private KeyStoreType keyStoreType;
	private String fromEmailAddress;
	private PKCS10CertificationRequest authPKCS10;
	
	public RegistrationFile(RegistrationType registrationType,KeyStoreType keyStoreType, String fromEmailAddress, PKCS10CertificationRequest authPKCS10){
		this.registrationType = registrationType;
		this.keyStoreType = keyStoreType;
		this.authPKCS10 = authPKCS10;
		this.fromEmailAddress = fromEmailAddress;
	}	
	
	/**
	 * Used when serializing
	 */
	public RegistrationFile(){
		
	}

	/**
	 * 
	 * @return the type of key store that should be generated.
	 */
	public KeyStoreType getKeyStoreType() {
		return keyStoreType;
	}
	
	/**
	 * 
	 * @return the type of key store, defining which
	 * key stores that should be generated when
	 */
	public RegistrationType getRegistrationType() {
		return registrationType;
	}


	/**
	 * @return Returns the PKCS10 used for authentication requests
	 */
	public PKCS10CertificationRequest getAuthenticationPkcs10() {
		return authPKCS10;
	}

	public void readExternal(ObjectInput in) throws IOException,
	ClassNotFoundException {
		in.readInt(); // VERSION
		
		int dataLen = in.readInt();
		byte data[] = new byte[dataLen];
		in.readFully(data);
		registrationType = RegistrationType.valueOf(new String(data,"UTF-8"));
		
		dataLen = in.readInt();
		data = new byte[dataLen];
		in.readFully(data);
		keyStoreType = KeyStoreType.valueOf(new String(data,"UTF-8"));
		
		dataLen = in.readInt();
		data = new byte[dataLen];
		in.readFully(data);
		fromEmailAddress = new String(data,"UTF-8");
		
		dataLen = in.readInt();
		data = new byte[dataLen];
		in.readFully(data);
		authPKCS10 = new PKCS10CertificationRequest(data);
	}


	public void writeExternal(ObjectOutput out) throws IOException { 
		out.writeInt(VERSION);
		
				
		byte[] data = registrationType.toString().getBytes("UTF-8");
		out.writeInt(data.length);
		out.write(data);
		
		data = keyStoreType.toString().getBytes("UTF-8");
		out.writeInt(data.length);
		out.write(data);
		
		data = fromEmailAddress.getBytes("UTF-8");
		out.writeInt(data.length);
		out.write(data);
		
		data = authPKCS10.getEncoded();
		out.writeInt(data.length);
		out.write(data,0,data.length);	
	}

	/**
	 * @return the fromEmailAddress used in the certificates
	 */
	public String getFromEmailAddress() {
		return fromEmailAddress;
	}
}
