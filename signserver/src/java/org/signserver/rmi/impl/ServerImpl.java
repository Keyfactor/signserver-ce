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

 
package org.signserver.rmi.impl;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;

import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.rmi.Server;
import org.signserver.rmi.TryAgainException;

import org.signserver.ejb.SignServerSessionLocal;
import org.signserver.ejb.SignServerSessionLocalHome;
import se.primeKey.utils.PrimeLog;
import se.primeKey.utils.RMIPort;
import se.primeKey.utils.SelectedPortUnicastRemoteObject;


/**
 * Implementation of common parts.
 * @author Lars Silvén
 *
 * @version $Id: ServerImpl.java,v 1.1 2007-02-27 16:18:26 herrvendil Exp $
 *
 */
public class ServerImpl extends SelectedPortUnicastRemoteObject implements Server {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private SignData signData;
    private final InetAddress localAddress;

    public ServerImpl(RMIPort port) throws RemoteException {
        super(port);
        InetAddress tmpA = null;
        try {
            tmpA = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throwRemoteException(e);
        }
        localAddress = tmpA;
        PrimeLog.debug("created");
    }
    
    private X509Certificate getClientCert(byte[] sessionId) throws Exception {
        X509Certificate clientCerts[] = (X509Certificate[])getPeerCertificates(sessionId);
        if ( clientCerts==null || clientCerts.length==0 )
            throw new TryAgainException();
        return clientCerts[0];
    }


    private void throwRemoteException( Throwable t ) throws RemoteException {
        PrimeLog.throwing(t);
        if ( t instanceof RemoteException )
            throw (RemoteException)t;
        else
            throw new RemoteException( "server exception", t );
    }

    public void wakeUp() throws RemoteException {
    }
    public String ping(byte[] sessionID) throws RemoteException {
        try {
            return "ipaddress: " + localAddress.getHostAddress() +
            	   ", name: " + localAddress.getHostName() +
            	   ", canonical name: " + localAddress.getCanonicalHostName() +
            	   ", client name: " + getClientCert(sessionID).getSubjectDN().toString();
        } catch( Throwable t ) {
            throwRemoteException(t);
        }
        return "";
    }
    private class SignData {
        final private SignServerSessionLocal signSession;
        SignData() throws Exception {
            super();
            Context ctx = new InitialContext();
            Object o = ctx.lookup("SignServerSessionLocal");
            SignServerSessionLocalHome intf = (SignServerSessionLocalHome) PortableRemoteObject.narrow(o, SignServerSessionLocalHome.class);
            signSession = intf.create();
        }
        ISignResponse signData(int signerID, ISignRequest request,
                               X509Certificate cert) throws Exception {
            PrimeLog.debug(">signData " + request.getRequestID());
            PrimeLog.debug(cert.toString());
            ISignResponse res = signSession.signData(signerID, request,
                                                          cert, null);
            
            PrimeLog.debug("<signData " + request.getRequestID());
            return res;
        }
    }
    /**
     * Get the sign session interface
     */
    public ISignResponse signData(int signerID, ISignRequest request,
                                  byte[] sessionID) throws RemoteException {
        try {
            X509Certificate clientCert = getClientCert(sessionID);
            if ( signData==null )
                signData = new SignData();
            return signData.signData(signerID, request, clientCert);
        } catch( Throwable e ) {
            throwRemoteException(e);
        }
        return null;
    }
}
