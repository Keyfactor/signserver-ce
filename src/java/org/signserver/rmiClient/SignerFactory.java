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

package org.signserver.rmiClient;
 
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.Security;
import java.security.cert.Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.common.MRTDSignRequest;
import org.signserver.rmiClient.impl.SignerImpl;

import se.primeKey.SetApplicationInfo;
import se.primeKey.utils.PrimeLog;

/**
 * @author lars
 *
 */
public class SignerFactory {

    /**
     * @author lars
     *
     */
    static private class TestCallback implements IErrorCallback {

        /* (non-Javadoc)
         * @see org.signserver.rmiClient.IErrorCallback#exceptionThrowed(org.signserver.rmiClient.IError)
         */
        public void exceptionThrowed(IError error) {
            try{
              errorlog("Error \""+error.getDescription()+"\" on host \""+error.getHostName()+"\".");
              errorlog(error.getThrowed().toString());
            }catch(IOException e){
                System.out.println(e.getMessage());            	
            }
        }
    }
    /**
     * the passwords must be inluded in the propertie file within the jar.
     * @param hosts
     * @param callback
     * @return
     * @throws Exception
     */
    static public ISigner getSigner(String hosts[], IErrorCallback callback) throws Exception {
        return getSigner(hosts, callback, null, null);
    }
    /**
     * @param hosts  to contact to
     * @param callback to monitor errors
     * @param keystorePassword this password will be used for the key as well
     * @return
     * @throws Exception
     */
    static public ISigner getSigner(String hosts[], IErrorCallback callback,
                                    String keystorePassword) throws Exception {
        return getSigner(hosts, callback, keystorePassword, null);
    }
    /**
     * @param hosts to contact to
     * @param callback to monitor errors
     * @param keystorePassword 
     * @param keyPassword
     * @return
     * @throws Exception
     */
    static public ISigner getSigner(String hosts[], IErrorCallback callback,
                                    String keystorePassword, String keyPassword) throws Exception {
        SetApplicationInfo.doIt();
        Security.addProvider( new BouncyCastleProvider() );
        if ( keystorePassword!=null && keystorePassword.length()>0) {
            if ( keyPassword!=null && keyPassword.length()>0)
                return new SignerImpl( hosts, callback, keystorePassword, keyPassword);
            else
                return new SignerImpl( hosts, callback, keystorePassword, null);
        } else
            return new SignerImpl( hosts, callback, null, null);
    }
    
    
    /**
     * Method used to test the RMI-SSL with client authentication and failover
     * 
     * @param args list of hostnames in jboss cluster.
     */
    public static void main(String[] args) throws Exception{
        ISigner test = null;
        try {
            System.out.println("give keystore password: ");
            test = getSigner(args, new TestCallback(),
                             new BufferedReader(new InputStreamReader(System.in)).readLine());
        } catch (Exception e) {
            PrimeLog.throwing(e);
            System.exit(0);
        }
        while ( true ){
        	Random rand = new java.util.Random(); 
            int reqid = rand.nextInt();
            ArrayList signrequests = new ArrayList();
            
            byte[] signreq1 = "Hello WorldGASDFasdfadfadpoivlaksdfxoiukakjdfadfamdnasdasdasdasasdzcxvzxcvkzxöcvkzxövkövfbamndfbvxzkvjhsf".getBytes();
 
            signrequests.add(signreq1);

            
            ISignRequest req = new MRTDSignRequest(reqid, signrequests);
            ISignResponse res = test.signData(1, req);
            
            
            if(res == null){
            	errorlog("No reponse was recieved");
            	infolog("No reponse was recieved");
            	continue;
            }
            infolog(" Req Id " + res.getRequestID() + " : Recieved Response");
            if(reqid != res.getRequestID())
            	errorlog("Error, request ID isn't what was espected in response , " + reqid + "!="  + res.getRequestID());

            Certificate signercert = res.getSignerCertificate();       
            ArrayList signatures = (ArrayList) res.getSignedData();
            if(signatures.size() != 1)
            	errorlog("Error, wrong number of signatures in response , " + signatures.size());            	
            Cipher c = Cipher.getInstance("RSA", "BC");
            c.init(Cipher.DECRYPT_MODE, signercert);

            byte[] signres1 = c.doFinal((byte[]) ((ArrayList) res.getSignedData()).get(0));

            if ( !Arrays.equals(signreq1, signres1) )
            	errorlog("Error, RSA Signature doesn't verify");	
        }
        
    }
    
    
    private static PrintWriter errorlog = null;
    private static PrintWriter infolog = null; 
    
    private static void errorlog(String msg) throws IOException{
    	if(errorlog == null){
    		errorlog = new PrintWriter(new FileWriter("error.log"));
    	}
    	errorlog.println(DateFormat.getTimeInstance().format(new Date()) + " : " + msg);    	
    	errorlog.flush();
    	
    }
    
    private static void infolog(String msg) throws IOException{
    	if(infolog == null){
    		infolog = new PrintWriter(new FileWriter("info.log"));
    	}    	
    	
    	infolog.println(DateFormat.getTimeInstance().format(new Date()) + " : " + msg);
    	infolog.flush();
    	
    }
}
