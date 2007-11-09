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

package org.signserver.server.signers;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.signserver.common.ArchiveData;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IProcessRequest;
import org.signserver.common.IProcessResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.ITimeSource;
import org.signserver.server.signtokens.ISignToken;
 

/**
 * A Signer signing TimeStamp request according to RFC 3161 using Bouncy Castle TimeStamp Api.
 * 
 * Implements a ISigner and have the following properties:
 * TIMESOURCE = property containing the classpath to the ITimeSource implementation that should be used. (default LocalComputerTimeSource)
 * ACCEPTEDALGORITHMS = A ';' separated string containing accepted algorithms, can be null if it shouldn't be used. (OPTIONAL)
 * ACCEPTEDPOLICIES =  A ';' separated string containing accepted policies, can be null if it shouldn't be used. (OPTIONAL)
 * ACCEPTEDEXTENSIONS = A ';' separated string containing accepted extensions, can be null if it shouldn't be used. (OPTIONAL)
 * DIGESTOID = The Digenst OID to be used in the timestamp
 * DEFAULTTSAPOLICYOID = The default policy ID of the time stamp authority
 * ACCURACYMICROS = Accuraty in micro seconds, Only decimal number format, only one of the accuracy properties should be set (OPTIONAL)
 * ACCURACYMILLIS = Accuraty in milli seconds, Only decimal number format, only one of the accuracy properties should be set (OPTIONAL)
 * ACCURACYSECONDS = Accuraty in seconds. Only decimal number format, only one of the accuracy properties should be set (OPTIONAL)
 * ORDERING = The ordering (OPTIONAL), default false.
 * TSA = General name of the Time Stamp Authority.
 * 
 * @author philip
 * $Id: TimeStampSigner.java,v 1.6 2007-11-09 15:47:15 herrvendil Exp $
 */
public class TimeStampSigner extends BaseSigner{
	
    /** Log4j instance for actual implementation class */
    public transient Logger log = Logger.getLogger(this.getClass());
    
    /** random generator algorithm */
    private static String algorithm = "SHA1PRNG";
    
    /** random generator */
    private SecureRandom random = null;
    
    private static final BigInteger lowest = new BigInteger("0080000000000000", 16);
    private static final BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);

	//Private Property constants
	public static final String TIMESOURCE          = "TIMESOURCE";
	public static final String ACCEPTEDALGORITHMS  = "ACCEPTEDALGORITHMS";
	public static final String ACCEPTEDPOLICIES    = "ACCEPTEDPOLICIES";
	public static final String ACCEPTEDEXTENSIONS  = "ACCEPTEDEXTENSIONS";
	//public static final String DEFAULTDIGESTOID    = "DEFAULTDIGESTOID";
	public static final String DEFAULTTSAPOLICYOID = "DEFAULTTSAPOLICYOID";
	public static final String ACCURACYMICROS      = "ACCURACYMICROS";
	public static final String ACCURACYMILLIS      = "ACCURACYMILLIS";
	public static final String ACCURACYSECONDS     = "ACCURACYSECONDS";
	public static final String ORDERING            = "ORDERING";
	public static final String TSA                 = "TSA";
	
	
    private static final String DEFAULT_TIMESOURCE          = "org.signserver.server.LocalComputerTimeSource";

    
    
    private static final String[] ACCEPTEDALGORITHMSNAMES = {"GOST3411", "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "RIPEMD128", "RIPEMD160", "RIPEMD256"};
    private static final String[] ACCEPTEDALGORITHMSOIDS = {TSPAlgorithms.GOST3411, TSPAlgorithms.MD5, TSPAlgorithms.SHA1, TSPAlgorithms.SHA224, 
    	                                                    TSPAlgorithms.SHA256, TSPAlgorithms.SHA384, TSPAlgorithms.SHA512, TSPAlgorithms.RIPEMD128, 
    	                                                    TSPAlgorithms.RIPEMD160, TSPAlgorithms.RIPEMD256};
    
    private static final HashMap<String, String> ACCEPTEDALGORITHMSMAP = new HashMap<String, String>();
    
    static{
    	for(int i= 0 ; i < ACCEPTEDALGORITHMSNAMES.length;  i++){
    		ACCEPTEDALGORITHMSMAP.put(ACCEPTEDALGORITHMSNAMES[i],ACCEPTEDALGORITHMSOIDS[i]);
    	}
    }
    
    
    
	private static final String DEFAULT_ORDERING    = "FALSE";
	//private static final String DEFAULT_DIGESTOID   = TSPAlgorithms.SHA1;
	
	private ITimeSource timeSource = null;
	private Set<String> acceptedAlgorithms = null;
	private Set<String> acceptedPolicies = null;
	private Set<String> acceptedExtensions = null;	
	
	//private String defaultDigestOID = null;
	private String defaultTSAPolicyOID = null;
	
	public void init(int signerId, WorkerConfig config) {
		super.init(signerId, config);
		// Check that the timestamp server is properly configured
	    timeSource = getTimeSource();
	    if(timeSource == null){
	    	log.error("Error: Timestamp signer :" + signerId + " has a malconfigured timesource.");
	    }
	    
/*	    defaultDigestOID = config.getProperties().getProperty(DEFAULTDIGESTOID);
		if(defaultDigestOID == null){
			defaultDigestOID = DEFAULT_DIGESTOID;
		}*/
	    
		defaultTSAPolicyOID = config.getProperties().getProperty(DEFAULTTSAPOLICYOID);
		if(defaultTSAPolicyOID == null){
			log.error( "Error: No default TSA Policy OID have been configured");
		}	
		
		
		
				                                 
	}

	/**
	 * The main method performing the actual timestamp operation.
	 * Expects the signRequest to be a GenericSignRequest contining a TimeStampRequest
	 * 
	 * @see org.signserver.server.signers.ISigner#signData(org.signserver.common.IProcessRequest, java.security.cert.X509Certificate)
	 */
	public IProcessResponse signData(IProcessRequest signRequest,
			X509Certificate clientCert) throws IllegalRequestException,
			SignTokenOfflineException {
		boolean returnbytearray = false;
		
		ISignRequest sReq = (ISignRequest) signRequest;
		// Check that the request contains a valid TimeStampRequest object.
		if(!(signRequest instanceof GenericSignRequest)){
			throw new IllegalRequestException("Recieved request wasn't a expected GenericSignRequest. ");
		}
		
		if(!((sReq.getRequestData() instanceof TimeStampRequest) ||
		    (sReq.getRequestData() instanceof byte[]))){
			throw new IllegalRequestException("Recieved request data wasn't a expected TimeStampRequest. ");
		}
		
		
		
		
		
        
        GenericSignResponse signResponse = null;
		try {
			TimeStampRequest timeStampRequest = null;
			if(sReq.getRequestData() instanceof byte[]){
				timeStampRequest = new TimeStampRequest((byte[]) sReq.getRequestData());
				returnbytearray = true;
			}else{
				timeStampRequest = (TimeStampRequest) sReq.getRequestData();
			}
			TimeStampTokenGenerator timeStampTokenGen = getTimeStampTokenGenerator(timeStampRequest);
			
			TimeStampResponseGenerator timeStampResponseGen = getTimeStampResponseGenerator(timeStampTokenGen);						
            
		    timeStampRequest.validate(this.getAcceptedAlgorithms(), this.getAcceptedPolicies(), this.getAcceptedExtensions(), "BC");
		    
		    TimeStampResponse timeStampResponse = timeStampResponseGen.generate(timeStampRequest,getSerialNumber(),getTimeSource().getGenTime(),getSignToken().getProvider(ISignToken.PROVIDERUSAGE_SIGN));
			if(returnbytearray){
				signResponse = new GenericSignResponse(sReq.getRequestID(),timeStampResponse.getEncoded(),getSigningCertificate(),
                        timeStampResponse.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16), new ArchiveData(timeStampResponse.getEncoded()));				
			}else{
			  signResponse = new GenericSignResponse(sReq.getRequestID(),timeStampResponse.getEncoded(),getSigningCertificate(),
					                               timeStampResponse.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16), new ArchiveData(timeStampResponse.getEncoded()));
			}
		} catch (InvalidAlgorithmParameterException e) {
			log.error("InvalidAlgorithmParameterException: ", e);
			throw new IllegalRequestException("InvalidAlgorithmParameterException: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error("NoSuchAlgorithmException: ", e);
			throw new IllegalRequestException("NoSuchAlgorithmException: " + e.getMessage());
		} catch (NoSuchProviderException e) {
			log.error("NoSuchProviderException: ", e);
			throw new IllegalRequestException("NoSuchProviderException: " + e.getMessage());
		} catch (SignTokenOfflineException e) {
			log.error("SignTokenOfflineException: ", e);
			throw new IllegalRequestException("SignTokenOfflineException: " + e.getMessage());
		} catch (CertStoreException e) {
			log.error("CertStoreException: ", e);
			throw new IllegalRequestException("CertStoreException: " + e.getMessage());
		} catch (IOException e) {
			log.error("IOException: ", e);
			throw new IllegalRequestException("IOException: " + e.getMessage());
		}catch(TSPException e){
			log.error("TSPException: ", e);
			throw new IllegalRequestException(e.getMessage());
		} 
		
		return signResponse;
	}




	/**
	 * Method returning a time source interface expected to provide accurate time.
	 */
	private ITimeSource getTimeSource(){
		if(timeSource == null){
			try{				
				String classpath =this.config.getProperties().getProperty(TIMESOURCE);
				if(classpath == null){
				  classpath = DEFAULT_TIMESOURCE;	
				}
				
				Class<?> implClass = Class.forName(classpath);
				Object obj = implClass.newInstance();
				timeSource = (ITimeSource) obj;
				timeSource.init(config.getProperties());								 
				
			}catch(ClassNotFoundException e){
				throw new EJBException(e);
			}
			catch(IllegalAccessException iae){
				throw new EJBException(iae);
			}
			catch(InstantiationException ie){
				throw new EJBException(ie);
			}			
		}
		
		return timeSource;		
	}
	
	@SuppressWarnings("unchecked")
	private Set<String> getAcceptedAlgorithms(){
		if(acceptedAlgorithms == null){
			String nonParsedAcceptedAlgorihms =  this.config.getProperties().getProperty(ACCEPTEDALGORITHMS);
			if(nonParsedAcceptedAlgorihms == null){
				acceptedAlgorithms = TSPAlgorithms.ALLOWED;
			}else{
				String[] subStrings = nonParsedAcceptedAlgorihms.split(";");
		    	if(subStrings.length > 0){
		    		acceptedAlgorithms = new HashSet();
		    		for(int i=0; i < subStrings.length ; i++){
		    			String algorithm = (String) ACCEPTEDALGORITHMSMAP.get(subStrings[i]);
		    			if (algorithm != null){
		    			  acceptedAlgorithms.add(algorithm);
		    			}else{
		    				log.error("Error, signer " + workerId + " configured with incompatible acceptable algorithm : " + subStrings[i]);
		    			}
		    		}
		    	}							    
			}
		}
		
		return acceptedAlgorithms;
	}
	

	private Set<String> getAcceptedPolicies(){
		if(acceptedPolicies == null){
			String nonParsedAcceptedPolicies =  this.config.getProperties().getProperty(ACCEPTEDPOLICIES);
			acceptedPolicies = makeSetOfProperty(nonParsedAcceptedPolicies);			
		}
		
		return acceptedPolicies;		
	
	}
	
	private Set<String> getAcceptedExtensions(){
		if(acceptedExtensions == null){
			String nonParsedAcceptedExtensions =  this.config.getProperties().getProperty(ACCEPTEDEXTENSIONS);
			acceptedExtensions = makeSetOfProperty(nonParsedAcceptedExtensions);			
		}
		
		return acceptedExtensions;		
	}
	
	/**
	 * Help method taking a string and creating a java.util.Set of the strings using ';' as a delimiter.
	 * If null is used as and argument then will null be returned by the method.
	 */
	private Set<String> makeSetOfProperty(String nonParsedPropery) {
		Set<String> retval = null;
	    if(nonParsedPropery != null){
	    	String[] subStrings = nonParsedPropery.split(";");
	    	if(subStrings.length > 0){
	    		retval = new HashSet<String>();
	    		for(int i=0; i < subStrings.length ; i++){
	    	       retval.add(subStrings[i]);		
	    		}
	    	}
	    	
	    }
		return retval;
	}
	
	private TimeStampTokenGenerator getTimeStampTokenGenerator(TimeStampRequest timeStampRequest) throws IllegalRequestException, SignTokenOfflineException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertStoreException{
		TimeStampTokenGenerator timeStampTokenGen = null;
			try {
				String digestOID= timeStampRequest.getMessageImprintAlgOID();
				/*if(digestOID == null){
					digestOID = defaultDigestOID;
				}*/
								
				String tSAPolicyOID = timeStampRequest.getReqPolicy();
				if(tSAPolicyOID == null){
					tSAPolicyOID = defaultTSAPolicyOID;
				}
				
				timeStampTokenGen = new TimeStampTokenGenerator(this.getSignToken().getPrivateKey(ISignToken.PURPOSE_SIGN), (X509Certificate) getSigningCertificate(), digestOID, tSAPolicyOID);
				
				
				if(config.getProperties().getProperty(ACCURACYMICROS) != null){
					timeStampTokenGen.setAccuracyMicros(Integer.parseInt(config.getProperties().getProperty(ACCURACYMICROS)));
				}
				
				if(config.getProperties().getProperty(ACCURACYMILLIS) != null){
					timeStampTokenGen.setAccuracyMillis(Integer.parseInt(config.getProperties().getProperty(ACCURACYMILLIS)));
				}
				
				if(config.getProperties().getProperty(ACCURACYSECONDS) != null){
					timeStampTokenGen.setAccuracySeconds(Integer.parseInt(config.getProperties().getProperty(ACCURACYSECONDS)));
				}
				
				if(config.getProperties().getProperty(ORDERING) != null){
					timeStampTokenGen.setOrdering(config.getProperties().getProperty(ORDERING, DEFAULT_ORDERING).equalsIgnoreCase("TRUE"));
				}

				if(config.getProperties().getProperty(TSA) != null){
					X509Name x509Name = new X509Name(config.getProperties().getProperty(TSA));
					timeStampTokenGen.setTSA(new GeneralName(x509Name));
				}
				
				CertStore certStore = CertStore.getInstance("Collection",
				        new CollectionCertStoreParameters(getSigningCertificateChain()), "BC");
				timeStampTokenGen.setCertificatesAndCRLs(certStore);	
				
			} catch (IllegalArgumentException e) {
				log.error("IllegalArgumentException: ", e);
				throw new IllegalRequestException(e.getMessage());
			} catch (TSPException e) {
				log.error("TSPException: ", e);
				throw new IllegalRequestException(e.getMessage());
			} 		
		return timeStampTokenGen;
	}
	
	private TimeStampResponseGenerator getTimeStampResponseGenerator(TimeStampTokenGenerator timeStampTokenGen) {
		return new TimeStampResponseGenerator(timeStampTokenGen, this.getAcceptedAlgorithms(), this.getAcceptedPolicies(), this.getAcceptedExtensions());

	}
	 
	
	/**
	 * Help method that generates a serial number using SecureRandom
	 */
	private BigInteger getSerialNumber(){
		BigInteger serialNumber = null;
		try{
		 serialNumber = getSerno();
		}catch(Exception e){
			log.error("Error initiating Serial Number generator, SEVERE ERROR.", e);
		}
		
		return serialNumber;
	}
	
    /**
     * Generates a number of serial number bytes. The number returned should be a positive number.
     *
     * @return a BigInteger with a new random serial number.
     */
    public BigInteger getSerno() {
    	if(random == null){
    		try {
				random = SecureRandom.getInstance(algorithm);
			} catch (NoSuchAlgorithmException e) {
				log.error(e);
			}
    	}
    	
        byte[] sernobytes = new byte[8];
        boolean ok = false;
        BigInteger serno = null;
        while (!ok) {
            random.nextBytes(sernobytes);
            serno = (new java.math.BigInteger(sernobytes)).abs();
            // Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
            if ( (serno.compareTo(lowest) >= 0) && (serno.compareTo(highest) <= 0) ) {
                ok = true;
            } 
        }
        return serno;
    }

    /**
     * Not supported yet
     */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException{
		return this.getSignToken().genCertificateRequest(info);
	}
}


	

	 
	