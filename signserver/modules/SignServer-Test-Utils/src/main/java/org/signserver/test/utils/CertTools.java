/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.test.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.asn1.x509.X509NameTokenizer;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * This class contains some utility methods from CertTools that are using
 * patched BouncyCastle packages, meening they currently conflicts when building
 * with Maven, since the BouncyCastle version bundled with the version of
 * CESeCore is patched with functionallity from newer versions.
 * 
 * TODO: this should be removed when we upgrade CESeCore
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class CertTools {
    private static final Logger log = Logger.getLogger(org.signserver.test.utils.CertTools.class);
    
    
    /** Flag indicating if the BC provider should be removed before installing it again. When developing and re-deploying alot
     * this is needed so you don't have to restart JBoss all the time. 
     * In production it may cause failures because the BC provider may get removed just when another thread wants to use it.
     * Therefore the default value is false. 
     */
    private static final boolean developmentProviderInstallation = BooleanUtils.toBoolean("@development.provider.installation@");
    
    /** Parameters used when generating or verifying ECDSA keys/certs using the "implicitlyCA" key encoding.
     * The curve parameters is then defined outside of the key and configured in the BC provider.
     */
    private static String IMPLICITLYCA_Q = "@ecdsa.implicitlyca.q@";
    private static String IMPLICITLYCA_A = "@ecdsa.implicitlyca.a@"; 
    private static String IMPLICITLYCA_B = "@ecdsa.implicitlyca.b@"; 
    private static String IMPLICITLYCA_G = "@ecdsa.implicitlyca.g@"; 
    private static String IMPLICITLYCA_N = "@ecdsa.implicitlyca.n@";
    
    /** System provider used to circumvent a bug in Glassfish. Should only be used by 
     * X509CAInfo, OCSPCAService, XKMSCAService, CMSCAService. 
     * Defaults to SUN but can be changed to IBM by the installBCProvider method.
     */
    public static String SYSTEM_SECURITY_PROVIDER = "SUN";
    
    /**
     * Generate a selfsigned certiicate.
     *
     * @param dn subject and issuer DN
     * @param validity in days
     * @param policyId policy string ('2.5.29.32.0') or null
     * @param privKey private key
     * @param pubKey public key
     * @param sigAlg signature algorithm, you can use one of the contants CATokenInfo.SIGALG_XXX
     * @param isCA boolean true or false
     *
     * @return X509Certificate, self signed
     *
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     * @throws SignatureException DOCUMENT ME!
     * @throws InvalidKeyException DOCUMENT ME!
     * @throws IllegalStateException 
     * @throws CertificateEncodingException 
     * @throws NoSuchProviderException 
     */

    public static X509Certificate genSelfCert(String dn, long validity, String policyId,
            PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA) 
        	throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    	return genSelfCert(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, "BC");
    }
    public static X509Certificate genSelfCert(String dn, long validity, String policyId,
        PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, String provider) 
    	throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
        int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
    	return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, provider);
    } //genselfCert

    /**
     * Generate a selfsigned certiicate with possibility to specify key usage.
     *
     * @param dn subject and issuer DN
     * @param validity in days
     * @param policyId policy string ('2.5.29.32.0') or null
     * @param privKey private key
     * @param pubKey public key
     * @param sigAlg signature algorithm, you can use one of the contants CATokenInfo.SIGALG_XXX
     * @param isCA boolean true or false
     * @param keyusage as defined by constants in X509KeyUsage
     *
     * @return X509Certificate, self signed
     *
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     * @throws SignatureException DOCUMENT ME!
     * @throws InvalidKeyException DOCUMENT ME!
     * @throws IllegalStateException 
     * @throws CertificateEncodingException 
     * @throws NoSuchProviderException 
     */

    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId,
    		PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage)
    				throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    	return genSelfCertForPurpose(dn, validity, policyId, privKey, pubKey, sigAlg, isCA, keyusage, "BC");
    }
    
    // TODO: fix usage of deprecated stuff (see commented-out WIP code below this method)
    public static X509Certificate genSelfCertForPurpose(String dn, long validity, String policyId,
            PrivateKey privKey, PublicKey pubKey, String sigAlg, boolean isCA, int keyusage, String provider)
            throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
            // Create self signed certificate
            Date firstDate = new Date();

            // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
            firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));

            Date lastDate = new Date();

            // validity in days = validity*24*60*60*1000 milliseconds
            lastDate.setTime(lastDate.getTime() + (validity * (24 * 60 * 60 * 1000)));

            X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();
            
            // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be 
            // a CVC public key that is passed as parameter
            PublicKey publicKey = null; 
            if (pubKey instanceof RSAPublicKey) {
            	RSAPublicKey rsapk = (RSAPublicKey)pubKey;
        		RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(rsapk.getModulus(), rsapk.getPublicExponent());        
        		try {
    				publicKey = KeyFactory.getInstance("RSA").generatePublic(rSAPublicKeySpec);
    			} catch (InvalidKeySpecException e) {
    				log.error("Error creating RSAPublicKey from spec: ", e);
    				publicKey = pubKey;
    			}			
    		} else if (pubKey instanceof ECPublicKey) {
    			ECPublicKey ecpk = (ECPublicKey)pubKey;
    			try {
    				ECPublicKeySpec ecspec = new ECPublicKeySpec(ecpk.getW(), ecpk.getParams()); // will throw NPE if key is "implicitlyCA"
    				publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
    			} catch (InvalidKeySpecException e) {
    				log.error("Error creating ECPublicKey from spec: ", e);
    				publicKey = pubKey;
    			} catch (NullPointerException e) {
    				log.debug("NullPointerException, probably it is implicitlyCA generated keys: "+e.getMessage());
    				publicKey = pubKey;
    			}
    		} else {
    			log.debug("Not converting key of class. "+pubKey.getClass().getName());
    			publicKey = pubKey;
    		}

            // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
            // bean is created.
            byte[] serno = new byte[8];
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed((new Date().getTime()));
            random.nextBytes(serno);
            certgen.setSerialNumber((new java.math.BigInteger(serno)).abs());
            certgen.setNotBefore(firstDate);
            certgen.setNotAfter(lastDate);
            certgen.setSignatureAlgorithm(sigAlg);
            certgen.setSubjectDN(CertTools.stringToBcX509Name(dn));
            certgen.setIssuerDN(CertTools.stringToBcX509Name(dn));
            certgen.setPublicKey(publicKey);

            // Basic constranits is always critical and MUST be present at-least in CA-certificates.
            BasicConstraints bc = new BasicConstraints(isCA);
            certgen.addExtension(Extension.basicConstraints, true, bc);

            // Put critical KeyUsage in CA-certificates
            if (isCA == true) {
                X509KeyUsage ku = new X509KeyUsage(keyusage);
                certgen.addExtension(Extension.keyUsage, true, ku);
            }

            // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
            try {
                if (isCA == true) {
                    SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
                                new ByteArrayInputStream(publicKey.getEncoded())).readObject());
                    SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki.getEncoded());

                    SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
                                new ByteArrayInputStream(publicKey.getEncoded())).readObject());
                    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

                    certgen.addExtension(Extension.subjectKeyIdentifier, false, ski);
                    certgen.addExtension(Extension.authorityKeyIdentifier, false, aki);
                }
            } catch (IOException e) { // do nothing
            }

            // CertificatePolicies extension if supplied policy ID, always non-critical
            if (policyId != null) {
                    PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policyId));
                    DERSequence seq = new DERSequence(pi);
                    certgen.addExtension(Extension.certificatePolicies, false, seq);
            }

            X509Certificate selfcert = certgen.generate(privKey, provider);

            return selfcert;
        } //genselfCertForPurpose

    /** See stringToBcX500Name(String, X509NameEntryConverter), this method uses the default BC converter (X509DefaultEntryConverter)
     * @see #stringToBcX500Name(String, X509NameEntryConverter)
     * @param dn String containing DN that will be transformed into X509Name, The
     *          DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *          the string will be added to the end positions of OID array.
     * 
     * @return X509Name or null if input is null
     */
    public static X509Name stringToBcX509Name(String dn) {
    	X509NameEntryConverter converter = new X509DefaultEntryConverter();
    	return stringToBcX509Name(dn, converter);    	
    }
    
    /**
     * Creates a (Bouncycastle) X500Name object from a string with a DN. Known OID
     * (with order) are:
     * <code> EmailAddress, UID, CN, SN (SerialNumber), GivenName, Initials, SurName, T, OU,
     * O, L, ST, DC, C </code>
     * To change order edit 'dnObjects' in this source file. Important NOT to mess
     * with the ordering within this class, since cert vierification on some
     * clients (IE :-() might depend on order.
     * 
     * @param dn
     *          String containing DN that will be transformed into X509Name, The
     *          DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
     *          the string will be added to the end positions of OID array.
     * @param converter BC converter for DirectoryStrings, that determines which encoding is choosen
     * @return X509Name or null if input is null
     */
    private static X509Name stringToBcX509Name(String dn, X509NameEntryConverter converter) {
    	return stringToBcX509Name(dn, converter, true);
    }
    
    public static X509Name stringToBcX509Name(final String dn, final X509NameEntryConverter converter, final boolean ldaporder) {

        if (dn == null) {
            return null;
        }

        final Vector<ASN1ObjectIdentifier> defaultOrdering = new Vector<>();
        final Vector<String> values = new Vector<>();
        final X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(dn);

        while (x509NameTokenizer.hasMoreTokens()) {
            // This is a pair key=val (CN=xx)
            final String pair = x509NameTokenizer.nextToken(); // Will escape '+' and initial '#' chars
            final int index = pair.indexOf('=');

            if (index != -1) {
                final String key = pair.substring(0, index).toLowerCase().trim();
                String val = pair.substring(index + 1);
                if (val != null) {
                    // String whitespace from the beginning of the value, to handle the case
                    // where someone type CN = Foo Bar
                    val = StringUtils.stripStart(val, null);
                }

                try {
                    // -- First search the OID by name in declared OID's
                    ASN1ObjectIdentifier oid = DnComponents.getOid(key);
                    // -- If isn't declared, we try to create it
                    if (oid == null) {
                        oid = new ASN1ObjectIdentifier(key);
                    }
                    defaultOrdering.add(oid);
                    values.add(getUnescapedPlus(val));
                } catch (IllegalArgumentException e) {
                    // If it is not an OID we will ignore it
                    log.warn("Unknown DN component ignored and silently dropped: " + key);
                }

            } else {
                log.warn("Huh, what's this? DN: " + dn + " PAIR: " + pair);
            }
        }

        final X509Name x509Name = new X509Name(defaultOrdering, values, converter);

        // -- Reorder fields
        final X509Name orderedX509Name = getOrderedX509Name(x509Name, ldaporder, converter);

        // log.trace("<stringToBcX509Name");
        return orderedX509Name;
    } // stringToBcX509Name

    // Remove extra '+' character escaping
    private static String getUnescapedPlus(final String value) {
        StringBuilder buf = new StringBuilder(value);
        int index = 0;
        int end = buf.length();
        while (index < end) {
            if (buf.charAt(index) == '\\' && index + 1 != end) {
                char c = buf.charAt(index + 1);
                if (c == '+') {
                    buf.deleteCharAt(index);
                    end--;
                }
            }
            index++;
        }
        return buf.toString();
    }
    
    /**
     * Obtain a X509Name reordered, if some fields from original X509Name doesn't appear in "ordering" parameter, they will be added at end in the
     * original order.
     * 
     * @param x509Name the X509Name that is unordered
     * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
     *            order is the reverse
     * @return X509Name with ordered conmponents according to the orcering vector
     */
    private static X509Name getOrderedX509Name(final X509Name x509Name, boolean ldaporder, final X509NameEntryConverter converter) {
        // -- Null prevent
        // Guess order of the input name
        final boolean isLdapOrder = !isDNReversed(x509Name.toString());
        // -- New order for the X509 Fields
        final List<ASN1ObjectIdentifier> newOrdering = new ArrayList<>();
        final List<Object> newValues = new ArrayList<>();
        // -- Add ordered fields
        @SuppressWarnings("unchecked")
        final Vector<ASN1ObjectIdentifier> allOids = x509Name.getOIDs();
        // If we think the DN is in LDAP order, first order it as a LDAP DN, if we don't think it's LDAP order
        // order it as a X.500 DN
        final List<ASN1ObjectIdentifier> ordering = getX509FieldOrder(isLdapOrder);
        final HashSet<ASN1ObjectIdentifier> hs = new HashSet<>(allOids.size() + ordering.size());
        for (final ASN1ObjectIdentifier oid : ordering) {
            if (!hs.contains(oid)) {
                hs.add(oid);
                @SuppressWarnings("unchecked")
                final Vector<Object> valueList = x509Name.getValues(oid);
                // -- Only add the OID if has not null value
                for (final Object value : valueList) {
                    newOrdering.add(oid);
                    newValues.add(value);
                }
            }
        }
        // -- Add unexpected fields to the end
        for (final ASN1ObjectIdentifier oid : allOids) {
            if (!hs.contains(oid)) {
                hs.add(oid);
                @SuppressWarnings("unchecked")
                final Vector<Object> valueList = x509Name.getValues(oid);
                // -- Only add the OID if has not null value
                for (final Object value : valueList) {
                    newOrdering.add(oid);
                    newValues.add(value);
                    if (log.isDebugEnabled()) {
                        log.debug("added --> " + oid + " val: " + value);
                    }
                }
            }
        }
        // If the requested ordering was the reverse of the ordering the input string was in (by our guess in the beginning)
        // we have to reverse the vectors
        if (ldaporder != isLdapOrder) {
            if (log.isDebugEnabled()) {
                log.debug("Reversing order of DN, ldaporder=" + ldaporder + ", isLdapOrder=" + isLdapOrder);
            }
            Collections.reverse(newOrdering);
            Collections.reverse(newValues);
        }
        // -- Return X509Name with the ordered fields
        return new X509Name(new Vector<>(newOrdering), new Vector<>(newValues), converter);
    } //

    
    /**
     * Tries to determine if a DN is in reversed form. It does this by taking the last attribute 
     * and the first attribute. If the last attribute comes before the first in the dNObjects array
     * the DN is assumed to be in reversed order.
     * The check if a DN is revered is relative to the default ordering, so if the default ordering is:
     * "C=SE, O=PrimeKey, CN=Tomas" (dNObjectsReverse ordering in EJBCA) a dn or form "CN=Tomas, O=PrimeKey, C=SE" is reversed.
     * 
     * if the default ordering is:
     * "CN=Tomas, O=PrimeKey, C=SE" (dNObjectsForward ordering in EJBCA) a dn or form "C=SE, O=PrimeKey, CN=Tomas" is reversed.
     * 
     *
     * @param dn String containing DN to be checked, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
     *
     * @return true if the DN is believed to be in reversed order, false otherwise
     */
    protected static boolean isDNReversed(String dn) {
    	/*if (log.isTraceEnabled()) {
    		log.trace(">isDNReversed: dn: " + dn);
    	}*/
        boolean ret = false;
        if (dn != null) {
            String first = null;
            String last = null;
            X509NameTokenizer xt = new X509NameTokenizer(dn);
            if (xt.hasMoreTokens()) {
            	first = xt.nextToken();
            }
            while (xt.hasMoreTokens()) {
                last = xt.nextToken();
            }
            String[] dNObjects = DnComponents.getDnObjects(false);
            if ( (first != null) && (last != null) ) {
            	first = first.substring(0,first.indexOf('='));
            	last = last.substring(0,last.indexOf('='));
            	int firsti = 0, lasti = 0;
            	for (int i = 0; i < dNObjects.length; i++) {
            		if (first.toLowerCase().equals(dNObjects[i])) {
            			firsti = i;
            		}
            		if (last.toLowerCase().equals(dNObjects[i])) {
            			lasti = i;
            		}
            	}
            	if (lasti < firsti) {
            		ret = true;
            	}
            	
            }
        }
        /*if (log.isTraceEnabled()) {
        	log.trace("<isDNReversed: " + ret);
        }*/
        return ret;
    } //isDNReversed
    
    /**
     * Obtains a Vector with the DERObjectIdentifiers for 
     * dNObjects names, in the specified order
     * 
     * @param ldaporder if true the returned order are as defined in LDAP RFC (CN=foo,O=bar,C=SE), otherwise the order is a defined in X.500 (C=SE,O=bar,CN=foo).
     * @return Vector with DERObjectIdentifiers defining the known order we require
     */
    public static Vector getX509FieldOrder(boolean ldaporder){
      Vector fieldOrder = new Vector();
      String[] dNObjects = DnComponents.getDnObjects(ldaporder);
        for (String dNObject : dNObjects) {
            fieldOrder.add(DnComponents.getOid(dNObject));
        }
      return fieldOrder;
    }
    
    /**
     * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
     *
     * @param cert byte array containing certificate in binary (DER) format
     * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
     *
     * @return Certificate
     *
     * @throws CertificateException if the byte array does not contain a proper certificate.
     * @throws IOException if the byte array cannot be read.
     */
    public static Certificate getCertfromByteArray(byte[] cert, String provider)
        throws CertificateException {
    	/*if (log.isTraceEnabled()) {
    		log.trace(">getCertfromByteArray");
    	}*/
        Certificate ret = null;
        String prov = provider;
        if (provider == null) {
        	prov = "BC";
        }
        try {
            CertificateFactory cf = CertTools.getCertificateFactory(prov);
            ret = cf.generateCertificate(new ByteArrayInputStream(cert));        	
        } catch (CertificateException e) {
        	log.debug("Certificate exception trying to read X509Certificate.");
        }
        if (ret == null) {
        	// We could not create an X509Certificate, see if it is a CVC certificate instead
            try {
            	CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
            	ret = new CardVerifiableCertificate(parsedObject);
			} catch (ParseException | ConstructionException | IllegalArgumentException e) {
	        	log.info("Certificate exception trying to read CVCCertificate: ", e);
	        	throw new CertificateException("Certificate exception trying to read CVCCertificate", e);
			}
        }
        if (ret == null) {
        	throw new CertificateException("No certificate found");
        }
        //log.trace("<getCertfromByteArray");
        return ret;
    } // getCertfromByteArray
    
    public static Certificate getCertfromByteArray(byte[] cert)
        throws CertificateException {
    	return getCertfromByteArray(cert, "BC");
    }
    
    public static CertificateFactory getCertificateFactory(String provider) {
    	String prov = provider;
    	if (provider == null) {
    		prov = "BC";
    	}
    	if (StringUtils.equals(prov, "BC")) {
        	installBCProviderIfNotAvailable();    		
    	}
        try {
            return CertificateFactory.getInstance("X.509", prov);
        } catch (NoSuchProviderException nspe) {
            log.error("NoSuchProvider: ", nspe);
        } catch (CertificateException ce) {
            log.error("CertificateException: ", ce);
        }
        return null;
    }
    
    public static CertificateFactory getCertificateFactory() {
    	return getCertificateFactory("BC");
    }
    
    public static synchronized void installBCProviderIfNotAvailable() {
    	if (Security.getProvider("BC") == null) {
    		installBCProvider();
    	}
    }
    
    public static synchronized void removeBCProvider() {
        Security.removeProvider("BC");  
        // Also remove the CVC provider
        Security.removeProvider("CVC");
    }
    public static synchronized void installBCProvider() {
    	// Also install the CVC provider
    	try {
        	Security.addProvider(new CVCProvider());    		
    	} catch (Exception e) {
    		log.info("CVC provider can not be installed, CVC certificate will not work: ", e);
    	}
    	
        // A flag that ensures that we install the parameters for implcitlyCA only when we have installed a new provider
        boolean installImplicitlyCA = false;
        if (Security.addProvider(new BouncyCastleProvider()) < 0) {
            // If already installed, remove so we can handle redeploy
            // Nope, we ignore re-deploy on this level, because it can happen
            // that the BC-provider is uninstalled, in just the second another
            // thread tries to use the provider, and then that request will fail.
            if (developmentProviderInstallation) {
                removeBCProvider();
                if (Security.addProvider(new BouncyCastleProvider()) < 0) {
                    log.error("Cannot even install BC provider again!");
                } else {
                    installImplicitlyCA = true;
                }
            }
        } else {
            installImplicitlyCA = true;
        }
        if (installImplicitlyCA) {
            // Install EC parameters for implicitlyCA encoding of EC keys, we have default curve parameters if no new ones have been given.
            // The parameters are only used if implicitlyCA is used for generating keys, or verifying certs
            checkImplicitParams();
            ECCurve curve = new ECCurve.Fp(
                    new BigInteger(IMPLICITLYCA_Q), // q
                    new BigInteger(IMPLICITLYCA_A, 16), // a
                    new BigInteger(IMPLICITLYCA_B, 16)); // b
            org.bouncycastle.jce.spec.ECParameterSpec implicitSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
                    curve,
                    curve.decodePoint(Hex.decode(IMPLICITLYCA_G)), // G
                    new BigInteger(IMPLICITLYCA_N)); // n
            ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");
            if (config != null) {
                config.setParameter(ConfigurableProvider.EC_IMPLICITLY_CA, implicitSpec);                                               
            } else {
                log.error("Can not get ConfigurableProvider, implicitlyCA EC parameters NOT set!");
            }                
        }
        
        // 2007-05-25
        // Finally we must configure SERIALNUMBER behavior in BC >=1.36 to be the same
        // as the behavior in BC 1.35, it changed from SN to SERIALNUMBER in BC 1.36
        // We must be backwards compatible
        // TODO: should this be removed?
        X509Name.DefaultSymbols.put(X509Name.SN, "SN");
        
        // We hard specify the system security provider in a few cases (see SYSTEM_SECURITY_PROVIDER). 
        // If the SUN provider does not exist, we will always use BC.
        Provider p = Security.getProvider(CertTools.SYSTEM_SECURITY_PROVIDER);
        if (p == null) {
        	log.debug("SUN security provider does not exist, using BC as system default provider.");
        	SYSTEM_SECURITY_PROVIDER = "BC";
        }
        
    }
    
    /** Check if parameters have been set correctly during pre-process, otherwise log an error and
     * set default values. Mostly used to be able to do JUnit testing
     */
    private static void checkImplicitParams() {
        if (StringUtils.contains(IMPLICITLYCA_Q, "ecdsa.implicitlyca.q")) {
        	log.info("IMPLICITLYCA_Q not set, using default.");
        	IMPLICITLYCA_Q = "883423532389192164791648750360308885314476597252960362792450860609699839";
        }
        if (StringUtils.contains(IMPLICITLYCA_A, "ecdsa.implicitlyca.a")) {
        	log.info("IMPLICITLYCA_A not set, using default.");
        	IMPLICITLYCA_A = "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc";
        }
        if (StringUtils.contains(IMPLICITLYCA_B, "ecdsa.implicitlyca.b")) {
        	log.info("IMPLICITLYCA_B not set, using default.");
        	IMPLICITLYCA_B = "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a";
        }
        if (StringUtils.contains(IMPLICITLYCA_G, "ecdsa.implicitlyca.g")) {
        	log.info("IMPLICITLYCA_G not set, using default.");
        	IMPLICITLYCA_G = "020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf";
        }
        if (StringUtils.contains(IMPLICITLYCA_N, "ecdsa.implicitlyca.n")) {
        	log.info("IMPLICITLYCA_N not set, using default.");
        	IMPLICITLYCA_N = "883423532389192164791648750360308884807550341691627752275345424702807307";
        }
    }
}
