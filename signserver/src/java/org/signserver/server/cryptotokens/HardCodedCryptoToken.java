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

package org.signserver.server.cryptotokens;
 
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;


import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignerStatus;


/**
 * Class used for testing purposes, contains soft dummy key and certificates 
 * @author Philip Vendil
 * @version $Id$
 */

public class HardCodedCryptoToken implements ICryptoToken {

	public HardCodedCryptoToken(){}
	
	/**
	 * Hard coded keys used for testing purposes.
	 */
	
	
	/*
	private static byte[] passTestKey = Base64.decode((
	"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDmZqPJNogVtiRZ" +
	"9loOFJ7UPMsrqWXZZ8R+nTPB72+kQ+4qOpgUHfto7QpSbs9/9wGrUsxc/mpadt/g" +
	"RTztl6FWGQ4TknOkoDFP+MilP08u5ZbOJrbN3E7vy0dEszzO9aHLBHXV1w2pWTlV" +
	"V2kWABpl4R4lfyWBroqpahhSReOrgL/utgcVgWkpYYb9Rx67aSl83F3lNZBMUTGR" +
	"4gi/eQ5zug+VYDDWLyBPw7jymspQ+RwbeDaR7k8lS4sRI/QgJtVTDtzMgTPlfvWD" +
	"QIxofdkiZnG3t30aDxif5O3qaUbwMSA4Jfo6xgc2f+NPdFjhYarRTezNB8D4J4yT" +
	"02U5bI6HAgMBAAECggEAaRoZTQibO4xDOOawXgv6CEdTRy+XTn2PnVKI8ccP3pc+" +
	"ZfUkusiSj2LSepgh//XlxQmYQDOuwGXJ6ryq9pdc+bGkQjlkl4yb8idDIF6o+HOz" +
	"P4dZjL8bIzhP4n8BFkfm7n2yY0Ie8UnKZaviPC7/28m9vs0phubgSjgjsCRBn1HW" +
	"hRwEFyjUXiKQYBZak/6AMUNrU/3fNOD5XZfRF56ppRNEUxq42ltUQidcKrPnKYgo" +
	"xpJ8iFTm+NvGJdV6svoDZXsdR74PTEZYaxw9+4K6Cj7mXiFehsJqMjahTJtAh7Vx" +
	"JL/U5+g/dJXXhTRaM10cDXn8ly81mV0iCIyb2YNQgQKBgQD7mATdp+9j7FFzfVKh" +
	"70ld/hTeBLwa2sx/55jt+iK98cDAUzWZ36rwgO2MqSSmk1gwTnGG8JPMTO0NW3AU" +
	"Qs7ozIubU1zichOXyyrKJPPSoKuVUD1KhqdOtX33kTIh0Hf3/9Xk025VH3zuzOZY" +
	"SkdouNhhS9ZEa6xnJjS5xTI4uQKBgQDqb5sX3R8b2pAfiKp67Xn6oMuAf5lsPYWr" +
	"CFTmBwjk2w5Ch9ffDeixtp+od6H3XzxWVfAfIYM1YtxpAfw11VtLaHPAC16fmBbc" +
	"O9jZa5um5qDkg1xbvuXCekD7Hbb/juxA/+zxpZGWTegQ+0taVUanZBrCXdAIXF4j" +
	"zc+uWObhPwKBgQCkDNrXYUJSKGxv3r67wlhXhm462mGBLTv9BpmMSvbOXc1uWpNv" +
	"0w0WJys99ahlSVxOm0ehUks9AsfrVrz9KRbba0x4qmG9cd7esmYjSvcFVyiqgpiE" +
	"eMqtIuCRRcanj9Q6DEJ/I3Ik5RREbayg00Y+vZCx2I5NLNxMofftTezSWQKBgGw8" +
	"zwx7iQthI72LabqLvg+bAZn4T6uL1BUdKaVyhgazpKfO9DoFv/Oc76XmZh9CFyd9" +
	"UfntjRiu5jiNNBbexOHR/e8i0LM6kwNnljz708eBH7OhepjZUFcz/qByHbVsFWQF" +
	"RS5kVQ1iNszwWOACEzbhnwEyMwRJMSWytjo2zZIdAoGACPzW59zxy2lyVWbJIjXa" +
	"Frf7tI8+FffkudTPxU/zNbJJqHlprTlqv7aeHn8gYO+++8HkJVksvBRMR3DVjF7h" +
	"Bstg/zzNoMZgzxjL+afGxe4KNcfTmoXFm/rG2WCEio+H4AF3g9QyQUxpvaLXG7VW" +
	"VI42L5Hy2MkUE1Mw7GfDoy4=").getBytes());*/

	private static byte[] passTestKey = Base64.decode((
	"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIUQj9LZl/yZQHm9" +
	"QSrg+o/Ir+F2UQrEamEL5Q307kS+AsrB+9mLYZhFY3vqIo21aZmxKdtPa/d1ML0u" +
	"E2Ykz0L1QGJ1MO5Wux+EOKwoj0+JsI/nkfCMbgDmYK79h11REc7quin3U2K0wm5t" +
	"XAaDus8X7ZRwp4wm7gP+tllUS4SrAgMBAAECgYAvSZVy/vTuRaAOI12XWWBx3IX0" +
	"f9GJHAgZ+NorvZE3SLdBSvKvesLyFCaokKo65e9jOPyA/ZaG2FS7xjYKpKYqwt96" +
	"1l5Vyd3dloaTFEDjjp/ZJgbmEwDKICXudqCH7PyCaCB+SofXUYmD7Ss7OxtqZtjY" +
	"MoXQ1IYwhPPFDJyjoQJBAPWXbC1Fzpx7LFisISbcmNlDt1qQg7GgOxq8IokRkqUm" +
	"1e/faRCXq8ZJmQfR9UnsESEWsCOWZ8gO2SKCvSiH8tMCQQCKtEPMDKtX/I3MjkMW" +
	"wkIX0ivTjPn9tFM6av0X2ppQELQINe/vZLRuplLfOnAgKuGNi712e+yHPpvugsX1" +
	"Lo/JAkEAk/Mx1yA7tOc7MvwXSKsSZai2t5dhzsshcBywjXSJrHZ14XjseXN1pxHF" +
	"YAGrTGorc4yQdg/w24OeaXzraZRkwwJBAIBC/+qh0JR1g76j0yAplKqofESNOeNE" +
	"rC36H36+dDITsBdjoTNTgZJMlZe9V1A3twmILjRxliDeYZ1mKp52ZxkCQD0gyo9r" +
	"gbE9jGM7yKu169PZXNpWN0YP3UPM+ctqNkKe2l2hK0rCopoymxJGthba9iKhzHCZ" +
	"FHqzLUsiKmWnrwY=" ).getBytes());
	
	/*private static byte[] certbytes = Base64.decode((
	"MIID7zCCAqigAwIBAgIIWOzgRTcR/iAwPAYJKoZIhvcNAQEKMC+gDzANBglghkgB" +
	"ZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFADA/MRMwEQYDVQQD" +
	"EwpTZXRlY1Rlc3QyMRswGQYDVQQKExJSaWtzcG9saXNzdHlyZWxzZW4xCzAJBgNV" +
	"BAYTAlNFMB4XDTA1MDkxMjA5MTg1MloXDTE1MDkwOTA5Mjg1MlowZzEcMBoGA1UE" +
	"AxMTVGVzdCBhdiBFeHByZXNzUGFzczEOMAwGA1UEBRMFMTIzNDUxDTALBgNVBAsT" +
	"BFBhc3MxGzAZBgNVBAoTElJpa3Nwb2xpc3N0eXJlbHNlbjELMAkGA1UEBhMCU0Uw" +
	"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDmZqPJNogVtiRZ9loOFJ7U" +
	"PMsrqWXZZ8R+nTPB72+kQ+4qOpgUHfto7QpSbs9/9wGrUsxc/mpadt/gRTztl6FW" +
	"GQ4TknOkoDFP+MilP08u5ZbOJrbN3E7vy0dEszzO9aHLBHXV1w2pWTlVV2kWABpl" +
	"4R4lfyWBroqpahhSReOrgL/utgcVgWkpYYb9Rx67aSl83F3lNZBMUTGR4gi/eQ5z" +
	"ug+VYDDWLyBPw7jymspQ+RwbeDaR7k8lS4sRI/QgJtVTDtzMgTPlfvWDQIxofdki" +
	"ZnG3t30aDxif5O3qaUbwMSA4Jfo6xgc2f+NPdFjhYarRTezNB8D4J4yT02U5bI6H" +
	"AgMBAAGjaTBnMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUKvx2IjcjhAFFpp80" +
	"ytO9KsC+rGgwHwYDVR0jBBgwFoAU19fDl5KAW2KqbuIHGG24AL+RfvAwFQYDVR0g" +
	"BA4wDDAKBggqhXBUCgEBATA8BgkqhkiG9w0BAQowL6APMA0GCWCGSAFlAwQCAQUA" +
	"oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAA4IBAQBIH8UOXoaZ/ImkF6Co" +
	"eIII6KHsd+5CAro0hiBXDAkuLmPSVHp6jgv7chv0W7CL89veu7Vy+7aow1hVkGC9" +
	"XTmgrCGiKzw9+XGJsunLmAMhLj/QztnkJgQBo/09geM+w5UTdR+5PP9nRs9oJtlU" +
	"FCOcN8VJEeIvgDyWoMUDG7K1YvjmkEU6CPVYrL2PAdY0bPZvTIymC1HuyPmMnf83" +
	"QKHW0KKtb4uhkruTkX87yZm7fZZXfso6HeUKQ0+fbcqmQdXFEcJJEKSHTCcu5BVj" +
	"JebCC2FiSP88KPGGW5D351LJ+UL8En3oA5eHxZCy/LeGejPw0N02XjVFfBZEKnf6" +
	"5a94").getBytes());*/

	public static byte[] certbytes = Base64.decode((
	"MIIC5DCCAcygAwIBAgIIfZgsZqV8NDAwDQYJKoZIhvcNAQEFBQAwNzERMA8GA1UE" +
	"AxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNhbXBsZTELMAkGA1UEBhMCU0Uw" +
	"HhcNMDYwNjAzMTUzMzM5WhcNMjYwNTI5MTU0MzM5WjA3MRYwFAYDVQQDEw10aW1l" +
	"c3RhbXB0ZXN0MR0wGwYDVQQKExRQcmltZUtleSBTb2x1dGlvbiBBQjCBnzANBgkq" +
	"hkiG9w0BAQEFAAOBjQAwgYkCgYEAhRCP0tmX/JlAeb1BKuD6j8iv4XZRCsRqYQvl" +
	"DfTuRL4CysH72YthmEVje+oijbVpmbEp209r93UwvS4TZiTPQvVAYnUw7la7H4Q4" +
	"rCiPT4mwj+eR8IxuAOZgrv2HXVERzuq6KfdTYrTCbm1cBoO6zxftlHCnjCbuA/62" +
	"WVRLhKsCAwEAAaN4MHYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwFgYD" +
	"VR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFOrxsQleE90vW4I2FC4cDim/" +
	"hKjhMB8GA1UdIwQYMBaAFNrdQb5Q2K3ZL/KD+leV040azuwPMA0GCSqGSIb3DQEB" +
	"BQUAA4IBAQB5WKwHfItwzbU3gdsszZ1V0yfnc9znP8De8fOjBHaGdgO3wxo2zB0G" +
	"JbgcyvVeJ5kecZRZcM+/bTNraWFGlCTkaqLD+1pMeVc1oBbtR5hevuykA+OR7RKS" +
	"mUZ7CadXnZjkDRgN8XsP5doDOpV2ZunLfrPCx61mJ3GxG6gvuMutOd7U2BN2vbMr" +
	"VMNxWOftXR/XyJAJxY0YOgplV8hOkW+Ky0MyAe2ktFnOOuMIMKhLgrN338ZeAXRs" +
	"2lhcc/p79imDL5QkPavZWrcnNZpT506DDyzn1cf68HpJNF1ICY57hWmx79gbIFhe" +
	"mJxVZp+eyws3H9Yb9o2pLs7EOS7n+X26" ).getBytes());
	
	private X509Certificate cert = null;
	
	private PrivateKey privateKey = null;
	
	public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
		
		try
		{
	        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
	        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certbytes));			
			
			PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(passTestKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(pkKeySpec);
			
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoTokenInitializationFailureException("NoSuchAlgorithmException: " + e.getMessage());
		} catch (InvalidKeySpecException e) {
			throw new CryptoTokenInitializationFailureException("InvalidKeySpecException: " + e.getMessage());
		}catch (CertificateException e) {
			throw new CryptoTokenInitializationFailureException("CertificateException: " + e.getMessage());
        } catch (NoSuchProviderException e) {
			throw new CryptoTokenInitializationFailureException("NoSuchProviderException: " + e.getMessage());
		}   

	}

	/**
	 * Always returns ICryptoToken.STATUS_ACTIVE
	 */
	public int getCryptoTokenStatus() {
		return SignerStatus.STATUS_ACTIVE;
	}

	
	/**
	 * Not used in current implementation
	 */
	public void activate(String authenticationcode)
			throws CryptoTokenAuthenticationFailureException,
			CryptoTokenOfflineException {
        if(authenticationcode.equals("9876")){
        	throw new CryptoTokenAuthenticationFailureException(""); 
        }

	}

	/**
	 * Not used in current implementation
	 */	
	public boolean deactivate() {	
		return true;
	}

	/**
	 * Returns the private part of the testkey
	 * 
	 * @param purpose not used
	 */
	public PrivateKey getPrivateKey(int purpose)
			throws CryptoTokenOfflineException {
		return privateKey;
	}

	/**
	 * Returns the public part of the testkey
	 * 
	 * @param purpose not used
	 */
	public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {

		return cert.getPublicKey();
	}

	public String getProvider(int providerUsage) {
		return "BC";
	}

	public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {		
		return cert;
	}

	/**
	 * Not supported
	 */
	public Collection<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
		ArrayList<Certificate> certs = new ArrayList<Certificate>();
		certs.add(cert);
		return certs;
	}

	/**
	 * Method not supported
	 */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException {
		return null;
	}

	/**
	 * Method not supported
	 */
	public boolean destroyKey(int purpose) {
		return true;
	}

}
