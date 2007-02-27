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

package org.signserver.server.signtokens;
 
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
import java.util.Collection;
import java.util.Properties;

import javax.ejb.EJBException;

import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.SignerStatus;


/**
 * Class used for testing purposes, contains soft dummy key and certificates 
 * @author Philip Vendil
 * @version $Id: HardCodedSignToken.java,v 1.1 2007-02-27 16:18:27 herrvendil Exp $
 */

public class HardCodedSignToken implements ISignToken {

	public HardCodedSignToken(){}
	
	/**
	 * Hard coded keys used for testing purposes.
	 */
	
	
	
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
	"VI42L5Hy2MkUE1Mw7GfDoy4=").getBytes());

	private static byte[] certbytes = Base64.decode((
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
	"5a94").getBytes());

	
	
	
	private X509Certificate cert = null;
	
	private PrivateKey privateKey = null;
	
	public void init(Properties props)  {
		
		try
		{
	        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
	        cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certbytes));			
			
			PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(passTestKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(pkKeySpec);
			
		} catch (NoSuchAlgorithmException e) {
			throw new EJBException(e);
		} catch (InvalidKeySpecException e) {
			throw new EJBException(e);
		}catch (CertificateException e) {
			throw new EJBException(e);
        } catch (NoSuchProviderException e) {
			throw new EJBException(e);
		}   

	}

	/**
	 * Always returns ISignToken.STATUS_ACTIVE
	 */
	public int getSignTokenStatus() {
		return SignerStatus.STATUS_ACTIVE;
	}

	
	/**
	 * Not used in current implementation
	 */
	public void activate(String authenticationcode)
			throws SignTokenAuthenticationFailureException,
			SignTokenOfflineException {
        // Do nothing

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
			throws SignTokenOfflineException {
		return privateKey;
	}

	/**
	 * Returns the public part of the testkey
	 * 
	 * @param purpose not used
	 */
	public PublicKey getPublicKey(int purpose) throws SignTokenOfflineException {

		return cert.getPublicKey();
	}

	public String getProvider() {
		return "BC";
	}

	public Certificate getCertificate(int purpose) throws SignTokenOfflineException {		
		return cert;
	}

	/**
	 * Not supported
	 */
	public Collection getCertificateChain(int purpose) throws SignTokenOfflineException {
		return null;
	}

	/**
	 * Method not supported
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException {		
		return null;
	}

}
