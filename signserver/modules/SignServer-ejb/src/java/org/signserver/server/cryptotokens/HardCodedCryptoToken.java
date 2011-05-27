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
import java.security.KeyStore;
import java.security.KeyStoreException;
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
import org.signserver.common.KeyTestResult;


/**
 * Class used for testing purposes, contains soft dummy key and certificates 
 * @author Philip Vendil
 * @version $Id$
 */

public class HardCodedCryptoToken implements ICryptoToken {

    public static final String KEY_ALIAS_1 = "key00001";
    public static final String KEY_ALIAS_2 = "key00002";
    
    /** CN=End Entity 1, O=Reversed Org, C=SE. **/
    public static final String KEY_ALIAS_3 = "key00003";

	public HardCodedCryptoToken(){}
	
	/**
	 * Hard coded keys used for testing purposes.
	 */
	
	
	
	private static byte[] passTestKey2 = Base64.decode((
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

        /**
         * friendlyName: Signer 4
         */
	private static byte[] passTestKey1 = Base64.decode((
	"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcIaVgAE9NbcnH"
	+ "rTtx2Qc8MkQZekoJeQjb3OPwHEIi8LfeTIZkHozsQgJT7u+3bTS7VOZKPHZq5N9k"
	+ "jqwDZwOwRKUyEon7yePa6PV/mD0xhFv4girUgiEMCtbAgKzCdmRYv/k1yCCDZs1y"
	+ "J0JuUPLlJRD7Ex5e0lBYJTxmfdr7JJlnVmJhnXSBS7klVqWy45vxilxP+moE8XRy"
	+ "ATLqYh7cA2iXPEso1QFgCxDNCcK+DH4aqBvNgejx+SmlIZQVVh0UjQwL0IFPvZ47"
	+ "HFCiC4gJZe6zwF0jB5tkMZB2W4q9M2yKDiEzf0bpa8+qgSL0jzpWFj2ZLJj5Y55T"
	+ "ljdmwLwJAgMBAAECggEAeAPhBHeYffNbvPKrlCr4xcv5zv/Ss49nQOJ+EE8Yg5U4"
	+ "MVfvojxdpSpkcbJkcEIw26M6Vmw9tpNyKPEGxqLEEhXiSig4CuU5EkgqlkcnGs4c"
	+ "iF0+oRXaY1BdnaILqnupTRNcdHv+iiNW313QUc5Ft+CTOfyLRuYxvl/5Guu5jXx0"
	+ "KgIj+ulLnETHz/ogXr2dhV3du+Rfz9HG1q8PWP86YxPcRzMNVkrrG/URBJGw3uax"
	+ "zgTDNOakb3z74iYRvmez4nbsAO+7jDwBGx29kUCEOg/Jp+8x7ih05vz8/5cH9Ovu"
	+ "6U4F4/rGKgTyP7fBPLYXAwVAycgklyFaSGgU/p/LJQKBgQDOy0DDE7DaIjs2PZ3l"
	+ "7AwfKw3laFu9QZr3FraZqpySdaIbbxQ9rCAfbOu3rzAsQ/8FmNQrVHKVGeDp0f+J"
	+ "AfkGYfn76Vwgpn1smu0+kr7dH+PPf/6b8n2Ye5fNsX9yAvOJBzQtEQKNeAcBzDV3"
	+ "V/DlVecS0hRLrOzYnYQUYjWowwKBgQDBSE+0u8yLi5Ku8G6XIQbGtsQ+JMHLvr2z"
	+ "Tnc7HFGkuCSjt8x6XuGAukCfg9iN0dSsmyRXMh2A8s/k9/ho2cKuIs886kSL2wnN"
	+ "h/sH1y1Lw8wKn22nSVX0S+cB77vYby74/stC8lCF7lOPhyekNeKv6qRCnuywZS0t"
	+ "YPiat+MbQwKBgQCSiSTTF1jyud8LiI4jJylPzMqEDXc0nRCaltW9/lAE2KaOmh/V"
	+ "s+rvWdeOye1w8J398VYnfifT0Aq4pb5V77fu9e6Wu740xMWL+By1gncNalOb7i8V"
	+ "grfNHYdskqKkv8KjDx/B75PHe447j+EzOHXTjRO5GnSXS2pp9PRrHUy40QKBgQCj"
	+ "e893VrW/frH2aIWSLSw3HlZFHgARnueD56WwCNcB1YOgOxGom+JvaJrKkdG0uzwB"
	+ "N0R4wHn2HOs9h4TE4xPpCKZzps+N4BqdjxwE2LuGbzmB7rHoIn6ioSTnHWisu/Zm"
	+ "Q9WXbbAwaJKjPzWHjtCL7ZM8ioI2/Y1F6dS9wTZGUwKBgB6dJg1Qa1b6+k2mrvBh"
	+ "Iq7eFk5mlqRhmh7yf5yWvkUj1YxSAjZE81hGQM7tMpydhGUqfn3Y3eLgg+gVWVrs"
	+ "hDH4pVgDu6HjP8/8aamBovAwkjoyl4FsngiI6mnwfVS1jo50B61/R43dxvnm6RGh"
	+ "LAImQIaJCYWP38dGiEkObuwU" ).getBytes());
	
	public static byte[] certbytes2 = Base64.decode((
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

        /**
         * subject=/CN=Signer 4/OU=Testing/O=SignServer/C=SE
         * issuer=/CN=DSS Root CA 10/OU=Testing/O=SignServer/C=SE
         */
	public static byte[] certbytes1 = Base64.decode((
	"MIIElTCCAn2gAwIBAgIITz1ZKtegWpgwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UE"
	+ "AwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNp"
	+ "Z25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA5NTE0NVoXDTIxMDUyNzA5"
	+ "NTE0NVowRzERMA8GA1UEAwwIU2lnbmVyIDQxEDAOBgNVBAsMB1Rlc3RpbmcxEzAR"
	+ "BgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEF"
	+ "AAOCAQ8AMIIBCgKCAQEAnCGlYABPTW3Jx607cdkHPDJEGXpKCXkI29zj8BxCIvC3"
	+ "3kyGZB6M7EICU+7vt200u1TmSjx2auTfZI6sA2cDsESlMhKJ+8nj2uj1f5g9MYRb"
	+ "+IIq1IIhDArWwICswnZkWL/5Ncggg2bNcidCblDy5SUQ+xMeXtJQWCU8Zn3a+ySZ"
	+ "Z1ZiYZ10gUu5JValsuOb8YpcT/pqBPF0cgEy6mIe3ANolzxLKNUBYAsQzQnCvgx+"
	+ "GqgbzYHo8fkppSGUFVYdFI0MC9CBT72eOxxQoguICWXus8BdIwebZDGQdluKvTNs"
	+ "ig4hM39G6WvPqoEi9I86VhY9mSyY+WOeU5Y3ZsC8CQIDAQABo38wfTAdBgNVHQ4E"
	+ "FgQUGqddBv2s8iEa5B98MVTbQ2HiFkAwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
	+ "gBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYw"
	+ "FAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQB8HpFOfiTb"
	+ "ylu06tg0yqvix93zZrJWSKT5PjwpqAU+btQ4fFy4GUBG6VuuVr27+FaFND3oaIQW"
	+ "BXdQ1+6ea3Nu9WCnKkLLjg7OjBNWw1LCrHXiAHdIYM3mqayPcf7ezbr6AMnmwDs6"
	+ "/8YAXjyRLmhGb23M8db+3pgTf0Co/CoeQWVa1eJObH7aO4/Koeg4twwbKG0MjwEY"
	+ "ZPi0ZWB93w/llEHbvMNI9dsQWSqIU7W56KRFN66WdqFhjdVPyg86NudH+9jmp4x1"
	+ "Ac9GKGNOYYfDnQCdsrJwZMvcI7bZykbd77ZC3zBzuaISAeRJq3rjHygSeKPHCYDW"
	+ "zAVEP9yaO0fL7HMZ2uqHxokvuOo5SxgVfvLr+kT4ioQHz+r9ehkCf0dbydm7EqyJ"
	+ "Y7YSFUDEqk57dnZDxy7ZgUA/TZf3I3rPjSopDxqiqJbm9L0GPW3zk0pAZx7dgLcq"
	+ "2I8fv+DBEKqJ47/H2V5aopxsRhiKC5u8nEEbAMbBYgjGQT/5K4mBt0gUJFNek7vS"
	+ "a50VH05u8P6yo/3ppDxGCXE2d2JfWlEIx7DRWWij2PuOgDGkvVt2soxtp8Lx+kS6"
	+ "K+G+tA5BGZMyEPdqAakyup7udi4LoB0wfJ58Jr5QNHCx4icUWvCBUM5CTcH4O/pQ"
	+ "oj/7HSYZlqigM72nR8f/gv1TwLVKz+ygzg==").getBytes());

        /** friendlyName: End Entity 1. */
        private static byte[] passTestKey3 = Base64.decode((
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZVx9KdiugO5Db"
	+ "omr6N2Ul3hA6KbNg98XOCKPj7ZNm8om4ke59a6nREV6etRbfcwb2KDAvXI42ZUbw"
	+ "jsyZ4ESwHoArrZ2BKcmwu/FJCbn4K3fRYj0QIJXTG0YNQcdeTA0vF7KMopecbmvX"
	+ "vqlBN9N35FEfVNW3SMNbCRJR+OyicuBASD5aIOCjpqOcy1AHVQI352Yjq3OJVnUC"
	+ "AlhNvgDTB5jly/mkMN6f+91Pjsdtz9ZZIb1P3Lh3JSTHydDV9b8/4U3F/goeGmzR"
	+ "91B9cAFvCptd/v+YUrZTihSsLdy9qfRfM6c8BsGjaa60r6SkEcX7a9ol4gUCwTDW"
	+ "3BgzDLTjAgMBAAECggEAbY1G98XxaSrlVWV2lImbJDDA2y0L0Q10Lr0RijgkBXrm"
	+ "Vg08nDKdQpbsSOsMClx97sPLmSrBF6/HvPnox07pBALmg04opy0ZwcCkpA/k4576"
	+ "nYdYJPuCzy4/IB2MuJwRF0IQ+FT5iHODbMH03nlqBdAC/SV5AtdjatjSU+pJ9cyI"
	+ "y3Iy2qSPq/jUXuHeI889GxUJ53vrfq5R4zknUItJSKY1zq6gUuBtl6NQuyPhDCSw"
	+ "ymqTbZX3sINQ4nZWimimd1V8MSyXOyJ1vfPhSuOHMSfSGuKmXiH9eiUuDDRQnnuX"
	+ "dhuMgHnKcxDO3p5AWNWGNr0iQlziDj6sYs76GOnCsQKBgQDuwKxebrI28toxeTmk"
	+ "Z8mXHn7WSlO61szJaN2WSrpGUSztZsfeh/qL4lfELNug33a47HEN75rybGo57BoP"
	+ "YUVs3hq9AkKynRpP2ulyP4PLOaJ05kIBAYcGmfNhGfrUD2YXblRaCcsXQJ6aym07"
	+ "V+w3R9wr2vpkUEQDvWpS3NvYvwKBgQCkauR7TUVs1ZIEoxpdFu/JNx499vHbN00N"
	+ "6BmJG4cR9H0mqdifanWMB2/C2EAzVscYKKUbEDRyoHraNI9OU+YmcfAZbU7Xm/qW"
	+ "Dq0IGNObhJfBJpttk0iWpnLjXxkUoNuLDNPfAPgamLUAFQJe2TsuYlx9Dg5YrEYd"
	+ "ZkcFVwto3QKBgAymCHu4QZjHpOeaFIOxO+zVoMKZjXYIizDgbVzY+KVhB5BMMaqI"
	+ "aa2fgCbUeY48SH3jiNnEJ+FP/RC0gWzvKk5qNeBtjjsIN6yjXFrBIqpRk1m+GSEU"
	+ "g6LF5S7vwWoapr33CmD6w9enhL+Omdra/ZiwJens3/cQiYnpLwjUypDhAoGAQ68p"
	+ "XcUClnoZAUWvnbDKh3fkQDf/enH6i4YHtRSa9v5B4v+6iG3H9Bw/muNxEnFfxoc8"
	+ "6LY0ERgVWuyWLfWF4j+3SpBgC4xPjSR/gLzPp87etgnRpDskf7gHxagpZ/+MQWLH"
	+ "eZ8pg7FnmaAMeMVOgprFXknCCCjrOEEZbY5WyRUCgYEAwaKNgARdd6tYH8hmjJR5"
	+ "SH0Kub4XwLM9K+JkxYpDTfRCV6YU1yv3Rhboi5vke2Tca2pQWJW6Wxa6I5f6sK9J"
	+ "gRwHAIC15UcWQbHC8aoZGKQarg/d/Gr9+b1TXe8dMR1lAtkg2VhMbo8lyvUQMrZL"
	+ "1aKMGuqUaTtDqXUuH7/GKEo="));
        
        /** friendlyName: End Entity 1.
            subject=/CN=End Entity 1/O=Reversed Org/C=SE
            issuer=/CN=ReversedCA1/O=Reversed Org/C=SE */
        public static byte[] certbytes3 = Base64.decode((
        "MIIC9TCCAl6gAwIBAgIINMqLj6H+R08wDQYJKoZIhvcNAQEFBQAwOjELMAkGA1UE"
	+ "BhMCU0UxFTATBgNVBAoMDFJldmVyc2VkIE9yZzEUMBIGA1UEAwwLUmV2ZXJzZWRD"
	+ "QTEwHhcNMTAxMjI5MTQzNTMxWhcNMTIxMjI4MTQzNTMxWjA7MQswCQYDVQQGEwJT"
	+ "RTEVMBMGA1UECgwMUmV2ZXJzZWQgT3JnMRUwEwYDVQQDDAxFbmQgRW50aXR5IDEw"
	+ "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZVx9KdiugO5Dbomr6N2Ul"
	+ "3hA6KbNg98XOCKPj7ZNm8om4ke59a6nREV6etRbfcwb2KDAvXI42ZUbwjsyZ4ESw"
	+ "HoArrZ2BKcmwu/FJCbn4K3fRYj0QIJXTG0YNQcdeTA0vF7KMopecbmvXvqlBN9N3"
	+ "5FEfVNW3SMNbCRJR+OyicuBASD5aIOCjpqOcy1AHVQI352Yjq3OJVnUCAlhNvgDT"
	+ "B5jly/mkMN6f+91Pjsdtz9ZZIb1P3Lh3JSTHydDV9b8/4U3F/goeGmzR91B9cAFv"
	+ "Cptd/v+YUrZTihSsLdy9qfRfM6c8BsGjaa60r6SkEcX7a9ol4gUCwTDW3BgzDLTj"
	+ "AgMBAAGjfzB9MB0GA1UdDgQWBBTWdUE9mxdwCzE1x2S0FLPj3hmiETAMBgNVHRMB"
	+ "Af8EAjAAMB8GA1UdIwQYMBaAFOMrANT2fK3JUR6mzTG7GJxo8YtFMA4GA1UdDwEB"
	+ "/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDQYJKoZIhvcN"
	+ "AQEFBQADgYEAYb+XG1aZICfEFGshGXKHHNTsISONrp1p7PhTIwlHut6COFJ3xecK"
	+ "yWVD5djfil3Gsi68t+2VeG81num9a0XdZgMkZPy3avBQCab9LmyII6BA0GNAuFJn"
	+ "WsUhUi4VgDaPyyhMVrzLoGgsTX2Dox/81/NfxTARuPYmOq7Dw7nqUS8="));

	
	private X509Certificate cert = null;
	
	private PrivateKey privateKey = null;
	
	public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {

            final String defaultKey;
            if (props == null) {
                defaultKey = KEY_ALIAS_1;
            } else {
                defaultKey = props.getProperty("defaultKey", KEY_ALIAS_1);
            }
            final byte[] certbytes;
            final byte[] passTestKey;

            if (KEY_ALIAS_3.equals(defaultKey)) {
                certbytes = certbytes3;
                passTestKey = passTestKey3;
            } else if (KEY_ALIAS_2.equals(defaultKey)) {
                certbytes = certbytes2;
                passTestKey = passTestKey2;
            } else {
                certbytes = certbytes1;
                passTestKey = passTestKey1;
            }

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
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info, 
                final boolean explicitEccParameters, final boolean defaultKey)
                throws CryptoTokenOfflineException {
		return null;
	}

	/**
	 * Method not supported
	 */
	public boolean destroyKey(int purpose) {
		return true;
	}

    public Collection<KeyTestResult> testKey(final String alias,
            final char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException(
                "Operation not supported by crypto token.");
    }
}
