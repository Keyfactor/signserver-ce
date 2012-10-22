/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.tsa;

import java.util.Date;
import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 *
 * @author Marcus Lundblad
 */
public class MSAuthCodeTimeStampSignerTest extends TestCase {
    
    private static int SIGNER_ID = 1000;
    private static int REQUEST_ID = 42;
    private static final String REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(MSAuthCodeTimeStampSignerTest.class);
	private static final String SIGN_CERT = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";
	private static final String SIGN_CERT_CHAIN = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ;MIIFfzCCA2egAwIBAgIIMk1BOK8CwTwwDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzA4MTQyN1oXDTM2MDUyNzA4MTQyN1owTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgblgjTTkMp1QAhgWDprhvqE9zX1Ux/A/RTOu4G4f6CTkd6JEEkbdKZv+CKv4cRoVCtfO3wnOokFRw/1JMmHHiQ1Z//uDoDjo8jk8nek0ArFE9R5NT02wMJCQa/mP1wU9ZSl1tx3jQRUFB+rTNeCcPTft+1FL7UjYMdkRzl261IOlmXzDMA+EYIGJ2c2wYhOv2DqfQygNz5GOf0EFqlQZIt/pzopSS+0K8mNb53ROhg9GJujwzugSH5Z+r0fsVHbCV0QUkZBfkRo9KMcdaDEPa8xpYTjsFPqU6RcnGkVABhn8OS8SIWw2re1f+htj6p9EGbk1m0I9pWGBA9ktWnrqlqDXV+tEhhh1O4f+LHieoxiscrF7RXxlYqyam6oabfXsX3VAC0M1UkwIciE8wA1Sj/+dgoSMqvEDNDfwpEYt6l8Z8czDTWDi7MM2u5VY0nP3+A+PepKrOtrdaGSP396f4a7A3un1o6nQWHsyWQ7kc8GIn8zN5nykQaghGyYlHHYe1XUSPtHmxjbdsyztrkIis3cfjFne0XgPAiQuYx3T/B+po9BhGIUwCV0Qi/gWVN6NkydsbzMeRXELQYyK+lHgIGiEaBzQRRtXbnB+wQXi2IacJNdKqICwDsl/PvvcZI9ZV6pB/KIzB+8IJm0CLY24K0OXJs3Bqij8gmpvbI+o0wUCAwEAAaNjMGEwHQYDVR0OBBYEFCB6Id7orbsCqPtxWKQJYrnYWAWiMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUIHoh3uituwKo+3FYpAliudhYBaIwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQAxFvpOZF6Kol48cQeKWQ48VAe+h5dmyKMfDLDZX51IRzfKKsHLpFPxzGNw4t9Uv4YOR0CD9z81dR+c93t1lwwIpKbx9Qmq8jViHEHKYD9FXThM+cVpsT25pg35m3ONeUX/b++l2d+2QNNTWMvdsCtaQdybZqbYFIk0IjPwLLqdsA8Io60kuES4JnQahPdLkfm70rgAdmRDozOfSDaaWHY20DovkfvKUYjPR6MGAPD5w9dEb4wp/ZjATblyZnH+LTflwfftUAonmAw46E0Zgg143sO6RfOOnbwjXEc+KXd/KQ6kTQ560mlyRd6q7EIDYRfD4n4agKV2R5gvVPhMD0+IK7kagqKNfWa9z8Ue2N3MedyWnb9wv4wC69qFndGaIfYADkUykoOyLsVVteJ70PVJPXO7s66LucfD2R0wo2MpuOYCsTOm7HHS+uZ9VjHl2qQ0ZQG89Xn+AXnzPbk1INe2z0lq3hzCW5DTYBKsJEexErzMpLwiEqUYJUfR9EeCM8UPMtLSqz1utdPoIYhULGzt5lSJEpMHMbquYfWJxQiKCbvfxQsP5dLUMEIqTgjNdo98OlM7Z7zjYH9Kimz3wgAKSAIoQZr7Oy1dMHO5GK4jBtZ8wgsyyQ6DzQQ7R68XFVKarIW8SATeyubAP+WjdMwk/ZXzsDjMZEtENaBXzAefYA==";
	private static final String KEY_DATA = "AAABJjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ09/BhvIv2xp7hTMJznYPnGhzJHTwWnEXQWiIIMDD3xOdEjmdky6wxByaLcWHWux0tPrV+XSHGpZhGApbP6bR8zuU0KanUU7k6saeXDAN+/coQ9Dqk1TQJh67z4/SMrZLaALQf8XI8JEUx2oGgpoOUljXCyslVHLe523kQOcg0iULAgBBhzWWyedLwE4NQ0BMik/Oxin0gbHJQNFiCCBzLfP0kYabFGcREmslOmAOCgsVbXsRecfgjiwegs85URvSQPFqV/cioCDLDAwLHLCS4iz44RE+YcABZuWUX0EBvSyNOkDUxqrpLk5Q22K0BgFEeWV1tNFjR34EtNAo1ArtECAwEAAQAABMEwggS9AgEAMA0GCSqGSIb3DQEBAQUABIIEpzCCBKMCAQACggEBAJ09/BhvIv2xp7hTMJznYPnGhzJHTwWnEXQWiIIMDD3xOdEjmdky6wxByaLcWHWux0tPrV+XSHGpZhGApbP6bR8zuU0KanUU7k6saeXDAN+/coQ9Dqk1TQJh67z4/SMrZLaALQf8XI8JEUx2oGgpoOUljXCyslVHLe523kQOcg0iULAgBBhzWWyedLwE4NQ0BMik/Oxin0gbHJQNFiCCBzLfP0kYabFGcREmslOmAOCgsVbXsRecfgjiwegs85URvSQPFqV/cioCDLDAwLHLCS4iz44RE+YcABZuWUX0EBvSyNOkDUxqrpLk5Q22K0BgFEeWV1tNFjR34EtNAo1ArtECAwEAAQKCAQBwMW7zXDDiROU/3pOcEHegIGgMltaqWNdaNk22RLRjaf/v2nAGio8tUq91NbUkWs22TaaNwxqchtrd+CXDMha0IarAboMhAQs8NUbl+mpgO3CRLCOO1goZfha+4gV0F50nnnMC9KxyHm0qWqX/TFyRw2aVF9uofz4lnMjgVFJKTaQkm1v6Odmhb/IqNQmjbmGHsfKcJHFwy667euzJkyr2Nh/9CBuIjmS4/8NsqdnXjugp5pBVvu7qoS7GlU5FgXohEV80OdsxLNVVw86K6FC/9+U6f7qoeULS9k0sGgH26UNUluiPPqXLgHj/HlGHWOYPqqWJwS3vL9sAwyULto3VAoGBAO5bsl/5BEGTUdNNEORTEaqT1GA23HjhlBwFOoJMeHzxoEyahPKwvyrDKB5LpIMu7Ll+YfIpPDPnZn5h11zcuYAzPWFY9oLYzq50lrHh0i7IgJ+4jPRtkdD2IcR52g+YpeczxHqWpZZCM2Um3fmAJBrkE8pGxl1lKw2G8I3yYOCrAoGBAKjhVmXlDaJfTJP5080+pP0WbZAqifI7NK63bKeLkzgSppOUus11pHmRLqB9Pm/+jVAssFsqOp7QptUYzt6SBgWT/QF1gFkp8oHVWBp6/WpVu0xInB94QWs99y/b5oHRjJOtYiodtd6pLyEM29Y/3iy/rseXTPuFlcnS1HBc50ZzAoGAOOtIw0ZRz98AMTc8C2oS0+sNUhSHvY4QskhFWowsUZnZr7FOgi3W2L1VvTZPCMyR1xHpDczvBW4CubdfmFtVKNoTlEWMSF7BrENHIR9N88IJhRqq/kuUAJRmJ+b5PbQ0GevwxV1oGWOhpkwLweLpvEout6UDBZZ9G3PXye3RWJUCgYBTp8v0jZJDbJGye36/nNh9xi5fy7Kpm0ptgc8A79LtY8/AK1ydijj/PzuppGDZeW7m2DxD7Jc9NH5v8OoItqzk9nnNzzbU9EJ8rgIGnAYMNouhLhaoQBmn1fosavG0POk1/h0yX6VHtubxqDz91IVqBUm+9OPddD7OyvEQ9/RYoQKBgQCOlHxw0uHMma/P/4Z8nyjyRF3vqzn/UpOMc1Z402yYK9ZcR7zPFHlrHC/6FACJJQpwnzDj24fNAJFrwl3usohj08hGn6NF7nTi8v4pFZHnt5pUIfXA4e4QIVO00Tv+GK+BMl3F+jsGUJK/TsccyoMht25o74oJDD6a7IcVTRnxTA==";
    
	private static final String SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
	private static final String CONTENT_TYPE_OID = "1.2.840.113549.1.9.3";
	private static final String SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
	private static final String MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4";

	
    public MSAuthCodeTimeStampSignerTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }


    /**
     * Test of processData method, of class MSAuthCodeTimeStampSigner.
     */
    public void testProcessData() throws Exception {
        System.out.println("processData");
        
        SignServerUtil.installBCProvider();
        
        final String CRYPTOTOKEN_CLASSNAME =
                "org.signserver.server.cryptotokens.HardCodedCryptoToken";
        
        ProcessRequest signRequest = null;
        
        final GlobalConfigurationSessionMock globalConfig
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalConfig);
        
        final WorkerConfig config = new WorkerConfig();
        config.setProperty("NAME", "TestMSAuthCodeTimeStampSigner");
        config.setProperty("AUTHTYPE", "NOAUTH");
        config.setProperty("SIGNINGCERTIFICATE", SIGN_CERT);
        config.setProperty("SIGNERCERTCHAIN", SIGN_CERT_CHAIN);
        config.setProperty("KEYDATA", KEY_DATA);
        config.setProperty("DEFAULTTSAPOLICYOID", "1.2.3");
        config.setProperty("TIMESOURCE", "org.signserver.server.ZeroTimeSource");
        
        
        workerMock.setupWorker(SIGNER_ID, CRYPTOTOKEN_CLASSNAME, config,
                    new MSAuthCodeTimeStampSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
        workerMock.reloadConfiguration(SIGNER_ID);
        
        // create sample hard-coded request
        signRequest = new GenericSignRequest(REQUEST_ID, REQUEST_DATA.getBytes());
        
        GenericSignResponse resp = (GenericSignResponse) workerMock.process(SIGNER_ID, signRequest, new RequestContext());
        
        // check that the response contains the needed attributes
        byte[] buf = resp.getProcessedData();
        ASN1Sequence asn1seq = ASN1Sequence.getInstance(Base64.decode(buf));
        
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1seq.getObjectAt(0));
        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(asn1seq.getObjectAt(1));
        
        assertEquals("Invalid OID in response", SIGNED_DATA_OID, oid.getId());
        
        ASN1Sequence asn1seq1 = ASN1Sequence.getInstance(ato.getObject());

        ASN1Set asn1set = ASN1Set.getInstance(asn1seq1.getObjectAt(4));
        ASN1Sequence asn1seq2 = ASN1Sequence.getInstance(asn1set.getObjectAt(0));
        ASN1TaggedObject ato1 = ASN1TaggedObject.getInstance(asn1seq2.getObjectAt(3));
        ASN1Sequence asn1seq3 = ASN1Sequence.getInstance(ato1.getObject());
        ASN1Sequence asn1seq4 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(0));
        ASN1Sequence asn1seq5 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(1));
        ASN1Sequence asn1seq6 = ASN1Sequence.getInstance(asn1seq3.getObjectAt(2));
        
        ASN1ObjectIdentifier ctOID = ASN1ObjectIdentifier.getInstance(asn1seq4.getObjectAt(0));
        assertEquals("Invalid OID for content type", CONTENT_TYPE_OID, ctOID.getId());
        
        ASN1ObjectIdentifier stOID = ASN1ObjectIdentifier.getInstance(asn1seq5.getObjectAt(0));
        assertEquals("Invalid OID for signing time", SIGNING_TIME_OID, stOID.getId());
        
        ASN1ObjectIdentifier mdOID = ASN1ObjectIdentifier.getInstance(asn1seq6.getObjectAt(0));
        assertEquals("Invalid OID for content type", MESSAGE_DIGEST_OID, mdOID.getId());
        
        // get signing time from response
        ASN1Set set = ASN1Set.getInstance(asn1seq5.getObjectAt(1));
        ASN1Encodable t = set.getObjectAt(0);
        Time t2 = Time.getInstance(t);
        Date d = t2.getDate();
        
        // the expected time (the "starting point" of time accoring to java.util.Date, consistent with the behavior of ZeroTimeSource
        Date d0 = new Date(0);
        
        assertEquals("Unexpected signing time in response", d0, d);
    }
}
