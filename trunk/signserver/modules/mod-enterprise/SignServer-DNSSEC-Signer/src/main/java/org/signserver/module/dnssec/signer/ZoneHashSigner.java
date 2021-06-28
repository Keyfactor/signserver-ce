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
package org.signserver.module.dnssec.signer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.*;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.common.data.ReadableData;
import static org.signserver.module.dnssec.common.ZoneHelper.RR_DNSKEY_Z1_ALGORITHM;
import static org.signserver.module.dnssec.common.ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME;
import static org.signserver.module.dnssec.common.ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT;
import static org.signserver.module.dnssec.common.ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME;
import static org.signserver.module.dnssec.common.ZoneHelper.RR_NSEC3PARAM;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;

/**
 * A Signer to use for client-side hashing of Zone or ZoneZip files.
 * 
 * Input is either a Pre-request or a Request.
 * 
 * Protocol:
 * 
 *   Client sends a "PreSignRequest":
 *   . Metadata: ZSK_SEQUENCE_NUMBER=1, SOA_TTL=86400
 *   . Body is empty
 *   Server responds with a "PreSignResponse":
 *   . DNSKEY records + SIG records
 *   . SIG record data: expireTime, signingTime, footprint, algorithm
 *   . NSEC3PARAM could also be returned from server as a convenience and to us the server RNG
 *   Client constructs the SignRequest:
 *   . Same -zsk-seq-no as in 1.
 *   . Same SIG record data as received in 2.
 *   . Map from each RRsetId to hash that should be signed. The hash is calculated using the SIG record data received in 2. and the RRset.
 *   Server verifies that the received foot print is correct (should be as zsk-seq-no is the same) and verified that the signingTime and expireTime are reasonable (i.e. now or in the past but not more than say 2 hour back or so). This check is not a security feature as the client is in control of the signingTime and expireTime etc values used.
 *   Server signs each hash and responds with a SignResponse:
 *   . Map from the same ID:s provided in the request to the signature values
 *   Client constructs each SIG record and inserts the signature received from the server.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ZoneHashSigner extends BaseZoneSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ZoneHashSigner.class);
    
    /** Content-type for the produced data. */
    private static final String CONTENT_TYPE = "text/plain";
    
    private String signatureAlgorithmJava;

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        try {
            signatureAlgorithmJava = getJavaHashSignatureAlgorithm(config.getProperty(PROPERTY_SIGNATUREALGORITHM, DEFAULT_NULL));
        } catch (IllegalArgumentException e) {
            configErrors.add("Unsupported signature algorithm: " +
                             config.getProperty(PROPERTY_SIGNATUREALGORITHM));
        }
    }
    
    private String getJavaHashSignatureAlgorithm(String signatureAlgorithmString) {
        if (signatureAlgorithmString == null) {
            return "NONEwithRSA";
        } else {
            switch (signatureAlgorithmString.toLowerCase(Locale.ENGLISH)) {
                case "sha1withrsa":
                case "sha256withrsa":
                case "sha512withrsa":
                    return "NONEwithRSA";
                default:
                    throw new IllegalArgumentException("Unsupported signature algorithm");
            }
        }
    }
    
    @Override
    protected void signData(ReadableData requestData, RequestContext requestContext, OutputStream out, List<ICryptoInstance> zskCryptoInstances, List<ICryptoInstance> kskCryptoInstances) throws TextParseException, NoSuchAlgorithmException,
                   FileNotFoundException, IOException, DNSSEC.DNSSECException,
                   IllegalArgumentException, IllegalRequestException, InvalidKeyException, SignatureException {
        
        try (InputStream in = requestData.getAsInputStream()) {
        
            final RequestMetadata requestMetaData = RequestMetadata.getInstance(requestContext);
            BaseZoneFileServerSideSigner.getZskSequenceNumber(requestContext);
            // TODO: REQUEST_VERSION==1        

            final KeyPair zsk1KeyPair = new KeyPair(zskCryptoInstances.get(0).getPublicKey(), zskCryptoInstances.get(0).getPrivateKey());

            final Properties requestBody = new Properties();
            requestBody.load(in);
            
            /// DUPLICATED from BaseZoneFileServerSideSigner
            System.setProperty("dnsjava.options", "multiline");

            // Times
            final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));

            // Comment this out for testing with fixed data (should be removed before release)
            if (fixedTime != null) {
                cal.setTimeInMillis(fixedTime);
                LOG.warn("Using fixed time: " + fixedTime);
            }

            // Use current time for signing and current time + 1 Month for expiration
            final Date timeSigned = cal.getTime();
            cal.add(Calendar.MONTH, 1);
            final Date expire = cal.getTime();
            /// END-DUPLICATED
            
            final Properties response = new Properties(); // XXX: Performance: Response is in memory!
            final String version = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);
            
            // Pre-request
            if (requestBody.isEmpty()) {
                /// DUPLICATED
                // Create the salt
                final byte[] salt;
                if (decodedSalt == null) {
                    if (random == null) {
                        random = SecureRandom.getInstance(RANDOM_ALGORITHM);
                    }
                    salt = new byte[8];
                    random.nextBytes(salt);
                } else {
                    salt = decodedSalt;
                }

                // NSEC params
                final NSEC3PARAMRecord nsec3Params =
                        new NSEC3PARAMRecord(Name.fromString(zoneName),
                                             DClass.IN, 0, NSEC3Record.Digest.SHA1, 0, 10,
                                             salt);
                // END-DUPLICATED

                final int soaTTL;

                try {
                    soaTTL = Integer.parseInt(requestMetaData.get("SOA_TTL"));
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Illegal SOA_TTL value", e);
                }

                dnskeyZSK1 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk1KeyPair.getPublic());

                /// DUPLICATED
                // Key-pairs for ZSK1 and ZSK2
                //final KeyPair zsk1KeyPair = new KeyPair(zskCryptoInstances.get(0).getPublicKey(), zskCryptoInstances.get(0).getPrivateKey());
                final PublicKey zsk2PublicKey = zskCryptoInstances.get(1).getPublicKey();
                //final DNSKEYRecord dnskeyZSK1 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithm, zsk1KeyPair.getPublic());
                final DNSKEYRecord dnskeyZSK2 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk2PublicKey);
                // END-DUPLICATED
                
                final DNSKEYRecord dnskeyZSK0;
                if (zskCryptoInstances.size() > 2) {
                    final PublicKey zsk0PublicKey = zskCryptoInstances.get(2).getPublicKey();
                    dnskeyZSK0 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, zsk0PublicKey);
                } else {
                    dnskeyZSK0 = null;
                }
                
                // Response metadata
                print(response, RR_DNSKEY_Z1_EXPIRETIME, String.valueOf(expire.getTime()));
                print(response, RR_DNSKEY_Z1_SIGNINGTIME, String.valueOf(timeSigned.getTime()));
                print(response, RR_DNSKEY_Z1_FOOTPRINT, String.valueOf(dnskeyZSK1.getFootprint()));
                print(response, RR_DNSKEY_Z1_ALGORITHM, String.valueOf(dnskeyZSK1.getAlgorithm()));

                // DNSKEY ZSK (1)
                print(response, "rr.dnskey.z1", dnskeyZSK1);

                // DNSKEY ZSK (2)
                print(response, "rr.dnskey.z2", dnskeyZSK2);
                
                // DNSKEY ZSK (0)
                if (dnskeyZSK0 != null) {
                    print(response, "rr.dnskey.z0", dnskeyZSK0);
                }

                // DNSKEY KSK (1-2)
                final RRset dnskeySet = new RRset();
                int k = 0;
                for (ICryptoInstance kskCrypto : kskCryptoInstances) {
                    final DNSKEYRecord dnskeyKSK = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, 0x101, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, kskCrypto.getPublicKey());
                    dnskeySet.addRR(dnskeyKSK);
                    print(response, "rr.dnskey.k" + ++k, dnskeyKSK);
                }

                // ZSK1 and ZSK2
                dnskeySet.addRR(dnskeyZSK1);
                dnskeySet.addRR(dnskeyZSK2);
                if (dnskeyZSK0 != null) {
                    dnskeySet.addRR(dnskeyZSK0);
                }
                
                // RRSIG DNSKEY ZSK
                final Record sigDnskeyZSK =  DNSSEC.sign(dnskeySet, dnskeyZSK1, zsk1KeyPair.getPrivate(), timeSigned, expire);
                //putType(typesMap, nsec3Params, prevName, Type.RRSIG);
                print(response, "rr.dnskey.sig.z1", sigDnskeyZSK);

                // RRSIG DNSKEY KSK & ZSK
                k = 0;
                for (ICryptoInstance kskCrypto : kskCryptoInstances) {
                    final DNSKEYRecord dnskeyKSK = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soaTTL, 0x101, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithmDnssec, kskCrypto.getPublicKey()); // XXX: Duplicate
                    final Record sigDnskeyKSK =  DNSSEC.sign(dnskeySet, dnskeyKSK, kskCrypto.getPrivateKey(), timeSigned, expire);
                    //putType(typesMap, nsec3Params, currentName, Type.RRSIG);
                    print(response, "rr.dnskey.sig.k" + ++k, sigDnskeyKSK);
                }

                // Insert NSEC3 param
                print(response, RR_NSEC3PARAM, nsec3Params);
                final RRSIGRecord sig = DNSSEC.sign(new RRset(nsec3Params), dnskeyZSK1, zsk1KeyPair.getPrivate(), timeSigned, expire);
                print(response, "rr.nsec3param.sig", sig);
                //putType(typesMap, nsec3Params, prevName, Type.NSEC3PARAM);
                //putType(typesMap, nsec3Params, prevName, Type.DNSKEY);            

                
            } else { // Request
                // Check expected request metadata
                if (requestMetaData.get(RR_DNSKEY_Z1_FOOTPRINT) == null) {
                    throw new IllegalRequestException("Missing request metadata property " + RR_DNSKEY_Z1_FOOTPRINT);
                }
                if (!String.valueOf(dnskeyZSK1.getFootprint()).equals(requestMetaData.get(RR_DNSKEY_Z1_FOOTPRINT))) {
                    throw new IllegalRequestException("Requested key in request does not match pre-request");
                }
                // TODO: Check expireTime (RR_DNSKEY_Z1_EXPIRETIME)
                // TODO: Check that signing time is reasonable (RR_DNSKEY_Z1_SIGNINGTIME)
                // TODO: Check algorithm (RR_DNSKEY_Z1_ALGORITHM)
                
                final ICryptoInstance crypto = zskCryptoInstances.get(0);                
                final String sigAlg = signatureAlgorithmJava == null ? getDefaultSignatureAlgorithm(crypto.getPublicKey()) : signatureAlgorithmJava;
                final PrivateKey privKey = crypto.getPrivateKey();
                
                final Enumeration<String> propertyNames = (Enumeration<String>) requestBody.propertyNames();
                
                while (propertyNames.hasMoreElements()) {
                    final String property = propertyNames.nextElement();
                    if (property.startsWith("hash.") && property.length() > "hash.".length()) {
                        final String id = property.substring("hash.".length());
                        
                        final String base64Hash = requestBody.getProperty(property);
                        final byte[] input = Base64.decode(base64Hash);

                        final Signature signature = Signature.getInstance(sigAlg, crypto.getProvider());
                        signature.initSign(privKey);
                        signature.update(input);
                        final byte[] signatureBytes = signature.sign();

                        print(response, "sig." + id, Base64.toBase64String(signatureBytes));
                    }
                }                
            }

            // Write output
            response.store(out, null);
        }
    }
    private DNSKEYRecord dnskeyZSK1;

    private void print(Properties response, String property, String value) {
        response.setProperty(property, value);
    }
    
    private void print(Properties response, String property, Record record) {
        // Clear text version: response.setProperty(property, record.toString());
        response.setProperty(property, Base64.toBase64String(record.toWireCanonical()));
    }

    @Override
    protected String getRequestContentType() {
        return CONTENT_TYPE;
    }

}
