/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.client.cli.enterprise;

import org.signserver.module.dnssec.common.ZoneClientHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.module.dnssec.common.ZoneClientHelper.TbsRecord;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestMetadata;
import org.signserver.module.dnssec.common.RRsetId;
import org.signserver.module.dnssec.common.ZoneFileParser;
import org.signserver.module.dnssec.common.ZoneHelper;
import org.signserver.module.dnssec.common.ZoneSignatureCreator;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * File-specific handler for zone ZIP files.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneFileSpecificHandler extends AbstractFileSpecificHandler {

    private static final Logger LOG = Logger.getLogger(ZoneFileSpecificHandler.class);
    
    private final File inFile;
    private final boolean forceResign;
    private final String zoneName; 
    private final Long minRemainingValidity;

    private Properties preResponse;
    private HashMap<RRsetId, String> rrsetId2sigId;
    private HashMap<String, TbsRecord> sigMap;

    private ZoneClientHelper.Phase1Data phase1Data;
    
    private List<InputStream> inputStreamsToBeClosed;
    private SOARecord soa;
    private ZoneFileParser parser;
    private ArrayList<RRsetId> rrSetIds;
    private HashMap<RRsetId, RRset> rrSetMap;

    private HashMap<String, String> nextNsec3MapPhase2;
    
    public ZoneFileSpecificHandler(final File inFile,
            final File outFile,
            final boolean forceResign,
            final String zoneName,
            final Long minRemainingValidity) {
        super(inFile, outFile);
        this.inFile = inFile;
        this.forceResign = forceResign;
        this.zoneName = zoneName;
        this.minRemainingValidity = minRemainingValidity;
        System.setProperty("dnsjava.options", "multiline");
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource producePreRequestInput()
            throws IOException, IllegalRequestException {
        inputStreamsToBeClosed = new ArrayList<>(2);

        try {
            // Parse zone file into RRsets
            parser = extractZoneFileAndParse(inFile, zoneName, inputStreamsToBeClosed, forceResign);

            rrSetMap = parser.getCurrentRrSetMap();
            rrSetIds = parser.getCurrentRrSetIds();
            soa = parser.getCurrentSoa();

            // Debug log the results
            if (LOG.isDebugEnabled()) {
                LOG.debug("\n");
                LOG.debug("rrsets: ");

                for (RRsetId id : rrSetIds) {
                    LOG.debug(id.getName() + " " + DClass.string(id.getdClass()) + " " + Type.string(id.getType()));
                    LOG.debug(rrSetMap.get(id));
                }
            }

            // Check that we got a SOA record
            if (soa == null) {
                throw new IllegalRequestException("Unable to parse zone file. Failed to find an SOA.");
            }

            final Map<String, String> metadata = new HashMap<>();

            metadata.put("SOA_TTL", Long.toString(soa.getTTL()));
            return new InputSource(new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8)),
                                       0, metadata);
        } catch (IOException | IllegalRequestException e) {
            for (final InputStream is : inputStreamsToBeClosed) {
                is.close();
            }

            throw e;
        }
    }

    @Override
    public void assemblePreResponse(OutputCollector oc) throws IOException {
        preResponse = new Properties();
        preResponse.load(new ByteArrayInputStream(oc.toByteArray()));
        
        // Debug log
        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("\tpreResponse:\n");
            preResponse.entrySet().forEach((entry) -> {
                sb.append("\t\t").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
            });
            LOG.debug(sb.toString());
        }
    }

    @Override
    public InputSource produceSignatureInput(final String digestAlgorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException, NoSuchProviderException {
        try {
            // Read from pre-request
            final DNSKEYRecord dnskeyZ0;
            if (preResponse.containsKey("rr.dnskey.z0")) {
                dnskeyZ0 = (DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.dnskey.z0")), 37); // XXX: 37
            } else {
                dnskeyZ0 = null;
            }
            final DNSKEYRecord dnskeyZ1 = (DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.dnskey.z1")), 37); // XXX: 37
            final DNSKEYRecord dnskeyZ2 = (DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.dnskey.z2")), 37); // XXX: 37
            final NSEC3PARAMRecord nsec3Param = (NSEC3PARAMRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty(ZoneHelper.RR_NSEC3PARAM)), 37);
            final List<DNSKEYRecord> ksks = getAllKsks(preResponse);
            final List<RRSIGRecord> kskSigs = getAllKsksSigs(preResponse);
            final RRSIGRecord sigDnskeyZSK = (RRSIGRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.dnskey.sig.z1")), 37); // XXX: 37
            final RRSIGRecord nsec3ParamsSig = (RRSIGRecord) DNSKEYRecord.fromWire(Base64.decode(preResponse.getProperty("rr.nsec3param.sig")), 37); // XXX: 37
            
            // Request
            final RequestMetadata requestMetadata = new RequestMetadata();
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM));
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT));
            final String z1SigningTimeValue = preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME);
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME, z1SigningTimeValue);
            final String z1ExpireTimeValue = preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME);
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME, z1ExpireTimeValue);
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_ALGORITHM));
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_FOOTPRINT));
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_SIGNINGTIME));
            requestMetadata.put(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME, preResponse.getProperty(ZoneHelper.RR_DNSKEY_Z1_EXPIRETIME));

            final Properties requestBody = new Properties();
            
            // Records to sign
            putRecordsToSign(digestAlgorithm, requestBody, dnskeyZ0, dnskeyZ1, dnskeyZ2, ksks, kskSigs, sigDnskeyZSK, new Date(Long.valueOf(z1SigningTimeValue)), new Date(Long.valueOf(z1ExpireTimeValue)), nsec3Param, nsec3ParamsSig);
            if (LOG.isDebugEnabled()) {
                debugLog(requestMetadata, requestBody);
            }
            
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();            
            requestBody.store(bos, null);
            final byte[] encoded = bos.toByteArray();
            
            return new InputSource(new ByteArrayInputStream(encoded),
                    encoded.length, null, requestMetadata);
        } catch (TextParseException | UnknownHostException | DNSSEC.DNSSECException ex) {
            throw new IOException(ex);
        }
    }
    
    private void putRecordsToSign(String digestAlgorithm, Properties requestBody, DNSKEYRecord dnskeyZ0, DNSKEYRecord dnskeyZ1, DNSKEYRecord dnskeyZ2,  final List<DNSKEYRecord> ksks, List<RRSIGRecord> kskSigs, final RRSIGRecord sigDnskeyZSK, Date z1SigningTime, Date z1ExpireTime, final NSEC3PARAMRecord nsec3Params, final RRSIGRecord nsec3ParamsSig) throws TextParseException, UnknownHostException, NoSuchAlgorithmException, IOException, IllegalRequestException, DNSSEC.DNSSECException, NoSuchProviderException {
        try {       
            // NSEC order
            final HashMap<String, List<Integer>> typesMap = new HashMap<>();
            //final NSEC3PARAMRecord nsec3Params = newNSEC3PARAMRecord();
            final ZoneHelper.HashData hd =
                    ZoneHelper.createInHashOrder(rrSetIds, nsec3Params,
                                                 parser.getCurrentDelegatedNSRecords(),
                                                 zoneName);
            final HashMap<String, String> nextNsec3Map =
                ZoneHelper.createNextNsec3Map(hd.getHashOrder(), nsec3Params);
            final String first = hd.getHashOrder().get(0).toString(false);
            
            nextNsec3MapPhase2 = new HashMap<>(nextNsec3Map);

            // Key-pairs for ZSK1 and ZSK2
            //final KeyPair zsk1KeyPair = new KeyPair(zskCryptoInstances.get(0).getPublicKey(), zskCryptoInstances.get(0).getPrivateKey());
            //final PublicKey zsk2PublicKey = zskCryptoInstances.get(1).getPublicKey();
            //final DNSKEYRecord dnskeyZSK1 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithm, zsk1KeyPair.getPublic());
            //final DNSKEYRecord dnskeyZSK2 = new DNSKEYRecord(Name.fromString(zoneName), DClass.IN, soa.getTTL(), DNSKEYRecord.Flags.ZONE_KEY, DNSKEYRecord.Protocol.DNSSEC, signatureAlgorithm, zsk2PublicKey);
            
            sigMap = new HashMap<>();
            rrsetId2sigId = new HashMap<>();
            phase1Data = new ZoneClientHelper.Phase1Data(first, nextNsec3Map, hd, soa, dnskeyZ0, dnskeyZ1, dnskeyZ2, ksks, kskSigs, sigDnskeyZSK, z1SigningTime, z1ExpireTime, nsec3Params, nsec3ParamsSig, typesMap, rrSetIds, rrSetMap, parser, zoneName, sigMap, rrsetId2sigId, minRemainingValidity);

            final ZoneSignatureCreator sigCreator
                    = new ClientSideZoneSignatureCreator(phase1Data, true,
                            minRemainingValidity, null);
            ZoneHelper.bigLoop(null, phase1Data, sigCreator);
            
            // Hash the empty sig records
            for (Map.Entry<String, TbsRecord> entry : sigMap.entrySet()) {
                final byte[] tbs1 = ZoneHelper.createToBeSignedData(entry.getValue().getSigRecord(), entry.getValue().getRrset());
                final String signatureInput1 = ZoneHelper.toSignatureInput(tbs1, digestAlgorithm);
                final String sigRecord1Id = entry.getKey();
                requestBody.put("hash." + sigRecord1Id, signatureInput1);
            }
        } finally {
            for (InputStream inputStream : inputStreamsToBeClosed) {
                inputStream.close();
            }
        }
    }

    private void debugLog(final RequestMetadata requestMetaData, final Properties requestBody) {
        
        final StringBuilder sb = new StringBuilder();
        sb.append("sendRequest {\n");
        sb.append("\trequestMetaData:\n");
        
        requestMetaData.entrySet().forEach((entry) -> {
            sb.append("\t\t").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        });
        
        sb.append("\trequest:\n");
        requestBody.entrySet().forEach((entry) -> {
            sb.append("\t\t").append(entry.getKey()).append("=").append(entry.getValue()).append("\n");
        });
        
        sb.append("}");
        
        LOG.debug(sb.toString());
    }
    
    @Override
    public void assemble(OutputCollector oc) throws IOException, IllegalArgumentException {
        try (final OutputStream os = new FileOutputStream(getOutFile())) {
            final Properties response = new Properties();
            response.load(new ByteArrayInputStream(oc.toByteArray()));
            final HashMap<String, byte[]> sigId2signatureBytes = getSigntureBytesMap(response);

            phase1Data.setNextNsec3Map(nextNsec3MapPhase2);

            final ZoneSignatureCreator sigCreator
                    = new ClientSideZoneSignatureCreator(phase1Data, false,
                            minRemainingValidity,
                            sigId2signatureBytes);
            ZoneHelper.bigLoop(os, phase1Data, sigCreator);
        } catch (TextParseException | NoSuchAlgorithmException | DNSSEC.DNSSECException ex) {
            throw new IOException(ex);
        }
    }

    @Override
    public String getFileTypeIdentifier() {
        return "ZONE_ZIP";
    }
 
    private ZoneFileParser extractZoneFileAndParse(final File zoneZipFile, String zoneName, List<InputStream> inputStreamsToBeClosed, boolean forceResign) throws IOException, IllegalRequestException {
        return ZoneHelper.createParserFromZoneZip(zoneZipFile, zoneName, forceResign, inputStreamsToBeClosed);
    }

    private List<DNSKEYRecord> getAllKsks(Properties preResponse) throws IOException {
        List<DNSKEYRecord> results = new ArrayList<>(2);
        
        String kValue = preResponse.getProperty("rr.dnskey.k1");
        if (kValue != null) {
            results.add((DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(kValue), 37)); // XXX: 37
        }
        kValue = preResponse.getProperty("rr.dnskey.k2");
        if (kValue != null) {
            results.add((DNSKEYRecord) DNSKEYRecord.fromWire(Base64.decode(kValue), 37)); // XXX: 37
        }
        
        return results;
    }

    private List<RRSIGRecord> getAllKsksSigs(Properties preResponse) throws IOException {
        List<RRSIGRecord> results = new ArrayList<>(2);
        
        String kValue = preResponse.getProperty("rr.dnskey.sig.k1");
        if (kValue != null) {
            results.add((RRSIGRecord) RRSIGRecord.fromWire(Base64.decode(kValue), 37)); // XXX: 37
        }
        kValue = preResponse.getProperty("rr.dnskey.sig.k2");
        if (kValue != null) {
            results.add((RRSIGRecord) RRSIGRecord.fromWire(Base64.decode(kValue), 37)); // XXX: 37
        }
        
        return results;
    }

    private HashMap<String, byte[]> getSigntureBytesMap(Properties response) {
        final HashMap<String, byte[]> results = new HashMap<>();
        final Enumeration<String> propertyNames = (Enumeration<String>) response.propertyNames();
        while (propertyNames.hasMoreElements()) {
            final String property = propertyNames.nextElement();
            if (property.startsWith("sig.") && property.length() > "sig.".length()) {
                final String id = property.substring("sig.".length());
                results.put(id, Base64.decode(response.getProperty(property)));
            }
        }
        return results;
    }
    
}
