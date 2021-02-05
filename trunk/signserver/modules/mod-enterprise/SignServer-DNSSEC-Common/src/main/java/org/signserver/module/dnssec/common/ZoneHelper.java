/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.module.dnssec.common;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CompileTimeSettings;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Master;
import org.xbill.DNS.NSEC3PARAMRecord;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base32;

/**
 * Constants and utility methods for zone file signing.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ZoneHelper {
    private static Logger LOG = Logger.getLogger(ZoneHelper.class);
    
    // Request or metadata properties
    public static final String RR_DNSKEY_Z1_ALGORITHM = "rr.dnskey.z1.algorithm";
    public static final String RR_DNSKEY_Z1_FOOTPRINT = "rr.dnskey.z1.footprint";
    public static final String RR_DNSKEY_Z1_SIGNINGTIME = "rr.dnskey.z1.signingtime";
    public static final String RR_DNSKEY_Z1_EXPIRETIME = "rr.dnskey.z1.expiretime";
    public static final String RR_NSEC3PARAM = "rr.nsec3param";
    
    // TODO: decide on this property later
    public static final boolean INCREMENT_SERIAL = true; // Later: possibly this should be a worker property
    public static final long MIN_REMAINING = 14 * 24 * 60 * 60 * 1000;
    
    
    /**
     * Create an RRSIGRecord without a signature for the given set and key.
     *
     * @param rrset to sign
     * @param key public key to use
     * @param inception not before date
     * @param expiration not after date
     * @return the new record
     */
    public static RRSIGRecord createRrsigRecord(RRset rrset, DNSKEYRecord key, Date inception, Date expiration) {
        int alg = key.getAlgorithm();
        return new RRSIGRecord(rrset.getName(), rrset.getDClass(),
					    rrset.getTTL(), rrset.getType(),
					    alg, rrset.getTTL(),
					    expiration, inception,
					    key.getFootprint(),
					    key.getName(), null);
    }
    
    /**
     * Create the data that should be feed to hashing for the RRSIGRecord and
     * the RRset it should cover.
     * @param rrsig RRSIGRecord
     * @param rrset set to cover
     * @return the data that should be hashed
     */
    public static byte[] createToBeSignedData(RRSIGRecord rrsig, RRset rrset) {
        return DNSSEC.digestRRset(rrsig, rrset);
    }
    
    /**
     * Create a new RRSIGRecord but with the signature added.
     * (We can't do RRSigRecord.setSignature() due to method visibility)
     * @param rrsig record to add the signature to
     * @param signature bytes to add to the record
     * @return RRSIGRecord that now has the signature
     */
    public static RRSIGRecord createWithSignature(RRSIGRecord rrsig, byte[] signature) {
        return new RRSIGRecord(rrsig.getName(), rrsig.getDClass(), rrsig.getTTL(), rrsig.getTypeCovered(), rrsig.getAlgorithm(), rrsig.getOrigTTL(), rrsig.getExpire(),
	      rrsig.getTimeSigned(), rrsig.getFootprint(), rrsig.getSigner(), signature);
    }
    
    public static String toSignatureInput(final byte[] plainText, final String digestAlgorithm) throws NoSuchAlgorithmException, IOException {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        
        md.update(plainText);
        byte[] hash = md.digest();
        byte[] modifierBytes;

        switch (digestAlgorithm) {
            case "SHA1":
            case "SHA-1": {
                // Taken from RFC 3447, page 42 for SHA-1, create input for signing
                modifierBytes = new byte[] {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
                break;
            }
            case "SHA256":
            case "SHA-256": {
                // Taken from RFC 3447, page 42 for SHA-256, create input for signing
                modifierBytes = new byte[] {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
                break;
            }
            case "SHA512":
            case "SHA-512": {
                // Taken from RFC 3447, page 42 for SHA-512, create input for signing
                modifierBytes = new byte[] {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
                break;
            }
            default:
                throw new NoSuchAlgorithmException("Unsupported digest algorithm: " + digestAlgorithm);
        }
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);
        
        return Base64.toBase64String(baos.toByteArray());
    }

    public static boolean isSubOfDelegatedNS(final RRsetId id,
                                             final List<Record> delegatedNSs)
            throws IOException {
        boolean subOfDelegatedNS = false;

        for (final Record delegatedNS : delegatedNSs) {
            if (id.getName().subdomain(delegatedNS.getName())) {
                subOfDelegatedNS = true;
            }
        }
        
        return subOfDelegatedNS;
    }

    /**
     * Create a copy of a super domain name relative to a given domain name.
     * 
     * @param name Name to create super name of
     * @param index the start index (zero-based, 0 would mean the original name)
     * @return
     * @throws IOException 
     */
    public static Name createSuperOfName(final Name name, final int index)
            throws IOException {
        final List<byte[]> labels = new LinkedList<>();
        int size = 0;
        for (int i = index; i < name.labels(); i++) {
            final byte[] label = name.getLabel(i);

            labels.add(label);
            size += label.length;
        }

        final byte[] result = new byte[size];

        int pos = 0;
        for (final byte[] label : labels) {
            System.arraycopy(label, 0, result, pos, label.length);
            pos += label.length;
        }

        return new Name(result);
    }

    public static void print(PrintStream out, RRSIGRecord sig) {
        out.print("			" + sig.getTTL() + "	RRSIG	");
        out.println(sig.rdataToString());
    }
    
    public static void print(PrintStream out, DNSKEYRecord dns) {
        out.print("			" + dns.getTTL() + "	DNSKEY	");
        out.println(dns.rdataToString());
    }

    public static void print(PrintStream out, Record r, String currentName,
                                boolean incrementSerial) {
        if (incrementSerial && (r instanceof SOARecord)) {
            SOARecord soa = (SOARecord) r;
            SOARecord soa2 = new SOARecord(soa.getName(), soa.getDClass(), soa.getTTL(), soa.getHost(), soa.getAdmin(), soa.getSerial() + 1, soa.getRefresh(), soa.getRetry(), soa.getExpire(), soa.getMinimum());
            r = soa2;
        }
        
        if (r.getName().toString().equals(currentName)) {
            out.print("			");
        } else {
            out.print(r.getName().toString());
        }
        out.print("    " + r.getTTL() + "	");
        if (r instanceof SOARecord || r instanceof ARecord) {
            out.print(DClass.string(r.getDClass()));
        }
        out.print(" " + Type.string(r.getType())  + "	");
        out.println(r.rdataToString());
    }

    /**
     * Helper class representing a list of hashed record names and possibly
     * the hashed name for the SOA record.
     * 
     */
    public static class HashData {
        ArrayList<Name> hashOrder;
        String soaHashName;

        private HashData(ArrayList<Name> hashOrder, String soaHashName) {
            this.hashOrder = hashOrder;
            this.soaHashName = soaHashName;
        }

        public ArrayList<Name> getHashOrder() {
            return hashOrder;
        }

        public String getSoaHashName() {
            return soaHashName;
        }
    };
    
    public static HashData createInHashOrder(ArrayList<RRsetId> rrOrder,
                                             NSEC3PARAMRecord nsec3Params,
                                             List<Record> delegatedNSRecords,
                                             String zoneName)
            throws NoSuchAlgorithmException, TextParseException, IOException {
        ArrayList<Name> rrOrder2;
        LOG.debug("====== rrSet in NSEC order:");
        final Name ourZone = Name.fromString(zoneName).canonicalize();
        Name soaName = null;
        rrOrder2 = new ArrayList<>();
        for (RRsetId id : rrOrder) {
            Name name = id.getName().canonicalize();            

            if (!ourZone.equals(id.getName()) && 
                (rrOrder.contains(new RRsetId(id.getName(), Type.NS, id.getdClass())) ||
                 ZoneHelper.isSubOfDelegatedNS(id, delegatedNSRecords)) &&
                id.getType() != Type.DS) {
                // Ignore delegated NS (but explicitly not DS (delegation signer) records)
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Ignoring delegated NS: " + id);
                }
            } else if (!rrOrder2.contains(name)) {
                if (name.subdomain(ourZone)) {
                    final int currLength = name.labels();
                    final int zoneLength = ourZone.labels();

                    for (int level = 1; level < currLength - zoneLength; level++) {
                        final Name superName =
                                ZoneHelper.createSuperOfName(name, level);

                        if (!rrOrder2.contains(superName)) {
                            // LOG.debug("adding super name: " + superName.toString());
                            rrOrder2.add(superName);
                        }
                    }
                }

                rrOrder2.add(name);

                if (id.getType() == Type.SOA) {
                    soaName = name;
                }
            }
        }

        // Hash
        base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);
        ArrayList<Name> hashOrder = new ArrayList<>();
        Name soaHashName = null;
        for (Name n : rrOrder2) {
            String hashed = b32.toString(nsec3Params.hashName(n));
            if (LOG.isDebugEnabled()) {
                LOG.debug("n: " + n + "   => " + hashed);
            }
            final Name hashedName = new Name(hashed);
            hashOrder.add(hashedName);

            if (soaName != null && n.equals(soaName)) {
                soaHashName = hashedName;
            }
        }

        Collections.sort(hashOrder, (Name o1, Name o2) -> o1.compareTo(o2));
        if (LOG.isTraceEnabled()) {
            LOG.trace("rrsets canonical (Hash Order): " + hashOrder);
        }

        return new HashData(hashOrder,
                            soaHashName != null ? soaHashName.toString() : null);
    }

    public static RRset incrementSoa(RRset rrset) {
        RRset result = new RRset();
        Iterator iterator = rrset.rrs(false);
        while (iterator.hasNext()) {
            Record r = (Record) iterator.next();
            if (r instanceof SOARecord) {
                SOARecord soa = (SOARecord) r;
                SOARecord soa2 = new SOARecord(soa.getName(), soa.getDClass(), soa.getTTL(), soa.getHost(), soa.getAdmin(), soa.getSerial() + 1, soa.getRefresh(), soa.getRetry(), soa.getExpire(), soa.getMinimum());
                r = soa2;
            }
            result.addRR(r);
        }
        
        return result;
    }

    public static void putType(HashMap<String, List<Integer>> typesMap,
                               NSEC3PARAMRecord nsec3Params, String name,
                               int type)
            throws TextParseException, NoSuchAlgorithmException {
        base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);
        String hashed = b32.toString(nsec3Params.hashName(new Name(name)));
        
        List<Integer> types = typesMap.get(hashed);
        if (types == null) {
            types = new ArrayList<>();
            typesMap.put(hashed, types);
        }
        if (!types.contains(type)) {
            types.add(type);
        }
    }

    public static HashMap<String, String> createNextNsec3Map(
            ArrayList<Name> hashOrder, NSEC3PARAMRecord nsec3Params)
            throws TextParseException {
        HashMap<String, String> nextNsecMap = new HashMap<>();
        Iterator<Name> iterator = hashOrder.iterator();
        Name first = iterator.next();
        Name name1 = first;
        Name name2;
        while (iterator.hasNext()) {
            name2 = iterator.next();
            nextNsecMap.put(name1.toString(), name2.toString());
            name1 = name2;
        }
        nextNsecMap.put(name1.toString(), first.toString());

        return nextNsecMap;
    }

    /**
     * Decompresses (unzip) given zipFile into given outputFolder.
     *
     * @param zipFile     * 
     * @return zoneFiles
     * @throws java.io.IOException
     */
    public static List<File> unzipFile(String zipFile) throws IOException {
        byte[] buffer = new byte[1024];
        List<File> zoneFiles = new ArrayList<>();
        
        try ( //get the zip file content
                ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            //get the zipped file list entry
            ZipEntry ze = zis.getNextEntry();
            int i = 0;            
            File file;

            while (ze != null && i < 2) {

                if (!ze.isDirectory()) {

                    if (i == 0) {
                        file = File.createTempFile("new", ".zone");
                    } else {
                        file = File.createTempFile("previous", ".zone");
                    }

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("zip entry name: "+ ze.getName());
                        LOG.debug("file to be created from zip entry: " + file.getAbsoluteFile());
                    }
                        
                    //create all non exists folders
                    //else you will hit FileNotFoundException for compressed folder
                    new File(file.getParent()).mkdirs();

                    try (FileOutputStream fos = new FileOutputStream(file)) {
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                    zoneFiles.add(file);
                    i++;
                }
                ze = zis.getNextEntry();

            }

            zis.closeEntry();
        }

        return zoneFiles;
    }
    
    /**
     * Output zone file comment with file header containing date and version.
     * @param out stream to write to
     */
    public static void printHeader(PrintStream out) {
        final Date now = new Date();
        final String creationTimeComment =
                String.format("; File written on %s", now.toString());
        final String version =
                CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);
        final String versionComment =
                String.format("; %s", version);
        out.println(creationTimeComment);
        out.println(versionComment);
    }
    
    public static ZoneFileParser createParserFromZone(InputStream in, String zoneName) throws TextParseException, IOException {
        final Master master = new Master(in, Name.fromString(zoneName));
        final ZoneFileParser zoneFileParser = new ZoneFileParser(master);        
        return zoneFileParser;
    }
    
    public static ZoneFileParser createParserFromZoneZip(File zoneZipFile, String zoneName, boolean forceResign, List<InputStream> inputStreamsToBeClosed) throws IOException {
        final ZoneFileParser result;
        List<File> zoneFiles = null;
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("zone zip file " + zoneZipFile.getAbsolutePath());
            }
            zoneFiles = ZoneHelper.unzipFile(zoneZipFile.getAbsolutePath());

            final InputStream isCurrent = new FileInputStream(zoneFiles.get(0));
            final InputStream isPrevious = 
                    zoneFiles.size() > 1 ? new FileInputStream(zoneFiles.get(1)) :
                                           null;

            inputStreamsToBeClosed.add(isCurrent);
            if (isPrevious != null) {
                inputStreamsToBeClosed.add(isPrevious);
            }
            
            final Name dnsZoneName = Name.fromString(zoneName);
            final Master currentMaster = new Master(isCurrent, dnsZoneName);           
            
            if (isPrevious != null) {
                final Master previousMaster = new Master(isPrevious, dnsZoneName);

                result = new ZoneFileParser(currentMaster, previousMaster, forceResign);
            } else {
                result = new ZoneFileParser(currentMaster);
            }

        } finally {
            if (zoneFiles != null) {
                for (File file : zoneFiles) {
                    FileUtils.deleteQuietly(file);
                }
            }
        }
        return result;
    }

    public static void bigLoop(final OutputStream outputStream,
                               final ZoneClientHelper.Phase1Data d,
                               final ZoneSignatureCreator sigCreator) 
            throws TextParseException, NoSuchAlgorithmException, IOException, DNSSEC.DNSSECException {
        
        final boolean hashingState = outputStream == null;
        
        int sigIdCounter = 0;
        
        try (PrintStream out = outputStream == null ? null : new PrintStream(outputStream)) {
                // Output header
                if (outputStream != null) {
                    ZoneHelper.printHeader(out);
                }

                boolean keysAdded = false;
                boolean nsec3ParamAdded = false;
                boolean nsec3Added = false;
                String prevName = null;
                String currentName = "";
                for (RRsetId id : d.getRrSetIds()) {
                    RRset rrset = d.getRrSetMap().get(id);

                    Iterator iter = rrset.rrs();
                    while (iter.hasNext()) {
                        final Record r = (Record) iter.next();
                        prevName = currentName;
                        currentName = r.getName().toString();

                        // Insert keys at end of first set (guess it is a good place)
                        if (!keysAdded && prevName != null && !prevName.equals("") && (!prevName.equals(currentName))) {
                            if (!hashingState) {
                                // DNSKEY ZSK (1)
                                ZoneHelper.print(out, d.getDnskeyZSK1());

                                // DNSKEY ZSK (2)
                                ZoneHelper.print(out, d.getDnskeyZSK2());
                                
                                // DNSKEY ZSK (0)
                                if (d.getDnskeyZSK0() != null) {
                                    ZoneHelper.print(out, d.getDnskeyZSK0());
                                }

                                // DNSKEY KSK (1-2)
                                final RRset dnskeySet = new RRset();
                                for (DNSKEYRecord dnskeyKSK : d.getKsks()) {
                                    ZoneHelper.print(out, dnskeyKSK);
                                    dnskeySet.addRR(dnskeyKSK);
                                }

                                // ZSK1 and ZSK2, and optionally ZSK0
                                dnskeySet.addRR(d.getDnskeyZSK1());
                                dnskeySet.addRR(d.getDnskeyZSK2());
                                if (d.getDnskeyZSK0() != null) {
                                    dnskeySet.addRR(d.getDnskeyZSK0());
                                }
                            }

                            // RRSIG DNSKEY ZSK
                            if (!hashingState) {
                                //final Record sigDnskeyZSK =  DNSSEC.sign(dnskeySet, dnskeyZSK1, zsk1KeyPair.getPrivate(), timeSigned, expire);
                                ZoneHelper.print(out, (RRSIGRecord) d.getSigDnskeyZSK());
                            }
                            ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), prevName, Type.RRSIG);

                            // RRSIG DNSKEY KSK & ZSK
                            for (RRSIGRecord kskSig : d.getKskSigs()) {
                                if (!hashingState) {
                                    ZoneHelper.print(out, (RRSIGRecord) kskSig);
                                }
                                ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), currentName, Type.RRSIG);
                            }

                            keysAdded = true;
                            LOG.trace("Added keys");
                        }

                        // Insert NSEC3 param
                        if (!nsec3ParamAdded && prevName != null && !prevName.equals("") && (!prevName.equals(currentName))) {
                            nsec3ParamAdded = true;
                            if (!hashingState) {
                                ZoneHelper.print(out, d.getNsec3Params(), prevName, INCREMENT_SERIAL);
                                ZoneHelper.print(out, sigCreator.createNsec3ParamsSig());
                            }
                            ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), prevName, Type.NSEC3PARAM);
                            ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), prevName, Type.DNSKEY);
                        }

                        if (!hashingState) {
                            ZoneHelper.print(out, r, prevName, INCREMENT_SERIAL);
                        }
                        ZoneHelper.putType(d.getTypesMap(), d.getNsec3Params(), r.getName().toString(), r.getType());
                    }


                    // Unless it is a delegated NS, sign it, always sign DS (delegation signer) records
                    if (Name.fromString(d.getZoneName()).equals(id.getName()) ||
                        !d.getRrSetIds().contains(new RRsetId(id.getName(), Type.NS,
                                           id.getdClass())) ||
                        id.getType() == Type.DS) {

                        if (!ZoneHelper.isSubOfDelegatedNS(id, d.getParser().getCurrentDelegatedNSRecords()) ||
                            id.getType() == Type.DS) {
                            sigIdCounter++;
                            final RRSIGRecord sig =
                                    sigCreator.createRRsetSig(id, rrset, sigIdCounter);

                            if (sig != null) {
                                print(out, sig);
                            }
                        }
                    }

                    if (!nsec3Added && prevName != null && !prevName.equals("") && (!prevName.equals(currentName))) {
                        nsec3Added = true;
                    }
                }

                // Insert all NSEC3 records
                String name = d.getFirst();
                while (!d.getNextNsec3Map().isEmpty()) {
                    final String next = d.getNextNsec3Map().remove(name);
                    
                    // Get intTypes
                    final int[] intTypes;
                    final List<Integer> types = d.getTypesMap().get(name);
                    if (types != null) {
                        if (types.contains(Type.NS) &&
                            !name.equalsIgnoreCase(d.getHd().getSoaHashName())) {
                            intTypes = types.stream().mapToInt(i -> i).filter(i -> i != Type.A).toArray();
                        } else {
                            intTypes = types.stream().mapToInt(i -> i).toArray();
                        }
                    } else {
                        intTypes = new int[]{};
                    }

                    // Insert NSEC3 record
                    final base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);
                    final NSEC3Record nsec3 = new NSEC3Record(Name.fromString(name + "." + d.getZoneName()), DClass.IN, d.getSoa().getMinimum(), d.getNsec3Params().getHashAlgorithm(), 1, d.getNsec3Params().getIterations(), d.getNsec3Params().getSalt(), b32.fromString(next), intTypes);
                    if (out != null) {
                        out.println(nsec3);
                    }

                    if (LOG.isDebugEnabled()) {
                        LOG.debug(name + " -> " + next);
                    }

                    // Signature of NSEC3 record
                    sigIdCounter++;
                    final RRSIGRecord sig = sigCreator.createNsec3RecordSig(nsec3, sigIdCounter);

                    if (sig != null) {
                        print(out, sig);
                    }

                    name = next;
                }
            }
    }
}
