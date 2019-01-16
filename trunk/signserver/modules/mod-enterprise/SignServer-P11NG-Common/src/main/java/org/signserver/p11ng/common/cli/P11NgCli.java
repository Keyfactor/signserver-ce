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
package org.signserver.p11ng.common.cli;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.Hex;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerUtil;
import org.signserver.p11ng.common.provider.CryptokiDevice;
import org.signserver.p11ng.common.provider.CryptokiManager;
import org.signserver.p11ng.common.provider.GeneratedKeyData;
import org.signserver.p11ng.common.provider.SlotEntry;
import org.signserver.server.cryptotokens.AttributeProperties;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_PRIVATEKEY_ENTRY;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_SECRETKEY_ENTRY;

/**
 * CLI command providing actions using JackNJI11 for troubleshooting.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11NgCli {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(P11NgCli.class);
    
    private static final Options OPTIONS;
    private static final String LIBFILE = "libfile";
    private static final String ACTION = "action";
    private static final String SLOT = "slot";
    private static final String PIN = "pin";
    private static final String ALIAS = "alias";
    private static final String WRAPKEY = "wrapkey";
    private static final String UNWRAPKEY = "unwrapkey";
    private static final String PRIVATEKEY = "privatekey";
    private static final String PUBLICKEY = "publickey";
    private static final String PLAINTEXT = "plaintext";
    private static final String METHOD = "method";
    private static final String SELFCERT = "selfcert";
    private static final String OBJECT = "object";
    private static final String ATTRIBUTES_FILE = "attributes_file";
    private static final String THREADS = "threads";
    private static final String WARMUPTIME = "warmuptime";
    private static final String TIMELIMIT = "timelimit";
    private static final String USE_CACHE = "use_cache";
    private static final String SIGNATUREALGORITHM = "signaturealgorithm";
    
    private static CEi ce;
    // used by the testSign stresstest command
    private long startTime;
    
    private static int exitCode;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(LIBFILE, true, "Shared library path");
        OPTIONS.addOption(ACTION, true, "Operation to perform. Any of: " + Arrays.asList(Action.values()));
        OPTIONS.addOption(SLOT, true, "Slot ID to operate on");
        OPTIONS.addOption(PIN, true, "User PIN");
        OPTIONS.addOption(ALIAS, true, "Key alias");
        OPTIONS.addOption(WRAPKEY, true, "Label of key to wrap with");
        OPTIONS.addOption(UNWRAPKEY, true, "Label of key to unwrap with");
        OPTIONS.addOption(PRIVATEKEY, true, "base64 encoded encrypted (wrapped) private key");
        OPTIONS.addOption(PUBLICKEY, true, "base64 encoded public key");
        OPTIONS.addOption(PLAINTEXT, true, "text string to sign");
        OPTIONS.addOption(METHOD, true, "Method to use, either pkcs11 (default) or provider");
        OPTIONS.addOption(SELFCERT, false, "Generate a self-signed certificate for the new key-pair");
        OPTIONS.addOption(OBJECT, true, "Object ID (decimal)");
        OPTIONS.addOption(ATTRIBUTES_FILE, true, "Path of file containing attributes to be used while generating key pair");
        OPTIONS.addOption(THREADS, true, "For sign-/unwrapPerformanceTest: Number of stresstest threads to run (default: 1)");
        OPTIONS.addOption(WARMUPTIME, true, "For sign-/unwrapPerformanceTest: Don't count number of signings and response times until after this time (in milliseconds). Default=0 (no warmup time).");
        OPTIONS.addOption(TIMELIMIT, true, "For sign-/unwrapPerformanceTest: Optional. Only run for the specified time (in milliseconds).");
        OPTIONS.addOption(USE_CACHE, true, "For sign-/unwrapPerformanceTest: Whether key objects are fetched from cache instead of HSM token (default: true)");
        OPTIONS.addOption(SIGNATUREALGORITHM, true, "For sign-/unwrapPerformanceTest: Signature algorithm to use (default: SHA256withRSA)");
    }

    private static enum Action {
        listSlots,
        showInfo,
        listObjects,

        listKeyStoreEntries,

        generateKey,
        generateAndWrapKeyPair,
        unwrapAndSign,
        deleteKeyStoreEntryByAlias,
        deleteObjects,
        generateKeyPair,
        signPerformanceTest,
        unwrapPerformanceTest,
        oneTimePerformanceTest
    }
    
    private static enum Method {
        pkcs11,
        provider
    }
    
    public static void main(String[] args) throws CryptoTokenOfflineException {
        final P11NgCli cli = new P11NgCli();
        try {
            cli.execute(args);
            System.exit(exitCode);
        } catch (ParseException ex) {
            System.err.println(ex.getMessage());
            System.err.println(cli.getUsages());

            System.exit(-2);
        }
    }
    
    public String getUsages() {
        final String NL = "\n";
        final String COMMAND = "p11ng-tool";
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listSlots").append(NL)
            .append("b) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action showInfo").append(NL)
            .append("c) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listObjects -slot 0 -pin foo123").append(NL)
            .append("d) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKey -slot 0 -pin foo123 -alias wrapkey1").append(NL)
            .append("e) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKeyPair -slot 0 -pin foo123 -alias myprivkey").append(NL)
            .append("f) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKeyPair -slot 0 -pin foo123 -alias myprivkey -attributes_file /home/user/attribute_file.properties").append(NL)
            .append("g) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteObjects -slot 0 -pin foo123 -object 4").append(NL)
            .append("h) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteObjects -slot 0 -pin foo123 -object 4 -object 5").append(NL)
            .append("i) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteKeyStoreEntryByAlias -slot 0 -alias mykey1").append(NL)
            .append("j) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listKeyStoreEntries -slot 0 -pin foo123").append(NL)
            .append("k) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateAndWrapKeyPair -slot 0 -pin foo123 -wrapkey wrapkey1 -selfcert -alias wrappedprivkey").append(NL)
            .append("l) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action signPerformanceTest -slot 0 -pin foo123 -alias mykey1 -warmuptime 10000 -timelimit 100000 -threads 10").append(NL)
            .append("m) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action unwrapPerformanceTest -slot 0 -pin foo123 -wrapkey wrapkey1 -warmuptime 10000 -timelimit 100000 -threads 10").append(NL);
        
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        final HelpFormatter formatter = new HelpFormatter();
        
        PrintWriter pw = new PrintWriter(bout);
        formatter.printHelp(pw, HelpFormatter.DEFAULT_WIDTH, "p11ng-tool [options]",  getDescription(), OPTIONS, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD, footer.toString());
        pw.close();
        
        return bout.toString();
    }
    
    public String getDescription() {
        return "P11NG commands";
    }
    
    public void execute(String[] args) throws ParseException, CryptoTokenOfflineException {
        final CommandLine commandLine = new GnuParser().parse(OPTIONS, args);
        
        final String lib;
        if (commandLine.hasOption(LIBFILE)) { 
            lib = commandLine.getOptionValue(LIBFILE);
        } else {
            throw new ParseException("Missing: " + LIBFILE);
        }
        
        final Action action;
        if (commandLine.hasOption(ACTION)) { 
            action = Action.valueOf(commandLine.getOptionValue(ACTION));
        } else {
            throw new ParseException("Missing: " + ACTION);
        }

        // Doesn't seem to work, anyway...
        System.setProperty("jna.debug_load", "true");
        System.setProperty("jna.nosys", "true");
     
        LOG.debug("Action: " + action);
        
        try {
            final File library = new File(lib);
            final String libDir = library.getParent();
            final String libName = library.getName();
            LOG.debug("Adding search path: " + libDir);
            NativeLibrary.addSearchPath(libName, libDir);
            JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(libName, JNAiNative.class);
            ce = new CEi(new Ci(new JNAi(jnaiNative)));
            
            switch (action) {
                case listSlots: {
                    ce.Initialize();
                    long[] allSlots = ce.GetSlotList(false);
                    System.out.println("All slots:        " + Arrays.toString(allSlots));
                    long[] slots = ce.GetSlotList(true);
                    System.out.println("Slots with token: " + Arrays.toString(slots));
                    
                    for (long slot : allSlots) {
                        CK_TOKEN_INFO info = ce.GetTokenInfo(slot);
                        System.out.println("ID: " + slot + ", Label: " + new String(info.label, StandardCharsets.UTF_8));
                    }
                    break;
                }
                case showInfo: {
                    ce.Initialize();
                    CK_INFO info = ce.GetInfo();
                    System.out.println("info: " + info);
                    break;
                }
                case listObjects: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    ce.Initialize();
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    
                    if (commandLine.hasOption(PIN)) {
                        ce.Login(session, CKU.USER, commandLine.getOptionValue(PIN).getBytes());
                    }            
                    
                    long[] privateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
                    System.out.println("Private Key Objects: " +  Arrays.toString(privateObjects));
                    StringBuilder buff = new StringBuilder();
                    for (long object : privateObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());

                    long[] publicObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PUBLIC_KEY));
                    System.out.println("Public Key Objects: " +  Arrays.toString(publicObjects));
                    buff = new StringBuilder();
                    for (long object : publicObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    
                    long[] certificateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.CERTIFICATE));
                    System.out.println("Certificate Objects: " +  Arrays.toString(certificateObjects));
                    buff = new StringBuilder();
                    for (long object : certificateObjects) {
                        printGeneralObjectInfo(buff, object, session);
                        printCertificateObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    
                    long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
                    System.out.println("Secret Objects: " +  Arrays.toString(secretObjects));
                    buff = new StringBuilder();
                    for (long object : secretObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    break;
                }
                case listKeyStoreEntries: {
                    LOG.debug("Using provider");

                    Security.addProvider(new BouncyCastleProvider());
                    
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    
                    if (commandLine.hasOption(PIN)) {
                        slot.login(commandLine.getOptionValue(PIN));
                    }
                                    
                    final Enumeration<SlotEntry> e = slot.aliases();
                    final StringBuilder buff = new StringBuilder();
                    while (e.hasMoreElements()) {
                        final SlotEntry slotEntry  = e.nextElement();                
                        final String keyAlias = slotEntry.getAlias();
                        final String type;
                        if (slotEntry.getType().equals(TYPE_PRIVATEKEY_ENTRY)) {
                            type = TYPE_PRIVATEKEY_ENTRY;
                        } else if (slotEntry.getType().equals(TYPE_SECRETKEY_ENTRY)) {
                            type = TYPE_SECRETKEY_ENTRY;
                        } else {
                            type = null;
                        }
                        
                        buff.append("Entry ").append(type).append(" \"").append(keyAlias).append("\"");
                        List<Certificate> certificateChain = slot.getCertificateChain(keyAlias);
                        for (Certificate cert : certificateChain) {
                            buff.append(", ");
                            buff.append("0x");
                            buff.append(((X509Certificate) cert).getSerialNumber().toString(16));
                        }
                        buff.append("\n");
                    }
                    System.out.println(buff.toString());
                    break;
                }
                case generateKey: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(ALIAS)) {
                        throw new ParseException("Missing " + ALIAS);
                    }
                    final String alias = commandLine.getOptionValue(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(commandLine.getOptionValue(PIN));                  

                    slot.generateKey(CKM.AES_KEY_GEN, 128, alias);

                    System.out.println("Generated wrapKey" + " with alias " + alias);

                    break;
                }
                case generateAndWrapKeyPair: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(WRAPKEY)) {
                        throw new ParseException("Missing " + WRAPKEY);
                    }
                    final String wrapkey = commandLine.getOptionValue(WRAPKEY);
                    final boolean selfCert = commandLine.hasOption(SELFCERT);
                    if (!commandLine.hasOption(ALIAS)) {
                        throw new ParseException("Missing " + ALIAS);
                    }
                    final String alias = commandLine.getOptionValue(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(commandLine.getOptionValue(PIN));                    

                    GeneratedKeyData generatedKeyData = slot.generateWrappedKey(wrapkey, "RSA", "2048", CKM.AES_CBC_PAD);

                    // Converting java PublicKey to BC RSAPublicKey
                    byte[] encoded = generatedKeyData.getPublicKey().getEncoded();
                    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                            ASN1Sequence.getInstance(encoded));
                    RSAPublicKey rsaPublicKey;
                    try {
                        byte[] rsaPublicKeyEncoded = subjectPublicKeyInfo.parsePublicKey().getEncoded();
                        ASN1InputStream ais = new ASN1InputStream(rsaPublicKeyEncoded);
                        Object asnObject = ais.readObject();
                        ASN1Sequence sequence = (ASN1Sequence) asnObject;
                        RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure(sequence);
                        rsaPublicKey = new RSAPublicKey(rsaPublicKeyStructure.getModulus(), rsaPublicKeyStructure.getPublicExponent());
                        System.out.println("Public key: " + new String(Base64.encode(rsaPublicKey.getEncoded())));
                    } catch (IOException ex) {
                        LOG.error("IO error while generating wrapped key ", ex);
                        System.err.println("IO error while generating wrapped key " + ex.getMessage());
                        break;
                    }

                    System.out.println("Wrapped private key: " + new String(Base64.encode(generatedKeyData.getWrappedPrivateKey())));

                    if (selfCert) {

                        PrivateKey privateKey = slot.unwrapPrivateKey(generatedKeyData.getWrappedPrivateKey(), wrapkey, CKM.AES_CBC_PAD);

                        StringWriter out = new StringWriter();
                        try {
                            Calendar cal = Calendar.getInstance();
                            Date notBefore = cal.getTime();
                            cal.add(Calendar.YEAR, 50);
                            Date notAfter = cal.getTime();

                            X500Name dn = new X500Name("CN=Dummy cert for " + alias);
                            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn, new BigInteger("123"), notBefore, notAfter, dn, generatedKeyData.getPublicKey());
                            X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));

                            try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
                                writer.writeObject(cert);
                            }
                            String pemCertificates = out.toString();

                            System.out.println("Self signed certificate for generated wrapped key pair alias: " + alias);
                            System.out.println(pemCertificates);
                        } catch (IOException | OperatorCreationException ex) {
                            LOG.error("Self signed certificate creation failed: ", ex);
                            System.err.println("Self signed certificate creation failed: " + ex.getMessage());
                        } finally {
                            if (privateKey != null) {
                                slot.releasePrivateKey(privateKey);
                            }
                        }
                    }
                    break;
                }
                case unwrapAndSign: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(UNWRAPKEY)) {
                        throw new ParseException("Missing " + UNWRAPKEY);
                    }
                    final String unwrapkey = commandLine.getOptionValue(UNWRAPKEY);
                    if (!commandLine.hasOption(PRIVATEKEY)) {
                        throw new ParseException("Missing " + PRIVATEKEY);
                    }
                    final String wrapped = commandLine.getOptionValue(PRIVATEKEY);
                    if (!commandLine.hasOption(PUBLICKEY)) {
                        throw new ParseException("Missing " + PUBLICKEY);
                    }
                    final String publickey = commandLine.getOptionValue(PUBLICKEY);
                    if (!commandLine.hasOption(PLAINTEXT)) {
                        throw new ParseException("Missing " + PLAINTEXT);
                    }
                    final String plaintext = commandLine.getOptionValue(PLAINTEXT);
                    try {
                        RSAPublicKey rsa = RSAPublicKey.getInstance(new ASN1InputStream(Base64.decode(publickey.getBytes())).readObject());
                        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));

                        if (commandLine.hasOption(METHOD) && Method.valueOf(commandLine.getOptionValue(METHOD)) == Method.provider) {
                            unwrapAndSignUsingProvider(libName, libDir, slotId, commandLine.getOptionValue(PIN), unwrapkey, wrapped, plaintext, publicKey);
                        } else {
                            unwrapAndSignUsingPKCS11(slotId, commandLine.getOptionValue(PIN), unwrapkey, wrapped, plaintext, publicKey);
                        }

                    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeySpecException | IOException ex) {
                        LOG.error("unwrapAndSign failed:", ex);
                        System.err.println("unwrapAndSign failed: " + ex.getMessage());
                    }
                    
                    break;
                }
                case deleteKeyStoreEntryByAlias: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(ALIAS)) {
                        throw new ParseException("Missing " + ALIAS);
                    }
                    final String alias = commandLine.getOptionValue(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    if (commandLine.hasOption(PIN)) {
                        slot.login(commandLine.getOptionValue(PIN));
                    }

                    if (slot.removeKey(alias)) {
                        System.out.println("Destroyed object with alias " + alias);
                    } else {
                        System.err.println("Something went wrong. All objects could not be deleted with alias " + alias);
                    }

                    break;
                }
                case deleteObjects: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(OBJECT)) {
                        throw new ParseException("Missing " + OBJECT);
                    }
                    final String[] objectIds = commandLine.getOptionValues(OBJECT);
                    ce.Initialize();
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.USER, commandLine.getOptionValue(PIN).getBytes());                    

                    for (String objectId : objectIds) {
                        System.out.println("Destroying object " + objectId);
                        ce.DestroyObject(session, Long.parseLong(objectId));
                    }

                    break;
                }
                case generateKeyPair: {
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(ALIAS)) {
                        throw new ParseException("Missing " + ALIAS);
                    }
                    final String alias = commandLine.getOptionValue(ALIAS);
                    
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    final CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(commandLine.getOptionValue(PIN));             

                    final Map<String, Object> params = new HashMap<>(); // CLI currently does not support specifying Dummy certificate parameters as it is not required as of now
                    Properties attributesConfig;
                    AttributeProperties attributeProperties;
                    Map<Long, Object> publicAttributesMap;
                    Map<Long, Object> privateAttributesMap;
                    if (commandLine.hasOption(ATTRIBUTES_FILE)) {
                        final String attributeFilePath = commandLine.getOptionValue(ATTRIBUTES_FILE);
                        try {
                            attributesConfig = getAttributesPropertiesFromFile(attributeFilePath);
                        } catch (IOException ex) {
                            LOG.error("IO exception while reading attributes_file ", ex);
                            System.out.println("IO exception while reading attributes_file " + ex.getMessage());
                            break;
                        }
                        attributeProperties = AttributeProperties.fromWorkerProperties(attributesConfig);
                        publicAttributesMap = CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPublicTemplate("RSA"));
                        privateAttributesMap = CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPrivateTemplate("RSA"));
                    } else {
                        publicAttributesMap = Collections.emptyMap();
                        privateAttributesMap = Collections.emptyMap();
                    }

                    try {
                        slot.generateKeyPair("RSA", "2048", alias, false, publicAttributesMap, privateAttributesMap, new CryptokiDevice.CertificateGenerator() {
                            @Override
                            public X509Certificate generateCertificate(KeyPair keyPair, Provider provider) throws OperatorCreationException, CertificateException {
                                return CryptoTokenHelper.createDummyCertificate(alias, params, keyPair, slot.getProvider().getName());
                            }
                        }, true);
                    } catch (CertificateException | OperatorCreationException ex) {
                        LOG.error("Dummy certificate generation failed. Objects might still have been created in the device: ", ex);
                        System.err.println("Dummy certificate generation failed. Objects might still have been created in the device: " + ex.getMessage());
                    }

                    System.out.println("Generated key pair with alias " + alias);
                    
                    break;
                }
                case signPerformanceTest: {
                    SignServerUtil.installBCProvider();
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final String pin = commandLine.getOptionValue(PIN);
                    if (!commandLine.hasOption(ALIAS)) {
                        throw new ParseException("Missing " + ALIAS);
                    }
                    final String alias = commandLine.getOptionValue(ALIAS);

                    String signatureAlgorithm = commandLine.getOptionValue(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }

                    final String threadsString = commandLine.getOptionValue(THREADS, Integer.toString(1));
                    final int numThreads;
                    final int warmupTime;
                    final int timeLimit;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    if (numThreads < 1) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = commandLine.getOptionValue(WARMUPTIME, Integer.toString(0));
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        throw new ParseException("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = commandLine.getOptionValue(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                throw new ParseException("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            throw new ParseException("Illegal time limit: " + timeLimitString);
                        }
                    } else {
                        timeLimit = -1;
                    }

                    boolean useCache = Boolean.parseBoolean(commandLine.getOptionValue(USE_CACHE, CryptoTokenHelper.DEFAULT_PROPERTY_USE_CACHE));

                    try {
                        runSignPerformanceTest(alias, libName, libDir, slotId, pin,
                                       numThreads, warmupTime, timeLimit, useCache, signatureAlgorithm);
                    } catch (InterruptedException ex) {
                        LOG.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }
                case oneTimePerformanceTest: {
                    SignServerUtil.installBCProvider();
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final String pin = commandLine.getOptionValue(PIN);                

                    String signatureAlgorithm = commandLine.getOptionValue(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }

                    final String threadsString = commandLine.getOptionValue(THREADS, Integer.toString(1));
                    final int numThreads;
                    final int warmupTime;
                    final int timeLimit;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    if (numThreads < 1) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = commandLine.getOptionValue(WARMUPTIME, Integer.toString(0));
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        throw new ParseException("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = commandLine.getOptionValue(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                throw new ParseException("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            throw new ParseException("Illegal time limit: " + timeLimitString);
                        }
                    } else {
                        timeLimit = -1;
                    }

                    boolean useCache = Boolean.parseBoolean(commandLine.getOptionValue(USE_CACHE, CryptoTokenHelper.DEFAULT_PROPERTY_USE_CACHE));
                    
                    // find attributes to override
                    Properties attributesConfig;
                    AttributeProperties attributeProperties;
                    Map<Long, Object> publicAttributesMap;
                    Map<Long, Object> privateAttributesMap;
                    if (commandLine.hasOption(ATTRIBUTES_FILE)) {
                        final String attributeFilePath = commandLine.getOptionValue(ATTRIBUTES_FILE);
                        try {
                            attributesConfig = getAttributesPropertiesFromFile(attributeFilePath);
                        } catch (IOException ex) {
                            LOG.error("IO exception while reading attributes_file ", ex);
                            System.err.println("IO exception while reading attributes_file " + ex.getMessage());
                            break;
                        }
                        attributeProperties = AttributeProperties.fromWorkerProperties(attributesConfig);
                        publicAttributesMap = CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPublicTemplate("RSA"));
                        privateAttributesMap = CryptoTokenHelper.convertCKAAttributeListToMap(attributeProperties.getPrivateTemplate("RSA"));
                    } else {
                        publicAttributesMap = Collections.emptyMap();
                        privateAttributesMap = Collections.emptyMap();
                    }

                    try {
                        oneTimePerformanceTest(libName, libDir, slotId, pin,
                                       numThreads, warmupTime, timeLimit, useCache, signatureAlgorithm, publicAttributesMap, privateAttributesMap);
                    } catch (InterruptedException ex) {
                        LOG.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }                
                case unwrapPerformanceTest: {
                    SignServerUtil.installBCProvider();
                    if (!commandLine.hasOption(SLOT)) {
                        throw new ParseException("Missing " + SLOT);
                    }
                    final long slotId = Long.parseLong(commandLine.getOptionValue(SLOT));
                    if (!commandLine.hasOption(PIN)) {
                        throw new ParseException("Missing " + PIN);
                    }
                    final String pin = commandLine.getOptionValue(PIN);
                    if (!commandLine.hasOption(WRAPKEY)) {
                        throw new ParseException("Missing " + WRAPKEY);
                    }
                    final String wrapkey = commandLine.getOptionValue(WRAPKEY);
                    
                    String signatureAlgorithm = commandLine.getOptionValue(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }
                    
                    final String threadsString = commandLine.getOptionValue(THREADS, Integer.toString(1));
                    final int numThreads;
                    final int warmupTime;
                    final int timeLimit;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    if (numThreads < 1) {
                        throw new ParseException("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = commandLine.getOptionValue(WARMUPTIME, Integer.toString(0));
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        throw new ParseException("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        throw new ParseException("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = commandLine.getOptionValue(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                throw new ParseException("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            throw new ParseException("Illegal time limit: " + timeLimitString);
                        }
                    } else {
                        timeLimit = -1;
                    }
                    
                    boolean useCache = Boolean.parseBoolean(commandLine.getOptionValue(USE_CACHE, CryptoTokenHelper.DEFAULT_PROPERTY_USE_CACHE));
                    
                    try {
                        runUnwrapPerformanceTest(wrapkey, libName, libDir, slotId, pin,
                                                 numThreads, warmupTime, timeLimit, 
                                                 signatureAlgorithm, useCache);
                    } catch (InterruptedException ex) {
                        LOG.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }

            }
        } finally {
//            CE.Finalize();
        }      
        
    }
    
    private void runSignPerformanceTest(final String alias, final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm)
            throws InterruptedException {
        final TestSignThread[] threads = new TestSignThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                LOG.error("   " + message);
                exitCode = -1;
            }
        };
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new TestSignThread(i, failureCallback, alias, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, useCache, signatureAlgorithm);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final TestSignThread w : threads) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void oneTimePerformanceTest(final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm, 
                                        Map<Long, Object> publicAttributesMap, Map<Long, Object> privateAttributesMap)
            throws InterruptedException {
        final OneTimeThread[] threads = new OneTimeThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                LOG.error("   " + message);
                exitCode = -1;
            }
        };
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new OneTimeThread(i, failureCallback, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, useCache, signatureAlgorithm, publicAttributesMap, privateAttributesMap);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final OneTimeThread w : threads) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void runUnwrapPerformanceTest(final String alias, final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit,
                                        final String signatureAlgorithm,
                                        final boolean useCache)
            throws InterruptedException {
        final UnwrapThread[] threads = new UnwrapThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                LOG.error("   " + message);
                exitCode = -1;
            }
        };
        
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final long wrappingCipherAlgo = CKM.AES_CBC_PAD;
        final GeneratedKeyData wrappedKey =
                slot.generateWrappedKey(alias, "RSA", "2048", wrappingCipherAlgo);
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new UnwrapThread(i, failureCallback, alias, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, signatureAlgorithm,
                                            wrappedKey, wrappingCipherAlgo,
                                            useCache);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final UnwrapThread w : threads) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void shutdown(final OperationsThread[] threads,
                          final int warmupTime) {
        for (final OperationsThread thread : threads) {
            thread.stopIt();
        }
        
        int totalOperationsPerformed = 0;
        
        // wait until all stopped
        try {
            for (int i = 0; i < threads.length; i++) {
                final OperationsThread thread = threads[i];
                thread.join();
                final int numberOfOperations = thread.getNumberOfOperations();
                LOG.info("Number of operations for thread " + i + ": " + numberOfOperations);
                totalOperationsPerformed += thread.getNumberOfOperations();
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted: " + ex.getMessage());
        }
        
        long totalRunTime = System.currentTimeMillis() - startTime - warmupTime;
        final double tps;
        if (totalRunTime > 1000) {
            tps = totalOperationsPerformed / (totalRunTime / 1000d);
        } else {
            tps = Double.NaN;
        }
        
        
        LOG.info("Total number of signings: " + totalOperationsPerformed);
        LOG.info("Signings per second: " + tps);
    }

    private static void printGeneralObjectInfo(StringBuilder buff, long object, long session) {
        buff.append("Object ").append(object).append("\n");
        printStringOrHexObjectInfo(buff, object, session, CKA.ID, "CKA_ID");
        printStringOrHexObjectInfo(buff, object, session, CKA.LABEL, "CKA_LABEL");
    }

    private static void printCertificateObjectInfo(StringBuilder buff, long object, long session) {
        printX509NameObjectInfo(buff, object, session, CKA.SUBJECT, "CKA_SUBJECT");
        printX509NameObjectInfo(buff, object, session, CKA.ISSUER, "CKA_ISSUER");
    }

    private static void printStringOrHexObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append("0x").append(Hex.b2s(ckaValue.getValue()));
            buff.append(" \"").append(new String(ckaValue.getValue(), StandardCharsets.UTF_8)).append("\"");
        }
        buff.append("\n");
    }

    private static void printX509NameObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append(" \"").append(new X500Principal(value).toString()).append("\"");
        }
        buff.append("\n");
    } 

    private void unwrapAndSignUsingPKCS11(final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        LOG.debug("Using p11");
        
        ce.Initialize();
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.USER, pin.getBytes());   

        // Find unWrapKey
        long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
        long unWrapKey = -1;
        for (long object : secretObjects) {
            CKA ckaLabel = ce.GetAttributeValue(session, object, CKA.LABEL);
            if (ckaLabel != null && unwrapkey.equals(ckaLabel.getValueStr())) {
                unWrapKey = object;
                break;
                }
        }
        if (unWrapKey < 0) {
            System.err.println("No such secret key found: " + unwrapkey);
            return;
        }

        CKA[] unwrappedPrivateKeyTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.DECRYPT, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, true),
        };
        long privateKey = ce.UnwrapKey(session, new CKM(CKM.AES_CBC_PAD), unWrapKey, Base64.decode(wrapped), unwrappedPrivateKeyTemplate);
        System.out.println("Unwrapped key: " + privateKey);

        ce.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS, null), privateKey);
        ce.SignUpdate(session, plaintext.getBytes());
        byte[] signed = ce.SignFinal(session);
        System.out.println("signed: " + new String(Base64.encode(signed)));

        Security.addProvider(new BouncyCastleProvider());

        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(publicKey);
        sig.update(plaintext.getBytes());
        System.out.println("Consistent: " + sig.verify(signed));
        System.out.println();
    }

    private void unwrapAndSignUsingProvider(final String libName, final String libDir, final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        LOG.debug("Using provider");
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);

        PrivateKey privateKey = null;
        try {
            privateKey = slot.unwrapPrivateKey(Base64.decode(wrapped), unwrapkey, CKM.AES_CBC_PAD);

            Signature sig1 = Signature.getInstance("SHA256withRSA", device.getProvider());
            sig1.initSign(privateKey);
            sig1.update(plaintext.getBytes());
            byte[] signed = sig1.sign();
            System.out.println("signed: " + new String(Base64.encode(signed)));

            Security.addProvider(new BouncyCastleProvider());

            Signature sig2 = Signature.getInstance("SHA256withRSA", "BC");
            sig2.initVerify(publicKey);
            sig2.update(plaintext.getBytes());
            System.out.println("Consistent: " + sig2.verify(signed));
            System.out.println();
        } finally {
            if (privateKey != null) {
                slot.releasePrivateKey(privateKey);
            }
        }
    }
    
    private Properties getAttributesPropertiesFromFile(String filePath) throws IOException, ParseException {
        Properties attributesConfig = null;
        InputStream in = null;
        final File attributesfile = new File(filePath);
        try {
            if (attributesfile.exists()) {
                in = new FileInputStream(attributesfile);
                attributesConfig = new Properties();
                attributesConfig.load(in);
            } else {
                throw new ParseException(ATTRIBUTES_FILE + " not found at path: " + filePath);
            }
            return attributesConfig;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Could not close " + ATTRIBUTES_FILE, ex);
                }
            }
        }
    }
    
}
