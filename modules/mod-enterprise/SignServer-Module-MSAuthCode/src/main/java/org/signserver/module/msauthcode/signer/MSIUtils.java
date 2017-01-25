/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.module.msauthcode.signer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Set;
import org.apache.log4j.Logger;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

/**
 *
 * @author user
 */
public class MSIUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(MSIUtils.class);

    public static ArrayList<String> sort(Set<String> entries) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Entries orig: " + entries + ", entries.len: " + entries.size());
        }
        ArrayList<String> result = new ArrayList<>(entries);
        Collections.sort(result, new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                int result;
                byte[] o1bs = o1.getBytes(StandardCharsets.UTF_16LE);
                byte[] o2bs = o2.getBytes(StandardCharsets.UTF_16LE);
                //System.out.println("o1bs: " + Hex.toHexString(o1bs));
                result = memcmp(o1bs, o2bs, Math.min(o1bs.length, o2bs.length));
                if (result == 0) {
                    result = 2 * o1bs.length > 2 * o2bs.length ? 1 : -1;
                }
                return result;
            }
        });
        if (LOG.isDebugEnabled()) {
            LOG.debug("Entries sort: " + result);
        }
        return result;
    }
    
    /**
     * From the Linux man pages:
     * 
     * <i>
     * The memcmp() function returns an integer less than, equal to, or greater
     * than zero if the first n bytes of s1 is found, respectively, to be less
     * than, to match, or be greater than the first n bytes of s2.
     *
     * For a nonzero return value, the sign is determined by the sign of the 
     * difference between the first pair of bytes (interpreted as unsigned char)
     * that differ in s1 and s2.
     *
     * If n is zero, the return value is zero.
     * </i>
     * 
     * 
     * @param s1
     * @param s2
     * @param n
     * @return 
     */
    public static int memcmp(byte[] s1, byte[] s2, int n) {
        for (int i = 0; i < n; i++) {
            if (s1[i] != s2[i]) {
                if ((s1[i] >= 0 && s2[i] >= 0) || (s1[i] < 0 && s2[i] < 0)) {
                    return s1[i] - s2[i];
                }
                if (s1[i] < 0 && s2[i] >= 0) {
                    return 1;
                }
                if (s2[i] < 0 && s1[i] >= 0) {
                    return -1;
                }
            }
        }
        return 0;
    }
    
    /**
     * Traverse directory entries of a POI filesystem and update a digest
     * instance.
     * 
     * @param fs Filesystem
     * @param root Root entry
     * @param md Message digest to operate on
     * @throws IOException 
     */
    public static void traverseDirectory(POIFSFileSystem fs, DirectoryEntry root, MessageDigest md) throws IOException {
        for (String name : sort(root.getEntryNames())) {
            
            Entry entry = root.getEntry(name);
            if (LOG.isTraceEnabled()) {
                LOG.trace("found entry: \"" + entry.getName() + "\"" + " which is " + entry);
            }
            if (entry instanceof DirectoryEntry) {
                // .. recurse into this directory
                DirectoryEntry dirEntry = (DirectoryEntry) entry;
                LOG.trace("Is directory");
                traverseDirectory(fs, dirEntry, md);
            } else if (entry instanceof DocumentEntry) {
                // entry is a document, which you can read
                //DocumentEntry docEntry = (DocumentEntry) entry;
                LOG.trace("Is document");

                if ("\05DigitalSignature".equals(entry.getName())) {
                    LOG.trace("Found Signature");
                } else {
                    DocumentInputStream stream = fs.createDocumentInputStream(entry.getName());
                    byte[] content = new byte[stream.available()]; // Note: This is by the book
                    stream.read(content);
                    stream.close();
                    md.update(content);
                }
            } else {
                // currently, either an Entry is a DirectoryEntry or a DocumentEntry,
                // but in the future, there may be other entry subinterfaces. The
                // internal data structure certainly allows for a lot more entry types.
                LOG.trace("Is other");
            }
        }
        
        // Add ClassID
        final byte[] classid = new byte[16];
        root.getStorageClsid().write(classid, 0);
        md.update(classid);
    }
}
