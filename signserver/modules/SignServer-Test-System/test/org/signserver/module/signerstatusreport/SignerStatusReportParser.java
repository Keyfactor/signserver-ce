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
package org.signserver.module.signerstatusreport;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Parses a signer status report according to the format specified in the 
 * manual for the SignerStatusReportTimedService.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignerStatusReportParser {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignerStatusReportParser.class);
    
    /**
     * Parses the report from an InputStream.
     *
     * Sample file:
     * <pre>
     *   workerName=Sod1, status=OFFLINE, signings=10000, signLimit=10000,
     *   workerName=Sod2, status=ACTIVE, signings=33524, signLimit=100000,
     *   workerName=Sod3, status=OFFLINE, signings=10000, signLimit=10000,
     *   workerName=Sod4, status=OFFLINE, signings=10000, signLimit=10000,
     *   workerName=Sod5, status=OFFLINE, signings=10000, signLimit=10000,
     *   workerName=Sod6, status=ACTIVE, signings=4676,
     *   workerName=Sod7, status=OFFLINE,
     * </pre>
     *
     * @param in stream to read the report from
     * @return Map from worker names to map of keys to values
     */
    public Map<String, Map<String, String>> parse(final InputStream in) throws FileNotFoundException, IOException {

        final Map<String, Map<String, String>> res
                = new HashMap<String, Map<String, String>>();

        BufferedReader bin = new BufferedReader(new InputStreamReader(in));
        String line;
        while ((line = bin.readLine()) != null) {
            Map<String, String> entry = new HashMap<String, String>();

            String[] parts = line.split(", ");
            for (String part : parts) {
                String[] keyval = part.split("=", 2);
                if (keyval.length == 2) {
                    entry.put(keyval[0], keyval[1]);
                } else {
                    throw new IOException("Unparsable line: \"" + part + "\"");
                }
            }
            res.put(entry.get("workerName"), entry);
        }
        return res;
    }
    
    /**
     * Convenience method parsing from a File.
     * @see #parse(java.io.InputStream) 
     */
    public Map<String, Map<String, String>> parseOutputFile(
            final File outputFile) throws FileNotFoundException, IOException {
        FileInputStream in = null;
        try {
            in = new FileInputStream(outputFile);
            return parse(in);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error(ex.getMessage(), ex);
                }
            }
        }
    }
}
