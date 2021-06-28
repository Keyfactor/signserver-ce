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
package org.signserver.testutils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;

/**
 * Utilities for MS auth code system tests.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ComplianceTestUtils {
    // Logger for this class
    private final static Logger LOG = Logger.getLogger(ComplianceTestUtils.class);
    
    public static class ProcResult {
        private final int exitValue;
        private final String errorMessage;
        private final List<String> output;
        
        public ProcResult(int exitValue, String errorMessage, List<String> output) {
            this.exitValue = exitValue;
            this.errorMessage = errorMessage;
            this.output = output;
        }
        
        public int getExitValue() {
            return exitValue;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
        
        public List<String> getOutput() {
            return output;
        }
    }
    
    public static ProcResult executeWithEnv(String[] envp, String... arguments) throws IOException {
        return executeWritingWithEnv(null, envp, arguments);
    }

    public static ProcResult execute(String... arguments) throws IOException {
        return executeWritingWithEnv(null, null, arguments);
    }

    public static ProcResult executeWriting(byte[] write, String... arguments) throws IOException {
        return executeWritingWithEnv(write, null, arguments);
    }
    
    public static ProcResult executeWritingWithEnv(byte[] write, String[] envp, String... arguments) throws IOException {
        Process proc;
        BufferedReader stdIn = null;
        BufferedReader errIn = null;
        OutputStream stdOut = null;

        try {
            Runtime runtime = Runtime.getRuntime();
            
            LOG.info(Arrays.toString(arguments));

            proc = runtime.exec(arguments, envp);
            stdIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            errIn = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
            stdOut = proc.getOutputStream();
            
            if (write != null) {
                stdOut.write(write);
                stdOut.close();
            }

            List<String> lines = new LinkedList<>();
            String line;
            while ((line = stdIn.readLine()) != null) {
                lines.add(line);
            }

            StringBuilder errBuff = new StringBuilder();
            while ((line = errIn.readLine()) != null) {
                errBuff.append(line).append("\n");
            }
            try {
                proc.waitFor();
                return new ProcResult(proc.exitValue(), errBuff.toString(), lines);
            } catch (InterruptedException ex) {
                LOG.error("Command interrupted", ex);
                return new ProcResult(-1, errBuff.toString(), lines);
            }
        } finally {
            if (stdOut != null) {
                try {
                    stdOut.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (stdIn != null) {
                try {
                    stdIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
            if (errIn != null) {
                try {
                    errIn.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    public static String toString(List<String> output) {
        final StringBuilder sb = new StringBuilder();
        for (String s : output) {
            sb.append(s).append("\n");
        }
        return sb.toString();
    }
}
