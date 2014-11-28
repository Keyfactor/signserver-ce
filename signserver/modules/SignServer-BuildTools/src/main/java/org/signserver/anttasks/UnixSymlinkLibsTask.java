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
package org.signserver.anttasks;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

/**
 * Replaces all jars with symlinks as specified in the specified mapping file.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class UnixSymlinkLibsTask extends Task {
    
    private String action;
    private String dir;
    private String mappingsFile;
    
    private Properties mappings = new Properties();

    @Override
    public void execute() throws BuildException {
        log("Dir: " + dir + "\n" + "mappingsFile: " + mappingsFile);
        
        // Load mappings
        FileInputStream in = null;
        try {
            in = new FileInputStream(new File(mappingsFile));
            mappings.load(in);
        } catch (IOException ex) {
            throw new BuildException(ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {}
            }
        }
        
        if ("create".equalsIgnoreCase(action)) {
            for (Object key : mappings.keySet()) {
                Object value = mappings.get(key);
                if (key instanceof String && value instanceof String) {
                    File localFile = new File(dir, (String) key);
                    String mappedTo = (String) value;
                    if (!localFile.getParentFile().exists()) {
                        if (!localFile.getParentFile().mkdirs()) {
                            log("Failed to create directory: " + localFile.getParentFile());
                        }
                    }
                    System.out.println("ln -s " + mappedTo + " " + localFile);
                    localFile.delete();
                    if (localFile.exists()) {
                        if (!localFile.delete()) {
                            log("Failed to delete old file: " + localFile);
                        }
                    }
                    try {
                        symlink(mappedTo, localFile.getAbsolutePath());
                    } catch (IOException ex) {
                        throw new BuildException(ex);
                    } catch (InterruptedException ex) {
                        throw new BuildException(ex);
                    }
                }
            }
        } else if ("replace".equalsIgnoreCase(action)) {
            File directory = new File(dir);
            try {
                processDirectory(directory, "", 5);
            } catch (IOException ex) {
                throw new BuildException(ex);
            } catch (InterruptedException ex) {
                throw new BuildException(ex);
            }
        } else {
            throw new BuildException("action should be either 'create' or 'replace'");
        }
        
        log("lib/ext/log4j.jar = " + mappings.getProperty("lib/ext/log4j.jar"));
        
    }
    
    private void processDirectory(File directory, String currentDir, int deepth) throws IOException, InterruptedException {
        if (deepth <= 0) {
            log("Max deepth reached in processing libs");
            return;
        }
        for (File file : directory.listFiles()) {
            if (file.isDirectory() && !file.isHidden()) {
//                log("directory: " + file.getName());
                processDirectory(file, currentDir + file.getName() + File.separator, deepth - 1);
            } else if (file.isFile() && file.canWrite()) {
                String mappedTo = mappings.getProperty(currentDir + file.getName());
                if (mappedTo != null) { 
                    log("file: " + currentDir + file.getName() + " is mapped to " + mappedTo);
                    file.delete();
                    symlink(mappedTo, file.getAbsolutePath());
                }
            }
        }
    }
    
    private static void symlink(String source, String dest) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec( new String[] { "ln", "-s", source, dest } );
        BufferedReader in = null;
        StringBuilder error = new StringBuilder();
        try {
            in = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            int ch;
            while ((ch = in.read()) != -1) {
                error.append((char) ch);
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        process.waitFor();
        process.destroy();
        if (process.exitValue() != 0) {
            throw new IOException("Symlink failed: " + error.toString());
        }
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
    
    public String getDir() {
        return dir;
    }

    public void setDir(String dir) {
        this.dir = dir;
    }

    public String getMappingsFile() {
        return mappingsFile;
    }

    public void setMappingsFile(String mappingsFile) {
        this.mappingsFile = mappingsFile;
    }
    
}
