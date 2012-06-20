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

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;

/**
 * Task postprocessing the modules.
 *
 * @author Markus Kilås
 * @author $Id$
 */
public class PostProcessModulesTask extends Task {
    private String modules;

    @Override
    public void execute() throws BuildException {
        if (modules == null) {
            throw new BuildException("Attribute 'modules' not specified");
        }
        
        // Get the list of all modules to process
        List<String> modulesList = asList(modules);
        log("Modules: " + modulesList, Project.MSG_DEBUG);
        
        // Process each module
        for (String module : modulesList) {
            
            // Get the list of all files to postprocess
            String postProcessFiles = getProject().getProperty(module + ".postprocess.files");
            if (postProcessFiles != null) {
                List<String> postProcessFilesList = asList(postProcessFiles);
                if (!postProcessFilesList.isEmpty()) {
                    log("Post processing module: " + module, Project.MSG_WARN);
                    String moduleType = getProject().getProperty(module + ".module.type");
                    log("    module.type: " + moduleType, Project.MSG_VERBOSE);
                    log("    Files to process: " + postProcessFilesList, Project.MSG_VERBOSE);
                    
                    // Process each jar-file
                    for (String postProcessFile : postProcessFilesList) {
                        try {
                            String dest = getProject().getProperty(module + "." + postProcessFile +".dest");
                            if (dest == null) {
                                dest = "";
                            }
                            log("    "+postProcessFile+".dest: " + dest, Project.MSG_DEBUG);
                            String src = getProject().getProperty(module  + "." + postProcessFile +".src");
                            log("    "+postProcessFile+".src: " + src, Project.MSG_DEBUG);
                            String includes = getProject().getProperty(module  + "." + postProcessFile +".includes");
                            log("    "+postProcessFile+".includes: " + includes, Project.MSG_DEBUG);
                            String destfile = getProject().getProperty("signserver.ear.dir") + "/" + dest + src;
//                            String tempdir = getProject().getProperty("tmp") + "/" + module + "-" + src + ".dir";
                            
                            // Postprocess the files
                            replaceInJar(includes, "lib/" + src, destfile, getProject().getProperties(), this);
                        } catch (IOException ex) {
                            throw new BuildException(ex);
                        }
                    }
                }
            }
        }
    }
    
    private static List<String> asList(String items) {
        final LinkedList<String> result = new LinkedList<String>();
        for (String item : items.split(",")) {
            item = item.trim();
            if (!item.isEmpty()) {
                result.add(item);
            }
        }
        return result;
    }

    public String getModules() {
        return modules;
    }

    public void setModules(String modules) {
        this.modules = modules;
    }
    
    /**
     * Replacer for the postprocess-jar Ant macro.
     * 
     * @param replaceincludes Ant list of all files in the jar to replace in
     * @param src Source jar file
     * @param destfile Destination jar file
     * @param properties Properties to replace from
     * @param self The Task (used for logging)
     * @throws IOException in case of error
     */
    public static void replaceInJar(String replaceincludes, String src, String destfile, Map properties, Task self) throws IOException {
        try {
            self.log("Replace " + replaceincludes + " in " + src + " to " + destfile, Project.MSG_VERBOSE);
            
            File srcFile = new File(src);
            if (!srcFile.exists()) {
                throw new FileNotFoundException(srcFile.getAbsolutePath());
            }
//            
//            File tempDirFile = new File(tempdir);
//            if (tempDirFile.exists()) {
//                FileUtils.deleteDirectory(tempDirFile);
//            }
//            if (!tempDirFile.mkdir()) {
//                throw new BuildException("Temp dir could not be created: " + tempDirFile.getAbsolutePath());
//            }
            
            // Expand properties of all files in replaceIncludes
            HashSet<String> replaceFiles = new HashSet<String>();
            String[] rfiles = replaceincludes.split(",");
            for (int i = 0; i < rfiles.length; i++) {
                rfiles[i] = rfiles[i].trim();
            }
            replaceFiles.addAll(Arrays.asList(rfiles));
            self.log("Files to replace: " + replaceFiles, Project.MSG_INFO);
            
            // Open source zip file
            ZipFile zipSrc = new ZipFile(srcFile);
            ZipOutputStream zipDest = new ZipOutputStream(new FileOutputStream(destfile));

            // For each entry in the source file copy them to dest file and postprocess if necessary
            Enumeration<? extends ZipEntry> entries = zipSrc.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                
                if (entry.isDirectory()) {
                    // Just put the directory
                    zipDest.putNextEntry(entry);
                } else {
                    // If we should postprocess the entry
                    if (replaceFiles.contains(name)) {
                        name += (" [REPLACE]");
                        self.log(name, Project.MSG_VERBOSE);
                        
                        // Create a new zip entry for the file
                        ZipEntry newEntry = new ZipEntry(entry.getName());
                        newEntry.setComment(entry.getComment());
                        newEntry.setExtra(entry.getExtra());
                        zipDest.putNextEntry(newEntry);
                        
                        // Read the old document
                        StringBuffer oldDocument = stringBufferFromFile(zipSrc.getInputStream(entry));
                        self.log("Before replace ********\n" + oldDocument.toString() + "\n", Project.MSG_DEBUG);
                        
                        // Do properties substitution
                        StrSubstitutor sub = new StrSubstitutor(properties);
                        String newDocument = sub.replace(oldDocument);
                        self.log("After replace ********\n" + newDocument.toString() + "\n", Project.MSG_DEBUG);
                        
                        // Write the new document
                        byte[] newBytes = newDocument.getBytes("UTF-8");
                        entry.setSize(newBytes.length);
                        copy(new ByteArrayInputStream(newBytes), zipDest);
                    } else {
                        // Just copy the entry to dest zip file
                        name += (" []");
                        self.log(name, Project.MSG_VERBOSE);
                        zipDest.putNextEntry(entry);
                        copy(zipSrc.getInputStream(entry), zipDest);
                    }
                    zipDest.closeEntry();
                }
            }
            zipSrc.close();
            zipDest.close();
        } catch (IOException ex) {
            throw new BuildException(ex);
        }
    }
    
    /**
     * Reads from one stream and writes on the other, with a buffer.
     */
    private static void copy(InputStream in, OutputStream out) throws IOException {
        int read;
        byte[] buff = new byte[10 * 1024];
        while ((read = in.read(buff))!= -1) {
            out.write(buff, 0, read);
        }
    }

    /**
     * Reads a text file into a StringBuffer. The StringBuffer can then be used 
     * by the StrSubstitutor.
     */
    private static StringBuffer stringBufferFromFile(InputStream in) throws IOException {
        StringBuffer result = new StringBuffer();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(in));
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
                result.append("\n");
            }
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        return result;
    }
}
