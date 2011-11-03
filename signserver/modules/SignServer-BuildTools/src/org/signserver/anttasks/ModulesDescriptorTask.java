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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.taskdefs.Property;

/**
 * Ant Task for creating a SignServer modules descriptor (property files to be 
 * placed under SIGNSERVER_HOME/mods-available) from an existing classpath.
 * 
 * TODO: Describe attributes.
 * TODO: Usage example.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ModulesDescriptorTask extends Task {

    private String moduleName;
    private String moduleType;
    private String classpathValue;
    private String dists;
    private File toFile;
    private String libsPrefix;
    private String excludePrefix;
    
    private Vector nestedProperties = new Vector();
    
    @Override
    public void execute() throws BuildException {
        
        if (dists == null) {
            throw new BuildException("Missing attribute 'dists'");
        }
        
        
        System.out.println("Value: " + getClasspathValue());
        
        Properties properties = new Properties();
        
        StringBuilder rootJars = new StringBuilder();
        StringBuilder libJars = new StringBuilder();
        
        Set<String> excludePrefixes = new HashSet<String>();
        if (excludePrefix != null) {
            for (String exclude : excludePrefix.split(",")) {
                excludePrefixes.add(exclude);
                System.out.println("exclude: " + exclude);
            }
        }
        Set<String> libsPrefixes = new HashSet<String>();
        if (libsPrefix != null) {
            for (String exclude : libsPrefix.split(",")) {
                libsPrefixes.add(exclude);
                System.out.println("libPrefix: " + exclude);
            }
        }
        
        outer: for (String lib : getClasspathValue().split(":")) {
            if (!lib.isEmpty()) {
                for (String exclude : excludePrefixes) {
                    if (!exclude.isEmpty() && lib.startsWith(exclude)) {
                        System.out.println("Skipping: " + lib);
                        continue outer;
                    }
                }
                for (String libs : libsPrefixes) {
                    if (!libs.isEmpty() && lib.startsWith(libs)) {
                        lib = new File("lib/" + lib.substring(libs.length())).getPath();
                        System.out.println("lib: " + lib);
                        libJars.append(lib).append(":");
                        continue outer;
                    }
                }
                if (lib.startsWith("..")) {
                    lib = "dist-server/" + new File(lib).getName();
                    System.out.println("local dep: " + lib);
                } else {
                    System.out.println("other: " + lib);
                }
                libJars.append(lib).append(":");
            }
        }
        
        if (moduleType.equalsIgnoreCase("ejb") || moduleType.equalsIgnoreCase("war")) {
            for (String lib : dists.split(":")) {
                rootJars.append("dist-server/").append(lib).append(":");
                System.out.println("Enterprise: " + lib);
            }
        } else if (moduleType.equalsIgnoreCase("lib")) {
            for (String lib : dists.split(":")) {
                libJars.append("dist-server/").append(lib).append(":");
                System.out.println("Lib: " + lib);
            }
        } else {
            throw new BuildException("Unknown module.type");
        }
        
        for (Iterator it=nestedProperties.iterator(); it.hasNext(); ) {
            Property property = (Property)it.next();
            log("Setting nested property: " + property.getName());
            properties.put(property.getName(), property.getValue());
        }
        
        properties.setProperty("module.name", moduleName);
        properties.setProperty("module.type", moduleType);
        properties.setProperty("to.root", rootJars.toString());
        properties.setProperty("to.lib", libJars.toString());
        
        OutputStream out = null;
        try {
            out = new FileOutputStream(toFile);
            properties.store(out, null);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {}
            }
        }
    }

    public String getModuleName() {
        return moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getModuleType() {
        return moduleType;
    }

    public void setModuleType(String moduleType) {
        this.moduleType = moduleType;
    }

    public String getClasspathValue() {
        return classpathValue;
    }

    public void setClasspathValue(String classpathValue) {
        this.classpathValue = classpathValue;
    }

    public String getDists() {
        return dists;
    }

    public void setDists(String dists) {
        this.dists = dists;
    }

    public File getToFile() {
        return toFile;
    }

    public void setToFile(File toFile) {
        this.toFile = toFile;
    }

    public String getLibsPrefix() {
        return libsPrefix;
    }

    public void setLibsPrefix(String libsPrefix) {
        this.libsPrefix = libsPrefix;
    }

    public String getExcludePrefix() {
        return excludePrefix;
    }

    public void setExcludePrefix(String excludePrefix) {
        this.excludePrefix = excludePrefix;
    }
    
    public Property createProperty() {
        Property msg = new Property();
        nestedProperties.add(msg);
        return msg;
    }

}
