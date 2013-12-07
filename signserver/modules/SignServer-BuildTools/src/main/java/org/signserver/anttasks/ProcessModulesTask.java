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
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;

/**
 * Ant Task for parsing all the modules descriptors and compile the list of all 
 * enabled modules and libraries that need to be copied to the EAR file etc.
 *
 * TODO: Document attributes.
 * TODO: Usage example.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ProcessModulesTask extends Task {

    private File modsDir;
    private String rootSet;
    private String libSet;
    private String configRootSet;
    private String configConfSet;
    private String applicationXml;
    private String enabledModules;
    private boolean allEnabled;
    
    @Override
    public void execute() throws BuildException {
        FileFilter filter = new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                return pathname.getName().endsWith(".properties");
            }
        };
        Set<String> libJars = new HashSet<String>();
        Set<String> rootJars = new HashSet<String>();
        Set<String> configRootFiles = new HashSet<String>();
        Set<String> configConfFiles = new HashSet<String>();
        StringBuilder xmlBuff = new StringBuilder();
        StringBuilder enabledModulesBuff = new StringBuilder();
        File[] propertyFiles = modsDir.listFiles(filter);
        Arrays.sort(propertyFiles, new ProcessModulesTask.FileNameComparator());
        for (File file : propertyFiles) {
            log("Processing: " + file, Project.MSG_VERBOSE);
            Properties properties = loadProperties(file);
            String name = properties.getProperty("module.name");
            boolean enabled = allEnabled || Boolean.parseBoolean(getProject().getProperty(name + ".enabled"));
            
            log("Module " + name + ": " + (enabled ? "enabled" : "disabled"), Project.MSG_WARN);
            
            if (enabled) {
                xmlBuff.append("\n    <!-- Enabled: ").append(name).append(" -->");
                enabledModulesBuff.append(name).append(",");
                setPropertiesWithPrefix(name, properties);
                
                String toRoot = properties.getProperty("to.root");
                List<String> toRootList = Arrays.asList(toRoot.split(","));
                rootJars.addAll(toRootList);
                log("To root: " + toRootList.toString(), Project.MSG_VERBOSE);
                
                String toLib = properties.getProperty("to.lib");
                List<String> toLibList = Arrays.asList(toLib.split(",")); 
                libJars.addAll(toLibList);
                log("To lib: " + toLibList.toString(), Project.MSG_VERBOSE);
                
                String toConfigRoot = properties.getProperty("to.config");
                if (toConfigRoot != null) {
                    List<String> toConfigList = Arrays.asList(toConfigRoot.split(",")); 
                    configRootFiles.addAll(toConfigList);
                    log("To config root: " + toConfigList.toString(), Project.MSG_VERBOSE);
                }
                String toConfigConf = properties.getProperty("to.config.conf");
                if (toConfigConf != null) {
                    List<String> toConfigList = Arrays.asList(toConfigConf.split(",")); 
                    configConfFiles.addAll(toConfigList);
                    log("To config conf: " + toConfigList.toString(), Project.MSG_VERBOSE);
                }
                
                String type = properties.getProperty("module.type", "lib");
                if (type.equalsIgnoreCase("ejb")) {
                    String ejb = properties.getProperty("module.ejb");
                    if (ejb == null) {
                        log("No module.ejb defined", Project.MSG_WARN);
                    } else {
                        xmlBuff.append("\n    <module>\n")
                                .append("        <ejb>").append(ejb).append("</ejb>\n")
                                .append("    </module>");
                    }
                } else if (type.equalsIgnoreCase("war")) {
                    String webUri = properties.getProperty("module.web.web-uri");
                    String contextRoot = properties.getProperty("module.web.context-root");
                    xmlBuff.append("\n    <module>\n")
                            .append("        <web>\n")
                            .append("            <web-uri>").append(webUri).append("</web-uri>\n")
                            .append("            <context-root>").append(contextRoot).append("</context-root>\n")
                            .append("        </web>\n")
                            .append("    </module>");
                }
                
                String postprocessFiles = properties.getProperty("postprocess.files", "");
                getProject().setProperty("postprocess." + name + ".files", postprocessFiles);
                for (String item : postprocessFiles.split(",")) {
                    getProject().setProperty("postprocess." + item+ ".src", properties.getProperty("postprocess." + item + ".src"));
                    getProject().setProperty("postprocess." + item+ ".includes", properties.getProperty("postprocess." + item + ".includes"));
                }
                
            } else {
                xmlBuff.append("\n    <!-- Disabled: ").append(name).append(" -->");
            }
        }
        
        getProject().setProperty(libSet, getAsString(libJars));
        getProject().setProperty(rootSet, getAsString(rootJars));
        if (configRootSet != null) {
            getProject().setProperty(configRootSet, getAsString(configRootFiles));
        }
        if (configConfSet != null) {
            getProject().setProperty(configConfSet, getAsString(configConfFiles));
        }
        getProject().setProperty(applicationXml, xmlBuff.toString());
        getProject().setProperty(enabledModules, enabledModulesBuff.toString());
    }
    
    private static String getAsString(Set<String> set) {
        StringBuilder buff = new StringBuilder();
        for (String item : set) {
            if (!item.isEmpty()) {
                buff.append(item).append(", ");
            }
        }
        return buff.toString();
    }
    
    private void setPropertiesWithPrefix(String prefix, Properties properties) {
        for (String key : properties.stringPropertyNames()) {
            String newName = prefix + "." + key;
            getProject().setProperty(newName, properties.getProperty(key));
            log("Setting property " + newName, Project.MSG_VERBOSE);
        }
    }

    public String getLibSet() {
        return libSet;
    }

    public void setLibSet(String libSet) {
        this.libSet = libSet;
    }

    public String getRootSet() {
        return rootSet;
    }

    public void setRootSet(String rootSet) {
        this.rootSet = rootSet;
    }

    public String getConfigRootSet() {
        return configRootSet;
    }

    public void setConfigRootSet(String configSet) {
        this.configRootSet = configSet;
    }
    
    public String getConfigConfSet() {
        return configConfSet;
    }

    public void setConfigConfSet(String configSet) {
        this.configConfSet = configSet;
    }

    public File getModsDir() {
        return modsDir;
    }

    public void setModsDir(File modsDir) {
        this.modsDir = modsDir;
    }
    
    public String getApplicationXml() {
        return applicationXml;
    }

    public void setApplicationXml(String applicationXml) {
        this.applicationXml = applicationXml;
    }

    public String getEnabledModules() {
        return enabledModules;
    }

    public void setEnabledModules(String enabledModules) {
        this.enabledModules = enabledModules;
    }

    public boolean isAllEnabled() {
        return allEnabled;
    }

    public void setAllEnabled(boolean allEnabled) {
        this.allEnabled = allEnabled;
    }

    private static Properties loadProperties(File file) {
        Properties properties;
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            properties = new Properties();
            properties.load(in);
            return properties;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {}
            }
        }
    }

    private static class FileNameComparator implements Comparator<File> {
        
        @Override
        public int compare(File f1, File f2) {
            // Use the lexicographical order of the names to get the same results
            // on all platforms
            return f1.getName().compareTo(f2.getName());
        }
    }
}
