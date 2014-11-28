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

import java.util.Properties;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Target;
import org.apache.tools.ant.Task;

/**
 * Ant Task calling a target for each name in a list. 
 *
 * Optionally all properties prefixed with that name will be copied to new 
 * properties with a specified prefix before the target is called and then 
 * cleared afterwards.
 *
 * See build.xml for an example of how this Task is used.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class AntCallForAllTask extends Task {
    
    private String names;
    private String callTarget;
    private String propertySuffixes;
    private String newPropertyPrefix;
    private String prePrefix;
    private String unlessEmpty;

    @Override
    public void execute() throws BuildException {
        if (names == null) {
            throw new BuildException("Attribute 'names' not specified");
        }
        if (prePrefix == null) {
            prePrefix = "";
        }
        
        for (String name : names.split(",")) {
            name = name.trim();
            if (!name.isEmpty()) {
                String callTargetProperty = newPropertyPrefix == null ? "calledname" : newPropertyPrefix + ".calledname";
                getProject().setProperty(callTargetProperty, name);
                if (newPropertyPrefix != null && !newPropertyPrefix.isEmpty()) {
                    setPropertiesWithNewPrefix(prePrefix + name , newPropertyPrefix);
                }
                String newUnlessEmpty = newPropertyPrefix + "." + unlessEmpty;
                if (unlessEmpty != null && !unlessEmpty.isEmpty() && (getProject().getProperty(newUnlessEmpty) == null || getProject().getProperty(newUnlessEmpty).isEmpty())) {
                    log("Not calling target " + callTarget + " for name " + name + " as property is not set: " + unlessEmpty, Project.MSG_VERBOSE);
                } else {
                    log("Calling target " + callTarget + " for name " + name);
                    Target t = (Target) getProject().getTargets().get(callTarget);
                    t.execute();
    //                getProject().executeTarget(callTarget);
                    if (newPropertyPrefix != null && !newPropertyPrefix.isEmpty()) {
                        clearPropertiesWithPrefix(newPropertyPrefix);
                    }
                }
                getProject().setProperty(callTargetProperty, "");
            }
        }
    }

    public String getNames() {
        return names;
    }

    public void setNames(String names) {
        this.names = names;
    }

    public String getPropertySuffixes() {
        return propertySuffixes;
    }

    public void setPropertySuffixes(String propertySuffixes) {
        this.propertySuffixes = propertySuffixes;
    }

    public String getTarget() {
        return callTarget;
    }

    public void setTarget(String target) {
        this.callTarget = target;
    }

    public String getNewPropertyPrefix() {
        return newPropertyPrefix;
    }

    public void setNewPropertyPrefix(String newPropertyPrefix) {
        this.newPropertyPrefix = newPropertyPrefix;
    }

    public String getPrePrefix() {
        return prePrefix;
    }

    public void setPrePrefix(String prePrefix) {
        this.prePrefix = prePrefix;
    }

    public String getUnlessEmpty() {
        return unlessEmpty;
    }

    public void setUnlessEmpty(String unlessEmpty) {
        this.unlessEmpty = unlessEmpty;
    }

    private void setPropertiesWithNewPrefix(String oldPrefix, String newPrefix) {
        Properties newProperties = new Properties();
        for (Object o : getProject().getProperties().keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(oldPrefix + ".")) {
                    newProperties.setProperty(newPrefix + "." + key.substring(oldPrefix.length() + 1), getProject().getProperty(key));
                }
            }
        }
//        System.out.println("new properties: " + newProperties);
        for (String key : newProperties.stringPropertyNames()) {
            getProject().setProperty(key, newProperties.getProperty(key));
        }
//        getProject().getProperties().putAll(newProperties);
    }

    private void clearPropertiesWithPrefix(String prefix) {
        for (Object o : getProject().getProperties().keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(prefix + ".")) {
                    getProject().setProperty(key, "");
                }
            }
        }
    }
    
    
    
}
