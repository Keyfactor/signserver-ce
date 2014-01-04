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
package org.signserver.anttasks.ws;

import java.io.File;
import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.taskdefs.ExecTask;
import org.apache.tools.ant.types.Commandline.Argument;

/**
 * Wrapper task around the wsimport command line tool available with the JDK.
 * This task replaces the com.sun.tools.ws.ant.WsImport which might not be 
 * available everywhere.
 * @author Markus Kilås
 * @version $Id$
 */
public class WsImport extends Task {
    
    private String sourcedestdir;
    private String destdir;
    private String wsdl;
    private String catalog;
    private boolean extension;
    private boolean verbose;
    private String wsdlLocation;
    private boolean xendorsed;
    private String package_;
    private Depends depends;
    private Produces produces;
    private boolean xnocompile;
    private String target;
    private String encoding;

    @Override
    public void execute() throws BuildException {
        StringBuilder buff = new StringBuilder();
        buff.append("-d").append(" ").append(new File(getProject().getBaseDir(), getDestdir()).getAbsolutePath()).append(" ");
        if (isExtension()) {
            buff.append("-extension").append(" ");
        }
        buff.append("-keep").append(" ");
        buff.append("-s").append(" ").append(new File(getProject().getBaseDir(), getSourcedestdir()).getAbsolutePath()).append(" ");
        buff.append("-catalog").append(" ").append(new File(getProject().getBaseDir(), getCatalog()).getAbsolutePath()).append(" ");
        if (isVerbose()) {
            buff.append("-verbose").append(" ");
        }
        buff.append("-wsdllocation").append(" ").append(getWsdlLocation()).append(" ");
        if (getPackage() != null) {
            buff.append("-p").append(" ").append(getPackage()).append(" ");
        }
        if (getXnocompile()) {
            buff.append("-Xnocompile").append(" ");
        }
        if (getTarget() != null) {
            buff.append("-target ").append(getTarget()).append(" ");
        }
        buff.append(getWsdl());
        
        log("Command line: wsimport " + buff.toString());
        ExecTask exec = new ExecTask(this);
        exec.setFailIfExecutionFails(true);
        exec.setExecutable("wsimport");
        Argument arg1 = exec.createArg();
        arg1.setLine(buff.toString());
        exec.execute();
    }
    
    public void addDepends(Depends depends) {
        this.depends = depends;
    }
    
    public void addProduces(Produces produces) {
        this.produces = produces;
    }

    public String getCatalog() {
        return catalog;
    }

    public void setCatalog(String catalog) {
        this.catalog = catalog;
    }

    public String getDestdir() {
        return destdir;
    }

    public void setDestdir(String destdir) {
        this.destdir = destdir;
    }

    public boolean isExtension() {
        return extension;
    }

    public void setExtension(boolean extension) {
        this.extension = extension;
    }

    public String getSourcedestdir() {
        return sourcedestdir;
    }

    public void setSourcedestdir(String sourcedestdir) {
        this.sourcedestdir = sourcedestdir;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public String getWsdl() {
        return wsdl;
    }

    public void setWsdl(String wsdl) {
        this.wsdl = wsdl;
    }

    public String getWsdlLocation() {
        return wsdlLocation;
    }

    public void setWsdlLocation(String wsdlLocation) {
        this.wsdlLocation = wsdlLocation;
    }

    public boolean getXendorsed() {
        return xendorsed;
    }

    public void setXendorsed(boolean xendorsed) {
        this.xendorsed = xendorsed;
    }
    
    public void setPackage(String package_) {
        this.package_ = package_;
    }
    
    public String getPackage() {
        return package_;
    }

    public boolean getXnocompile() {
        return xnocompile;
    }

    public void setXnocompile(boolean xnocompile) {
        this.xnocompile = xnocompile;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

}
