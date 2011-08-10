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

import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.FileSet;

/**
 * TODO
 * 
 * 
 * @author Philip Vendil 28 jun 2008
 * @version $Id$
 */
public class PartAntTask extends Task {

    private String name = "server";
    private List<FileSet> files = new ArrayList<FileSet>();

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    public void addConfiguredFileset(FileSet fileSet) {
        this.files.add(fileSet);
    }

    public List<FileSet> getFileSets() {
        return files;
    }
}
