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

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

/**
 * Custom Ant target for constructing "enable" and "include" properties for
 * the different projects/modules.
 * We do not use JavaScript for this as it is not guaranteed to be available.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SetModuleEnablePropertiesTask extends Task {

    @Override
    public void execute() throws BuildException {
        final String projectName = getProject().getProperty("modulename");
        final String enablename = projectName + ".enabled";
        getProject().setProperty("moduleEnableProperty", enablename);
        getProject().setProperty("moduleEnable",
                getProject().getProperty(enablename));
    }
    
}
