/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * 
 * Use is subject to license terms.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Version {

    private static final String CURRENT_CLASS_RESOURCE_PATH = "org/odftoolkit/odfdom/Version.class";
    private static final String MANIFEST_JAR_PATH = "META-INF/MANIFEST.MF";
    private static String APPLICATION_NAME;
    private static String APPLICATION_VERSION;
    private static String APPLICATION_WEBSITE;
    private static String BUILD_BY;
    private static String BUILD_DATE;
    private static String SUPPORTED_ODF_VERSION;
   
    static {
        try {
            Manifest manifest = new Manifest(getManifestAsStream());
            Attributes attr = manifest.getEntries().get("ODFDOM");
            APPLICATION_NAME = attr.getValue("Application-Name");
            APPLICATION_VERSION = attr.getValue("Application-Version");
            APPLICATION_WEBSITE = attr.getValue("Application-Website");
            BUILD_BY = attr.getValue("Built-By");
            BUILD_DATE = attr.getValue("Built-Date");
            SUPPORTED_ODF_VERSION = attr.getValue("Supported-Odf-Version");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static InputStream getManifestAsStream() {
        String versionRef = Version.class.getClassLoader().getResource(CURRENT_CLASS_RESOURCE_PATH).toString();
        String manifestRef = versionRef.substring(0, versionRef.lastIndexOf(CURRENT_CLASS_RESOURCE_PATH)) + MANIFEST_JAR_PATH;
        URL manifestURL = null;
        InputStream in = null;
        try {
            manifestURL = new URL(manifestRef);
        } catch (MalformedURLException ex) {
            Logger.getLogger(Version.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            in = manifestURL.openStream();
        } catch (IOException ex) {
            Logger.getLogger(Version.class.getName()).log(Level.SEVERE, null, ex);
        }
        return in;
    }

    private Version() {
    }

    public static void main(String[] args) throws IOException {
        System.out.println(getApplicationTitle() + " (build " + getBuildDate() + ')' + "\nfrom " + getApplicationWebsite() + " supporting ODF " + getSupportedOdfVersion());
    }

    /**
     * Return the name of this application 
     * @return the application name
     */
    public static String getApplicationName() {
        return APPLICATION_NAME;
    }

    /**
     * Returns the application title 
     * 
     * @return A string containing both the application name and the application
     *     version
     */
    public static String getApplicationTitle() {
        return getApplicationName() + ' ' + getApplicationVersion();
    }    

    /**
     * Return the version of this application 
     * @return the application version
     */
    public static String getApplicationVersion() {
        return APPLICATION_VERSION;
    }

    /**
     * Return the website of this application 
     * @return the application website
     */
    public static String getApplicationWebsite() {
        return APPLICATION_WEBSITE;
    }

    /**
     * Return the name of the one building this application 
     * @return the name of the application builder
     */
    public static String getBuildResponsible() {
        return BUILD_BY;
    }

    /**
     * Return the date when the application had been build
     * @return the date of the build
     */
    public static String getBuildDate() {
        return BUILD_DATE;
    }

    /**
     * Returns the version of the OpenDocument specification covered by this application
     * @return the supported ODF version number
     */
    public static String getSupportedOdfVersion() {
        return SUPPORTED_ODF_VERSION;
    }
}
