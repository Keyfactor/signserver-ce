/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.webtest.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.internal.ProfilesIni;
import org.signserver.common.util.PathUtil;

/**
 * WebTestBase is a base class and should be extended by all web tests.
 * 
 * @version $Id$
 */
public abstract class WebTestBase {

    private static final String APPSERVER_DOMAINNAME = "webtest.appserver.domainname";
    private static final String APPSERVER_PORT = "webtest.appserver.port";
    private static final String APPSERVER_SECUREPORT = "webtest.appserver.secureport";
    private static final String EXECUTION_TMPDIR = "webtest.execution.tmpdir";
    private static final String FIREFOX_PROFILE_DEFAULT = "webtest.firefox.profile.default";

    /**
     * webDriver used to access elements on web page
     */
    protected static WebDriver webDriver;
    private static String uniqueId;
    private static String testDir;
    private static Properties properties;

    /**
     * Sets up the test, reads webtest.properties and configures the WebDriver
     * accordingly.
     * 
     * @param testName the name of the test (
     */
    protected static void setUp(String testName) {
        // Load properties
        properties = new Properties();
        try {
            properties.load(WebTestBase.class.getClassLoader().getResourceAsStream("webtest.properties"));
        } catch (IOException e) {
            Assert.fail("Error loading properties: " + e.getMessage());
        }

        // Set the unique ID of the test execution
        uniqueId = testName + "_" + String.valueOf(System.currentTimeMillis());

        // Create a local temporary directory for files used during test
        testDir = properties.getProperty(EXECUTION_TMPDIR) + "/" + uniqueId;
        try {
            File testDirFile = new File(testDir);
            FileUtils.forceMkdir(testDirFile);

            // Schedule deletion of the directory when the JVM exits, note that
            // the directory needs to be empty for this to work
            FileUtils.forceDeleteOnExit(testDirFile);
        } catch (IOException e) {
            Assert.fail("Unable to create local directory " + testDir + ": " + e.getMessage());
        }

        // Set Firefox driver property
        System.setProperty("webdriver.gecko.driver", getSignServerDir() + "/lib/ext/ext/geckodriver-v0.21.0-linux64.bin");

        // Configure Firefox options
        ProfilesIni allProfiles = new ProfilesIni();
        FirefoxProfile firefoxProfile;
        firefoxProfile = allProfiles.getProfile(properties.getProperty(FIREFOX_PROFILE_DEFAULT));
        firefoxProfile.setPreference("security.default_personal_cert", "Select Automatically");
        firefoxProfile.setPreference("browser.download.folderList", 2);
        firefoxProfile.setPreference("browser.download.dir", testDir);
        firefoxProfile.setPreference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream,text/plain,application/pdf,application/pkcs7-signature,application/pkcs10,text/xml,application/zip");
        FirefoxOptions firefoxOptions = new FirefoxOptions();
        firefoxOptions.setProfile(firefoxProfile);
        firefoxOptions.setAcceptInsecureCerts(true);
        webDriver = new FirefoxDriver(firefoxOptions);

        // Set AuditLogHelper filter time
        AuditLogHelper.resetFilterTime();
        // Set Archive filter time
        ArchiveHelper.resetFilterTime();
    }

    /**
     * @return the WebDriver
     */
    public static WebDriver getWebDriver() {
        return webDriver;
    }

    /**
     * @return the unique ID of the test execution
     */
    public static String getUniqueId() {
        return uniqueId;
    }

    /**
     * @return the path to the local temporary directory for files used in test
     */
    public static String getTestDir() {
        return testDir;
    }

    /**
     * @return the SignServer application directory
     */
    public static String getSignServerDir() {
        try {
            return PathUtil.getAppHome().getAbsolutePath();
        } catch (FileNotFoundException e) {
            Assert.fail("Could not find SignServer: " + e.getMessage());
            return null;
        }
    }

    /**
     * @return the AdminWeb URL
     */
    public static String getAdminWebUrl() {
        return "https://" + properties.getProperty(APPSERVER_DOMAINNAME) + ":"
                + properties.getProperty(APPSERVER_SECUREPORT) + "/signserver/adminweb";
    }
    
    /**
     * @return the ClientWeb URL
     */
    public static String getClientWebUrl() {
        return "https://" + properties.getProperty(APPSERVER_DOMAINNAME) + ":"
                + properties.getProperty(APPSERVER_SECUREPORT) + "/signserver/clientweb";
    }
    
    /**
     * @return the Web interface URL
     */
    public static String getWebInterfaceUrl() {
        return "https://" + properties.getProperty(APPSERVER_DOMAINNAME) + ":"
                + properties.getProperty(APPSERVER_SECUREPORT) + "/signserver/";
    }
}
