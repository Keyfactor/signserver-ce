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

import com.google.common.collect.ImmutableMap;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.log4j.Logger;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * WebTestHelper contains general helper methods for web tests.
 * 
 * @version $Id$
 */
public class WebTestHelper {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(WebTestHelper.class);
    
    private WebTestHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /* Non-web helper methods */

    /**
     * Copies a file locally and schedules it for deletion when the JVM exits.
     * 
     * @param from the file to copy
     * @param to the file destination
     */
    public static void copyFileTemporarily(String from, String to) {
        File fromFile = new File(from);
        File toFile = new File(to);
        try {
            FileUtils.copyFile(fromFile, toFile);
            FileUtils.forceDeleteOnExit(toFile);
        } catch (IOException e) {
            Assert.fail("Could not copy file from " + fromFile + " to " + toFile + ": " + e.getMessage());
        }
    }
    
    /**
     * Copies a file fromFile to toFile.
     *
     * @param fromFile
     * @param toFile
     */
    public static void copyFile(File fromFile, File toFile) {
        try {
            FileUtils.copyFile(fromFile, toFile);
            // File is to be deleted by calling test case
        } catch (IOException e) {
            Assert.fail("Could not copy file from " + fromFile + " to " + toFile + ": " + e.getMessage());
        }
    }

    /**
     * Deletes all files in the local temporary directory.
     * 
     * This method must be called if the test has performed a download, since
     * the temporary directory will not be deleted upon exit if it's not empty.
     */
    public static void deleteTestFiles() {
        File testDir = new File(WebTestBase.getTestDir());
        try {
            FileUtils.cleanDirectory(testDir);
        } catch (IOException e) {
            Assert.fail("Could not clean the test directory " + testDir + ": " + e.getMessage());
        }
    }

    /**
     * Reads a file in the local temporary directory and returns a list of it's lines.
     * 
     * If there is more than one file matching the pattern
     * 
     * @param pattern the pattern to use for finding the file (wildcards permitted)
     * @param encoding the file's encoding
     * @return a list of strings where each string is a line in the file
     */
    public static List<String> linesFromFile(String pattern, Charset encoding) {
        try {
            File[] matches = new File(WebTestBase.getTestDir()).listFiles((FileFilter) new WildcardFileFilter(pattern));
            return Files.readAllLines(matches[0].toPath(), encoding);
        } catch (IOException e) {
            Assert.fail("Could not read file from pattern " + pattern + ": " + e.getMessage());
            return null;
        }
    }

    /* Web helper methods */

    /**
     * Opens the SignServer AdminWeb.
     */
    public static void openAdminWeb() {
        WebTestBase.getWebDriver().get(WebTestBase.getAdminWebUrl());
    }
    
    /**
     * Opens the SignServer Client Web page.
     */
    public static void openClientWebPage() {
        WebTestBase.getWebDriver().get(WebTestBase.getClientWebUrl());
    }
    
    /**
     * Opens the SignServer web interface page.
     */
    public static void openWebInterfacePage() {
        WebTestBase.getWebDriver().get(WebTestBase.getWebInterfaceUrl());
    }

    /**
     * Checks if an element exists on the current page.
     * 
     * @param by the By to use as the parameter for findElement
     * @return true if at least one element is found
     */
    public static boolean elementExists(By by) {
        try {
            WebTestBase.getWebDriver().findElement(by);
            return true;
        } catch (NoSuchElementException e) {
            return false;
        }
    }

    /**
     * Clears a text field and then fills it with text.
     * 
     * @param field the text field to clear
     * @param text the text to fill in
     */
    public static void setText(WebElement field, String text) {
        field.clear();
        field.sendKeys(text);
    }

    /**
     * Selects an entry in a dropdown menu.
     * 
     * @param dropdown the dropdown menu
     * @param entry the entry to select
     */
    public static void dropdownSelect(WebElement dropdown, String entry) {
        new Select(dropdown).selectByVisibleText(entry);
    }

    /**
     * Clicks the 'Generate' button on the current page.
     */
    public static void clickGenerateButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Generate']")).click();
    }

    /**
     * Clicks the 'Download' button on the current page.
     */
    public static void clickDownloadButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Download']")).click();
    }

    /**
     * Clicks the 'Submit' button on the current page.
     */
    public static void clickSubmitButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[@value='Submit']")).click();
    }

    /**
     * Clicks the 'Add' (or 'Add...') button on the current page.
     */
    public static void clickAddButton() {
        WebTestBase.getWebDriver().findElement(By.xpath("//input[contains(@value, 'Add')]")).click();
    }

    /**
     * Clicks the 'Add' or 'Add...' link on the current page.
     */
    public static void clickAddLink() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[contains(text(), 'Add') and not(contains(text(), 'DssQa'))]")).click();
    }

    /**
     * Clicks the 'Cancel' link on the current page.
     */
    public static void clickCancelLink() {
        WebTestBase.getWebDriver().findElement(By.xpath("//a[text()='Cancel']")).click();
    }

    /**
     * Adds an active CryptoTokenP12 with its own copy of dss10_keystore.p12.
     * 
     * This means that its safe to e.g. create new keys without modifying the
     * original keystore. Remember to remove the worker after the test.
     * 
     * @return the name of the created worker
     */
    public static String addCryptoTokenP12() {
        String workerName = "CryptoTokenP12_" + WebTestBase.getUniqueId();
        String keystorePath = WebTestBase.getTestDir() + "/dss10_keystore.p12";

        // Copy dss10_keystore.p12 to the temporary directory
        WebTestHelper.copyFileTemporarily(WebTestBase.getSignServerDir() + "/res/test/dss10/dss10_keystore.p12", keystorePath);

        // Set up properties
        Map<String, String> properties = ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.KEYSTOREPATH", keystorePath,
                "WORKERGENID1.KEYSTOREPASSWORD", "foo123"
        );

        // Add the worker
        AllWorkersHelper.addFromTemplate("keystore-crypto.properties", properties);
        return workerName;
    }
    
    /**
     * Adds an active CryptoTokenP12 with its own copy of dss10_keystore.p12.
     *
     * This means that its safe to e.g. create new keys without modifying the
     * original keystore. Remember to remove the worker and keystore file after
     * the test.
     *
     * @param keyStoreFile
     * @return the name of the created worker
     */
    public static String addCryptoTokenP12WithKeyStoreFile(File keyStoreFile) {
        String workerName = "CryptoTokenP12_" + WebTestBase.getUniqueId();        

        // Copy dss10_keystore.p12 to the temporary directory
        File fromFile = new File(WebTestBase.getSignServerDir() + "/res/test/dss10/dss10_keystore.p12");
        WebTestHelper.copyFile(fromFile, keyStoreFile);

        // Set up properties
        Map<String, String> properties = ImmutableMap.of(
                "WORKERGENID1.NAME", workerName,
                "WORKERGENID1.KEYSTOREPATH", keyStoreFile.getAbsolutePath(),
                "WORKERGENID1.KEYSTOREPASSWORD", "foo123"
        );

        // Add the worker
        AllWorkersHelper.addFromTemplate("keystore-crypto.properties", properties);
        return workerName;
    }

    /**
     * Decompresses (unzip) given zipFile into given outputFolder.
     *
     * @param zipFile
     * @param outputFolder
     * @throws java.io.IOException
     */
    public static void unzipFile(String zipFile, String outputFolder) throws IOException {
        byte[] buffer = new byte[1024];

        //create output directory is not exists
        File folder = new File(outputFolder);
        if (!folder.exists()) {
            folder.mkdir();
        }

        //get the zipped file list entry
        try ( //get the zip file content
                ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            //get the zipped file list entry
            ZipEntry ze = zis.getNextEntry();

            while (ze != null) {

                String fileName = ze.getName();
                File newFile = new File(outputFolder + File.separator + fileName);

                LOG.info("file unzip : " + newFile.getAbsoluteFile());

                //create all non exists folders
                //else you will hit FileNotFoundException for compressed folder
                new File(newFile.getParent()).mkdirs();

                try (FileOutputStream fos = new FileOutputStream(newFile)) {
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        fos.write(buffer, 0, len);
                    }
                }
                ze = zis.getNextEntry();
            }

            zis.closeEntry();
        }

        LOG.info("Done");
    }
}
