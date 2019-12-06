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
package org.signserver.client.cli.defaultimpl;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.LinkedList;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.CommandFailureException;

/**
 * Manager responsible for all the file transfer threads.
 * 
 * All accessible methods in this file handles concurrency and are thread-safe.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TransferManager {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TransferManager.class);

    /** Queue of files to process. */
    private final LinkedList<File> files = new LinkedList<>();
    
    /** The username (if password auth). */
    private final String username;
    
    /**
     * The current password to use.
     * Note: volatile as it could be read/written by multiple threads.
     */
    private volatile String password;
    
    /** Provider of the password console. */
    private final ConsolePasswordProvider passwordProvider;
    
    /** Output to ask for the password. */
    private final PrintStream out;
    
    /** If oneFirst mode is used at the moment. */
    private boolean oneFirst;
    
    /** If the first file is being served. */
    private boolean firstAlreadyServed;
    
    /** The first file being processed. */
    private File first;
    
    /** Number of password attempts. */
    private int retryCount;
    
    /** Flag if the processing is aborted. */
    private boolean aborted;
    
    /** Flag if any file has failed. */
    private boolean failed;
    
    /** Number of successful files. */
    private int success;

    /**
     * Constructs a new instance of TransferManager.
     * @param inFiles to work on.
     * @param username if password auth is used
     * @param password to try to use
     * @param passwordProvider for creating a console password reader if the password auth fails
     * @param out output stream to use when asking for correct password
     * @param oneFirst if the first attempt should be done from a single thread
     */
    public TransferManager(File[] inFiles, String username, String password, ConsolePasswordProvider passwordProvider, PrintStream out, boolean oneFirst) {
        files.addAll(Arrays.asList(inFiles));
        this.username = username;
        this.password = password;
        this.passwordProvider = passwordProvider;
        this.out = out;
        this.oneFirst = oneFirst;
    }

    /**
     * Called by a thread to get the next file to work on.
     * Returns null if there are no more files to work on or if the the process
     * was aborted.
     * This method might block until there is time to start work on the next
     * file. This can for instance happen with the "onefirst" option and if
     * an other thread has already started processing the first file.
     * @return The next file or null if no more work is available
     */
    public synchronized File nextFile() {
        // No more work to do if we should abort
        if (aborted) {
            return null;
        }
        if (oneFirst && firstAlreadyServed) { // If a other thread is already working on the first file
            while (oneFirst && !aborted) { // Wait until the oneFirst is done, or it got aborted
                try {
                    wait();
                } catch (InterruptedException ex) {
                    aborted = true;
                    LOG.error("Interrupted: " + ex.getLocalizedMessage());
                    Thread.currentThread().interrupt();
                }
            }
            if (aborted) { // Check if it got aborted while waiting
                return null;
            }
        } else if (oneFirst) { // Otherwise if we are the first
            firstAlreadyServed = true; // Signal that we are serving it
            first = files.isEmpty() ? null : files.remove(); // Get the file
            return first;
        }
        return files.isEmpty() ? null : files.remove(); // Else just return the next file
    }

    /**
     * Abort all worker threads.
     * No more files will be returned by a call to nextFile.
     */
    public synchronized void abort() {
        aborted = true;
        notifyAll();
    }

    /**
     * Check if the processing is aborted.
     * @return True if it is aborted
     */
    public synchronized boolean isAborted() {
        return aborted;
    }

    /**
     * Signal that there has been a failure processing a file.
     * If the first file failed in oneFirst mode all threads will be aborted.
     */
    public synchronized void registerFailure() {
        failed = true;
        if (oneFirst) {
            // If the first one did not succeed in onefirst mode we will abort
            abort();
        }
    }

    /**
     * Checks if there has been any failures registered.
     * @return True if there has been at least one failure
     */
    public synchronized boolean hasFailures() {
        return failed;
    }

    /**
     * Register that the processing of a file was successful.
     * If this was the first file in oneFirst mode then the remaining threads
     * can start working.
     */
    public synchronized void registerSuccess() {
        success++;
        if (oneFirst && firstAlreadyServed) {
            oneFirst = false;
            notifyAll();
        }
    }

    /**
     * @return True if there has been at least one successfully process filed.
     */
    private boolean hasSuccess() {
        return success > 0;
    }

    /**
     * Called by a thread if processing failed because of the password and the
     * user should be asked again for the correct one.
     * A call to this method will cause the mode to change to oneFirst so that
     * the user is only asked once for the password and the processing only
     * continues by any threads if the next request succeeded.
     * @param inFile The file that caused the password error and that should be
     * tried again
     */
    synchronized void tryAgainWithNewPassword(File inFile) {
        // Note more than one thread might be standing in line for this method
        if (aborted) {
            return;
        }
        // If the password has not worked before, ask for a new password unless we are already waiting for the oneFirst
        // Or if this is the next attempt for the same file that we just asked password for
        if ((!hasSuccess() && !oneFirst) || (oneFirst && inFile.equals(first))) {
            if (++retryCount > 3) {
                abort();
                return;
            } else {
                final ConsolePasswordReader passwordReader = passwordProvider.createConsolePasswordReader();
                out.print("Enter correct password for user '" + username + "': ");
                out.flush();
                try {
                    password = new String(passwordReader.readPassword());
                } catch (CommandFailureException e) {
                    LOG.error("Failed to obtain password from console: " + e.getLocalizedMessage());
                    abort();
                    return;
                }
                // We will now only accept one new request until it succeeds
                oneFirst = true;
                firstAlreadyServed = false;
            }
        }
        // Put back the file to be tested again
        files.addFirst(inFile);
        notifyAll();
    }

    /**
     * @return The current password
     */
    public String getPassword() {
        return password;
    }
    
}
