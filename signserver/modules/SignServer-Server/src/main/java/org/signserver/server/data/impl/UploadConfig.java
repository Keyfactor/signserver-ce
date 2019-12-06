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
package org.signserver.server.data.impl;

import java.io.File;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;


/**
 * Configuration settings for file uploads (and storage of response data).
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UploadConfig {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(UploadConfig.class);
  
    /** Global configuration property for the maximum upload size. */
    public static final String HTTP_MAX_UPLOAD_SIZE = "HTTP_MAX_UPLOAD_SIZE";
    private static final long DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);

    /** Global configuration property for the file size threshold. */
    public static final String FILE_SIZE_THRESHOLD = "FILE_SIZE_THRESHOLD";
    private static final int DEFAULT_FILE_SIZE_THRESHOLD = 1 * 1024 * 1024; // 1 MB
    
    private long maxUploadSize;
    private int sizeThreshold;
    private File repository;

    /**
     * Creates an instance of UploadConfig with the default configuration.
     */
    public UploadConfig() {
        this(DEFAULT_MAX_UPLOAD_SIZE, DEFAULT_FILE_SIZE_THRESHOLD, new File(System.getProperty("java.io.tmpdir")));
    }

    /**
     * Creates an instance of UploadConfig with the provided configuration.
     * @param maxUploadSize
     * @param sizeThreshold
     * @param repository 
     */
    public UploadConfig(long maxUploadSize, int sizeThreshold, File repository) {
        this.maxUploadSize = maxUploadSize;
        this.sizeThreshold = sizeThreshold;
        this.repository = repository;
    }
    
    /**
     * Creates an UploadConfig instance by querying the global configuration.
     * @param globalSession to query for configuration
     * @return the instance
     */
    public static UploadConfig create(GlobalConfigurationSessionLocal globalSession) {
        final File repository = new File(System.getProperty("java.io.tmpdir"));
        
        final GlobalConfiguration globalConfiguration = globalSession.getGlobalConfiguration();
        
        // Max upload size
        String confValue = globalConfiguration.getProperty(GlobalConfiguration.SCOPE_GLOBAL, HTTP_MAX_UPLOAD_SIZE);
        long maxUploadSize = DEFAULT_MAX_UPLOAD_SIZE;
        if (confValue != null) {
            try {
                maxUploadSize = Long.parseLong(confValue);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using " + HTTP_MAX_UPLOAD_SIZE + ": " + maxUploadSize);
                }
            } catch (NumberFormatException ex) {
                LOG.error("Incorrect value for global configuration property " + HTTP_MAX_UPLOAD_SIZE + ": " + ex.getLocalizedMessage());
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default max upload size as no " + HTTP_MAX_UPLOAD_SIZE + " configured");
            }
        }

        // Max upload size
        confValue = globalConfiguration.getProperty(GlobalConfiguration.SCOPE_GLOBAL, FILE_SIZE_THRESHOLD);
        int sizeThreshold = DEFAULT_FILE_SIZE_THRESHOLD;
        if (confValue != null) {
            try {
                sizeThreshold = Integer.parseInt(confValue);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using " + FILE_SIZE_THRESHOLD + ": " + sizeThreshold);
                }
            } catch (NumberFormatException ex) {
                LOG.error("Incorrect value for global configuration property " + FILE_SIZE_THRESHOLD + ": " + ex.getLocalizedMessage());
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default file size threshold as no " + FILE_SIZE_THRESHOLD + " configured");
            }
        }

        return new UploadConfig(maxUploadSize, sizeThreshold, repository);
    }

    public long getMaxUploadSize() {
        return maxUploadSize;
    }

    public void setMaxUploadSize(long maxUploadSize) {
        this.maxUploadSize = maxUploadSize;
    }

    public int getSizeThreshold() {
        return sizeThreshold;
    }

    public void setSizeThreshold(int sizeThreshold) {
        this.sizeThreshold = sizeThreshold;
    }

    public File getRepository() {
        return repository;
    }

    public void setRepository(File repository) {
        this.repository = repository;
    }

}
