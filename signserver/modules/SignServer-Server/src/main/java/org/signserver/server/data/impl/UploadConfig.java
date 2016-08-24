/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.data.impl;

import java.io.File;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;


/**
 *
 * @author user
 */
public class UploadConfig {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(UploadConfig.class);
    
    public static final String HTTP_MAX_UPLOAD_SIZE = "HTTP_MAX_UPLOAD_SIZE";
    private static final long DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);

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

    public UploadConfig(long maxUploadSize, int sizeThreshold, File repository) {
        this.maxUploadSize = maxUploadSize;
        this.sizeThreshold = sizeThreshold;
        this.repository = repository;
    }
    
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
