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
    
    private static final String HTTP_MAX_UPLOAD_SIZE = "HTTP_MAX_UPLOAD_SIZE";
    private static final long DEFAULT_MAX_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB (100*1024*1024);
    private static final int DEFAULT_SIZE_THRESHOLD = 10240;
    
    private long maxUploadSize;
    private int sizeThreshold;
    private File repository;

    /**
     * Creates an instance of UploadConfig with the default configuration.
     */
    public UploadConfig() {
        this(DEFAULT_MAX_UPLOAD_SIZE, DEFAULT_SIZE_THRESHOLD, new File(System.getProperty("java.io.tmpdir")));
    }

    public UploadConfig(long maxUploadSize, int sizeThreshold, File repository) {
        this.maxUploadSize = maxUploadSize;
        this.sizeThreshold = sizeThreshold;
        this.repository = repository;
    }
    
    public static UploadConfig create(GlobalConfigurationSessionLocal globalSession) {
        final int sizeThreshold = 1024 * 1024; // TODO: Configurable
        final File repository = new File(System.getProperty("java.io.tmpdir")); // TODO new File("/home/user/tmp/signserver/");  // XXX: Fix this!
        final long maxUploadSize = getMaxUploadSize(globalSession);
        return new UploadConfig(maxUploadSize, sizeThreshold, repository);
    }
    
    private static long getMaxUploadSize(GlobalConfigurationSessionLocal globalSession) {
        final String confValue = globalSession.getGlobalConfiguration().getProperty(GlobalConfiguration.SCOPE_GLOBAL, HTTP_MAX_UPLOAD_SIZE);
        long result = DEFAULT_MAX_UPLOAD_SIZE;
        if (confValue != null) {
            try {
                result = Long.parseLong(confValue);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using " + HTTP_MAX_UPLOAD_SIZE + ": " + result);
                }
            } catch (NumberFormatException ex) {
                LOG.error("Incorrect value for global configuration property " + HTTP_MAX_UPLOAD_SIZE + ": " + ex.getLocalizedMessage());
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using default max upload size as no " + HTTP_MAX_UPLOAD_SIZE + " configured");
            }
        }
        return result;
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
