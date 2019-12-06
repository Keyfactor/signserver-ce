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
package org.signserver.admin.web;

import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerType;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Worker {

    private final int id;
    private final boolean existing;
    private final String name;
    private final Properties config;
    private String error;
    private String success;
    private String status;
    private boolean cryptoWorker;
    private boolean hasCrypto;

    public Worker(int id, boolean existing, String name, Properties config) {
        this.id = id;
        this.existing = existing;
        this.name = name;
        this.config = config;
        this.cryptoWorker = WorkerType.CRYPTO_WORKER.name().equals(config.get(WorkerConfig.TYPE));
        this.hasCrypto = config.containsKey(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS);
    }

    public int getId() {
        return id;
    }

    public boolean isExisting() {
        return existing;
    }

    public String getName() {
        return name;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = StringUtils.trim(error);
    }

    public String getSuccess() {
        return success;
    }

    public void setSuccess(String success) {
        this.success = StringUtils.trim(success);
    }

    public Properties getConfig() {
        return config;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public boolean isCryptoWorker() {
        return cryptoWorker;
    }

    public void setCryptoWorker(boolean cryptoWorker) {
        this.cryptoWorker = cryptoWorker;
    }

    public boolean isHasCrypto() {
        return hasCrypto;
    }

    public void setHasCrypto(boolean hasCrypto) {
        this.hasCrypto = hasCrypto;
    }

    public String getImageName() {
        final String result;
        if (cryptoWorker) {
            result = "cryptoworker-small.png";
        } else if (hasCrypto) {
            result = "workerwithcrypto-small.png";
        } else {
            result = "worker-small.png";
        }
        return result;
    }

    public String getImageAlt() {
        final String result;
        if (cryptoWorker) {
            result = "Crypto Worker";
        } else if (hasCrypto) {
            result = "Worker with Crypto Token";
        } else {
            result = "Worker";
        }
        return result;
    }

    @Override
    public String toString() {
        return "Worker{" + id + ", " + name + "}";
    }

}
