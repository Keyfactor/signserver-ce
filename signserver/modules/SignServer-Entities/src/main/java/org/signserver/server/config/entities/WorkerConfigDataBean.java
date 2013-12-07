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
package org.signserver.server.config.entities;

import java.io.Serializable;
import javax.persistence.*;

/**
 * Entity Bean storing each worker configuration.
 *
 * Notice: The old columns signerId and signerConfigData is still used
 * for the database columns but their name in the application have been
 * changed to workerId and workerConfig.
 * 
 * Information stored:
 * <pre>
 * signerId (PrimaryKey, int)
 * signerConfigData (WorkerConfig in xml-encoding, String)
 * </pre>
 *
 * @version $Id$
 */
@Entity
@Table(name = "signerconfigdata")
public class WorkerConfigDataBean implements Serializable {
    
    @Id
    private int signerId;
    
    @Lob
    @Column(length = 1048576)
    private String signerConfigData;

    /**
     * Unique Id of the signer
     *
     * @return signerId
     */
    public int getSignerId() {
        return signerId;
    }

    /**
     * Unique Id of the signer
     * Shouldn't be set after creation.
     */
    public void setSignerId(int signerId) {
        this.signerId = signerId;
    }

    /**
     * WorkerConfig in xmlencoded String format
     * Shouldn't be used outside of entity bean, use getSignerConfig instead
     *
     * @return  xmlencoded encoded WorkerConfig
     */
    public String getSignerConfigData() {
        return signerConfigData;
    }

    /**
     * WorkerConfig in  xmlencoded String format
     *
     * @param WorkerConfig xmlencoded encoded WorkerConfig
     * @ejb.persistence
     */
    public void setSignerConfigData(String signerConfigData) {
        this.signerConfigData = signerConfigData;
    }
}
