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
package org.signserver.server.archive.olddbarchiver.entities;

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import javax.ejb.EJBException;
import javax.persistence.*;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.signserver.common.ArchiveData;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;

/**
 * Entity Bean storing requests and responses of signer beans
 * Information stored:
 * <pre>
 * uniqueId                  : (PrimaryKey, String) (notNull)
 * time                     : long (notNull)
 * signerid                 : int
 * archiveid                : String
 * type                     : int
 * requestIssuerDN          : String (Null)
 * requestCertSerialnumber  : String (Null)
 * requestIP                : String (Null)
 * archiveData              : String
 * dataEncoding             : int
 * </pre>
 *
 * @version $Id$
 *
 */
@Entity
@Table(name = "ArchiveData")
@NamedQueries({
    @NamedQuery(name = "ArchiveDataBean.findByArchiveId", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.archiveid=?3"),
    @NamedQuery(name = "ArchiveDataBean.findAllByArchiveId", query = "SELECT a from ArchiveDataBean a WHERE a.signerid=?1 AND a.archiveid=?2"),
    @NamedQuery(name = "ArchiveDataBean.findByTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.time>=?3 AND a.time<=?4"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestCertificate", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4"),
    @NamedQuery(name = "ArchiveDataBean.findAllByRequestCertificate", query = "SELECT a from ArchiveDataBean a WHERE a.signerid=?1 AND a.requestIssuerDN=?2 AND a.requestCertSerialnumber=?3"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestCertificateAndTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1  AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4 AND a.time>=?5 AND a.time<=?6"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestIP", query = "SELECT  a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3"),
    @NamedQuery(name = "ArchiveDataBean.findAllByRequestIP", query = "SELECT  a from ArchiveDataBean a WHERE a.signerid=?1 AND a.requestIP=?2"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestIPAndTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3 AND a.time>=?4 AND a.time<=?5")
})
public class ArchiveDataBean implements Serializable {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ArchiveData.class);
    
    public static final int DATA_ENCODING_XML = 0;
    public static final int DATA_ENCODING_BASE64 = 1;

    @Id
    private String uniqueId;
    
    private long time;
    
    private int type;
    
    private int signerid;
    
    private String archiveid;
    
    private String requestIssuerDN;
    
    private String requestCertSerialnumber;
    
    private String requestIP;
    
    private Integer dataEncoding;
    
    @Lob
    @Column(length = 10485760)
    private String archiveData;

    /**
     * Unique Id of the archieved data
     * Is a compination of type, archiveId and signerId
     *
     * @return uniqueId
     */
    public String getUniqueId() {
        return uniqueId;
    }

    /**
     * Unique Id of the archieved data
     * Shouldn't be set after creation.
     *
     * @param uniqueId  (could be response serialnumber or requestId or other
     */
    public void setUniqueId(String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public long getTime() {
        return time;
    }

    public void setTime(long time) {
        this.time = time;
    }

    /**
     * type indicates if the archieve is of the type response or request
     * see ArchiveDataVO.TYPE_ constants for more information
     *
     * @return  the type (if the archive is of requests or responses
     */
    public int getType() {
        return type;
    }

    /**
     * type indicates if the archieve is of the type response or request
     * see TYPE constants for more information
     *
     */
    public void setType(int type) {
        this.type = type;
    }

    /**
     * @return which signer that generated the archived data.
     *
     */
    public int getSignerid() {
        return signerid;
    }

    /**
     * @param signerid which signer that generated the archived data.
     *
     */
    public void setSignerid(int signerid) {
        this.signerid = signerid;
    }

    /**
     * The unique ID of the archive, could be the response serial number.
     */
    public String getArchiveid() {
        return archiveid;
    }

    public Integer getDataEncoding() {
        return dataEncoding;
    }

    public void setDataEncoding(int dataEncoding) {
        this.dataEncoding = dataEncoding;
    }

    /**
     * The unique ID of the archive, could be the response serial number.
     */
    public void setArchiveid(String archiveid) {
        this.archiveid = archiveid;
    }

    public String getRequestIssuerDN() {
        return requestIssuerDN;
    }

    public void setRequestIssuerDN(String requestIssuerDN) {
        this.requestIssuerDN = requestIssuerDN;
    }

    public String getRequestCertSerialnumber() {
        return requestCertSerialnumber;
    }

    public void setRequestCertSerialnumber(String requestSerialnumber) {
        this.requestCertSerialnumber = requestSerialnumber;
    }

    public String getRequestIP() {
        return requestIP;
    }

    public void setRequestIP(String requestIP) {
        this.requestIP = requestIP;
    }

    /**
     * WorkerConfig in xmlencoded String format
     * Shouldn't be used outside of entity bean, use getSignerConfig instead
     *
     * @return  xmlencoded encoded WorkerConfig
     */
    public String getArchiveData() {
        return archiveData;
    }

    /**
     * @param archiveData the archive data
     */
    public void setArchiveData(String archiveData) {
        this.archiveData = archiveData;
    }

    //
    // Public business methods used to help us manage certificates
    //
    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to retreive archieve data
     * correctly.
     *
     * @return certificate request history object
     */
    public ArchiveData getArchiveDataObject() {
        final ArchiveData result;
        
        try {
            if (dataEncoding != null && dataEncoding == DATA_ENCODING_BASE64) {
                result = new ArchiveData(Base64.decode(getArchiveData().getBytes("UTF8")));
            } else {
                java.beans.XMLDecoder decoder;

                    decoder =
                            new java.beans.XMLDecoder(
                            new java.io.ByteArrayInputStream(getArchiveData().getBytes("UTF8")));
                HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
                decoder.close();

                HashMap<?, ?> data = new Base64GetHashMap(h);

                result = new ArchiveData();
                result.loadData(data);
            }
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }

        return result;
    }

    /**
     * Method that saves the archive data to database.
     */
    @SuppressWarnings("unchecked")
    void setArchiveDataObject(ArchiveData data) {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap) data.saveData());
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();

        try {
            setArchiveData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }
    }

    /**
     * Method used to get the ArchiveDataVO representation of the data row.
     */
    public ArchiveDataVO getArchiveDataVO() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("getArchiveDataVO: dataEncoding: " + getDataEncoding());
        }
        if (getDataEncoding() != null && getDataEncoding() == DATA_ENCODING_BASE64) {
            try {
                return new ArchiveDataVO(getType(), getSignerid(), getArchiveid(), new Date(getTime()),
                    getRequestIssuerDN(), getRequestCertSerialnumber(), getRequestIP(),
                    Base64.decode(getArchiveData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException(ex);
            }
        } else {
            return new ArchiveDataVO(getType(), getSignerid(), getArchiveid(), new Date(getTime()),
                getRequestIssuerDN(), getRequestCertSerialnumber(), getRequestIP(),
                getArchiveDataObject());
        }
    }
}
