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
package org.signserver.server.archive.olddbarchiver;

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.EJBException;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.signserver.common.ArchiveData;
import org.signserver.common.ArchiveDataVO;

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
 * </pre>
 *
 * @version $Id$
 *
 */
@Entity
@Table(name = "ArchiveData")
@NamedQueries({
    @NamedQuery(name = "ArchiveDataBean.findByArchiveId", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.archiveid=?3"),
    @NamedQuery(name = "ArchiveDataBean.findByTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.time>=?3 AND a.time<=?4"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestCertificate", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestCertificateAndTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1  AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4 AND a.time>=?5 AND a.time<=?6"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestIP", query = "SELECT  a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3"),
    @NamedQuery(name = "ArchiveDataBean.findByRequestIPAndTime", query = "SELECT a from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3 AND a.time>=?4 AND a.time<=?5")
})
public class ArchiveDataBean implements Serializable {

    @Id
    private String uniqueId;
    
    private long time;
    
    private int type;
    
    private int signerid;
    
    private String archiveid;
    
    private String requestIssuerDN;
    
    private String requestCertSerialnumber;
    
    private String requestIP;
    
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
     * WorkerConfig in  xmlencoded String format
     *
     * @param WorkerConfig xmlencoded encoded data
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

        java.beans.XMLDecoder decoder;
        try {
            decoder =
                    new java.beans.XMLDecoder(
                    new java.io.ByteArrayInputStream(getArchiveData().getBytes("UTF8")));
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);
        }
        HashMap<?, ?> h = (HashMap<?, ?>) decoder.readObject();
        decoder.close();

        HashMap<?, ?> data = new Base64GetHashMap(h);

        ArchiveData archiveData = new ArchiveData();
        archiveData.loadData(data);

        return archiveData;
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
        return new ArchiveDataVO(getType(), getSignerid(), getArchiveid(), new Date(getTime()),
                getRequestIssuerDN(), getRequestCertSerialnumber(), getRequestIP(),
                getArchiveDataObject());
    }
}
