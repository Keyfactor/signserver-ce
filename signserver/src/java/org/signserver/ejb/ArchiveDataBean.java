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
 

package org.signserver.ejb;

import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.ejbca.util.CertTools;
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
 * @version $Id: ArchiveDataBean.java,v 1.1 2007-02-27 16:18:19 herrvendil Exp $
 *
 * @ejb.bean description="Entity Bean storing requests and responses of signer beans"
 * display-name="ArchiveDataBean"
 * name="ArchiveData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="ArchiveDataBean"
 * 
 * @ejb.finder
 *   description="findByArchiveId"
 *   signature="org.signserver.ejb.ArchiveDataLocal findByArchiveId(int type, int signerid, java.lang.String archiveid)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.archiveid=?3"
 * 
 * @ejb.finder
 *   description="findByTime"
 *   signature="java.util.Collection findByTime(int type, int signerid, long starttime, long endtime)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.time>=?3 AND a.time<=?4"
 *   
 * @ejb.finder
 *   description="findByRequestCertificate"
 *   signature="java.util.Collection findByRequestCertificate(int type, int signerid, java.lang.String requestIssuerDN, java.lang.String requestCertSerialnumber)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4"
 *
 * @ejb.finder
 *   description="findByRequestCertificateAndTime"
 *   signature="java.util.Collection findByRequestCertificateAndTime(int type, int signerid, java.lang.String requestIssuerDN, java.lang.String requestCertSerialnumber, long starttime, long endtime)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1  AND a.signerid=?2 AND a.requestIssuerDN=?3 AND a.requestCertSerialnumber=?4 AND a.time>=?5 AND a.time<=?6"
 *
 *
 * @ejb.finder
 *   description="findByRequestIP"
 *   signature="java.util.Collection findByRequestIP(int type, int signerid, java.lang.String requestIP)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3"
 *
 *@ejb.finder
 *   description="findByRequestIPAndTime"
 *   signature="java.util.Collection findByRequestIPAndTime(int type, int signerid, java.lang.String requestIP, long starttime, long endtime)"
 *   query="SELECT OBJECT(a) from ArchiveDataBean a WHERE a.type=?1 AND a.signerid=?2 AND a.requestIP=?3 AND a.time>=?4 AND a.time<=?5"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.permission role-name="InternalUser"
 *
 *
 * @ejb.pk class="org.signserver.ejb.ArchiveDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.signserver.ejb.ArchiveDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.signserver.ejb.ArchiveDataLocal"
 *
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class ArchiveDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(ArchiveDataBean.class);

    
  
    /**
     * Unique Id of the archieved data
     * Is a compination of type, archiveId and signerId
     *
     * @return uniqueId
     * @ejb.persistence
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getUniqueId();

    /**
     * Unique Id of the archieved data
     * Shouldn't be set after creation.
     * 
     * @param uniqueId  (could be response serialnumber or requestId or other
     * @ejb.persistence
     */
    public abstract void setUniqueId(String uniqueId);
   
    /**
     * @ejb.persistence
     */
    public abstract long getTime();

    /**
     * @ejb.persistence
     */
    public abstract void setTime(long time);    
    
    /**
     * type indicates if the archieve is of the type response or request
     * see ArchiveDataVO.TYPE_ constants for more information
     *
     * @return  the type (if the archive is of requests or responses
     * @ejb.persistence 
     */
    public abstract int getType();

    /**
     * type indicates if the archieve is of the type response or request
     * see TYPE constants for more information
     *
     * @ejb.persistence
     */
    public abstract void setType(int type);

    /**
     * @return which signer that generated the archived data.
     *
     * @ejb.persistence
     */
    public abstract int getSignerid();
    
    /**
     * @param signerid which signer that generated the archived data.
     *
     * @ejb.persistence
     */
    public abstract void setSignerid(int signerid);
    
    /**
     * The unique ID of the archive, could be the response serialnumber
     * @ejb.persistence
     */
    public abstract String getArchiveid();

    /**
     * The unique ID of the archive, could be the response serialnumber
     * @ejb.persistence
     */
    public abstract void setArchiveid(String archiveid);   
    
    
    /**
     * @ejb.persistence
     */
    public abstract String getRequestIssuerDN();

    /**
     * @ejb.persistence
     */
    public abstract void setRequestIssuerDN(String requestIssuerDN);
    
    /**
     * @ejb.persistence
     */
    public abstract String getRequestCertSerialnumber();

    /**
     * @ejb.persistence
     */
    public abstract void setRequestCertSerialnumber(String requestSerialnumber);
    
    /**
     * @ejb.persistence
     */
    public abstract String getRequestIP();

    /**
     * @ejb.persistence
     */
    public abstract void setRequestIP(String requestIP);
    
    /**
     * WorkerConfig in xmlencoded String format
     * Shouldn't be used outside of entity bean, use getSignerConfig instead
     *
     * @return  xmlencoded encoded WorkerConfig
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getArchiveData();

    /**
     * WorkerConfig in  xmlencoded String format
     *
     * @param WorkerConfig xmlencoded encoded data
     * @ejb.persistence
     */
    public abstract void setArchiveData(String archiveData);
    

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
    	HashMap h  = (HashMap) decoder.readObject();
    	decoder.close();

        HashMap data = new Base64GetHashMap(h);
    		
    	ArchiveData archiveData = new ArchiveData(); 
    	archiveData.loadData(data);
    	
        return archiveData;
    }
    
    /**
     * Method that saves the archive data to database.
     */
    private void setArchiveDataObject(ArchiveData data){
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)data.saveData());
    	
    	java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    	
    	java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    	encoder.writeObject(a);
    	encoder.close();
    	
    	try {
    		if (log.isDebugEnabled()) {
    			log.debug("WorkerConfig data: \n" + baos.toString("UTF8"));
    		}
    		setArchiveData(baos.toString("UTF8"));
    	} catch (UnsupportedEncodingException e) {
    		throw new EJBException(e);
    	}
    	
    	
    }
    
    /**
     * Method used to get the ArchiveDataVO representation of the data row. 
     * @ejb.interface-method
     */
    public ArchiveDataVO getArchiveDataVO(){
    	return new ArchiveDataVO(getType(), getSignerid(), getArchiveid(), new Date(getTime()),
    			 getRequestIssuerDN(),getRequestCertSerialnumber(),getRequestIP(),
    			 getArchiveDataObject());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a signers configuration
     * 
     * @param signerId uniqe Id of the signer 
     *
     * @return primary key
     * @ejb.create-method
     */
    public ArchiveDataPK ejbCreate(int type, int signerId, String archiveid, X509Certificate clientCert,
    		                       String requestIP, ArchiveData archiveData)
        throws CreateException {
        String uniqueId =type+";"+signerId+";"+archiveid;
        log.debug("Creating archive data, uniqueId=" + uniqueId);
        this.setUniqueId(uniqueId);
        this.setType(type);
        this.setSignerid(signerId);
        this.setTime(new Date().getTime());
        this.setArchiveid(archiveid);
        if(clientCert!=null){        	
          this.setRequestIssuerDN(CertTools.getIssuerDN(clientCert));
          this.setRequestCertSerialnumber(clientCert.getSerialNumber().toString(16));
        }
        this.setRequestIP(requestIP);
        this.setArchiveDataObject(archiveData);
        return null;
    }

    /**
     * required method, does nothing
     */
    public void ejbPostCreate(int type, int signerId, String archiveid, X509Certificate clientCert,
            String requestIP, ArchiveData archiveData) {
        // Do nothing. Required.
    }



}
