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

package org.signserver.mailsigner.module.common;

import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.signserver.common.MailSignerStatus;
import org.signserver.common.ProcessableConfig;

/**
 * Class generating parameter data for email notifications. 
 * 
 * All parameters isn't always set, it depends on the input data.
 * 
 * The following parameters can be set
 * ${NL}                           = New Line in message
 * ${DATE} or ${current.DATE}      = The current date
 * ${HOSTNAME}                     = Name of host running the application 
 * 
 * ${WORKERID} : Worker Id
 * ${WORKERNAME} : Worker Name      
 *   
 * Variables used with  expiring certificates. 
 * ${cert.CERTSERIAL}      = The serial number of the certificate about to expire 
 * ${cert.EXPIREDATE}      = The date the certificate will expire
 * ${cert.CERTSUBJECTDN}   = The certificate subject dn
 * ${cert.CERTISSUERDN}    = The certificate issuer dn
 * 
 * 
 * @author Philip Vendil 2008 sep 30
 *
 */

public class NotificationParamGen {

  private HashMap<String,String> params = new HashMap<String,String>();	
  
  /** regexp pattern to match ${identifier} patterns */
  private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
  
  /**
   * Constructor that mainly should be used when notifying about expiring certificates.
   */
  public NotificationParamGen(MailSignerStatus status){
	  populate(status);
  }
	

  /**
   * Method used to retrieve the populated parameter hash map with the notification text.
   * @return
   */
  public HashMap<String,String> getParams(){
	  return params;
  }
  
  private void populate(MailSignerStatus status){
	  X509Certificate expiringCert = (X509Certificate) status.getSignerCertificate();
	  paramPut("NL", System.getProperty("line.separator"));
      String date = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date());
      paramPut("DATE", date);
      
      try {
        java.net.InetAddress localMachine = java.net.InetAddress.getLocalHost();
        paramPut("HOSTNAME", localMachine.getHostName());
      }
      catch (java.net.UnknownHostException uhe) {
      
      }
      
      paramPut("WORKERID", status.getWorkerId());
      
      if(status.getActiveSignerConfig().getProperty(ProcessableConfig.NAME) != null){
    	  paramPut("WORKERNAME", "" + status.getActiveSignerConfig().getProperty(ProcessableConfig.NAME));   	  
      }
                
	  if(expiringCert != null){
		  paramPut("cert.CERTSERIAL",expiringCert.getSerialNumber().toString(16));
		  String dateString = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(expiringCert.getNotAfter());
		  paramPut("cert.EXPIREDATE",dateString);
          paramPut("cert.CERTSUBJECTDN",expiringCert.getSubjectDN().toString());
          paramPut("cert.CERTISSUERDN",expiringCert.getIssuerDN().toString());          
	  }

	  
  }
  
  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  private void paramPut(String key, String value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value);
	  }
  }
  
  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  private void paramPut(String key, Integer value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value.toString());
	  }
  }
	
  // Help method used to populate a message 
  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public static String interpolate(HashMap<String,String> patterns, String input) {
      final Matcher m = PATTERN.matcher(input);
      final StringBuffer sb = new StringBuffer(input.length());
      while (m.find()) {
          // when the pattern is ${identifier}, group 0 is 'identifier'
          String key = m.group(1);
          String value = (String)patterns.get(key);
          // if the pattern does exists, replace it by its value
          // otherwise keep the pattern ( it is group(0) )
          if (value != null) {
              m.appendReplacement(sb, value);
          } else {
              // I'm doing this to avoid the backreference problem as there will be a $
              // if I replace directly with the group 0 (which is also a pattern)
              m.appendReplacement(sb, "");
              String unknown = m.group(0);
              sb.append(unknown);
          }
      }
      m.appendTail(sb);
      return sb.toString();
  }
  
}
