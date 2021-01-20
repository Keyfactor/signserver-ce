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
package org.signserver.clientws;

import java.util.Set;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.log4j.Logger;
import org.w3c.dom.Node;

public class QoSHandler implements SOAPHandler<SOAPMessageContext> {

    // Logger for this class
    private static final Logger LOG = Logger.getLogger(QoSHandler.class);

    @Override
    public Set<QName> getHeaders() {
        return null;
    }

    @Override
    public boolean handleMessage(final SOAPMessageContext messageContext) {
        final Boolean outboundProperty = (Boolean) messageContext.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        // Only incoming
        if(!outboundProperty) {
            /*
             * An example:
             * <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
             *   <soap:Header/>
             *   <soap:Body>
             *     <ns2:processData xmlns:ns2="http://clientws.signserver.org/">
             *       <worker>1000</worker>
             *       <data>PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48cm9vdC8+</data>
             *     </ns2:processData>
             *   </soap:Body>
             * </soap:Envelope>
             */
            final SOAPMessage soapMessage = messageContext.getMessage();
            try {
                final SOAPBody soapBody = soapMessage.getSOAPBody();
                final Node operationNode = soapBody.getFirstChild();
                final String operationNodeName = operationNode.getNodeName();
                if(operationNodeName.endsWith(":processData")) {
                    Node currentNode = operationNode.getFirstChild();
                    String currentNodeName = currentNode.getNodeName();
                    String workerId = null;
                    while (currentNode.hasChildNodes()) {
                        if (currentNodeName.equals("worker")) {
                            workerId = currentNode.getFirstChild().getTextContent();
                            break;
                        }
                        // Next
                        currentNode = operationNode.getFirstChild();
                        currentNodeName = currentNode.getNodeName();
                    }
                    // Get permission to process from QoSFilter
                    final Client client = ClientBuilder.newClient();
                    client.target("http://localhost:8080/signserver/soap-queue")
                            .queryParam("wid", workerId)
                            .request(MediaType.TEXT_HTML)
                            .get(String.class);
                    return true;
                }
            } catch (SOAPException ex) {
                LOG.error("Got error processing SOAP Message", ex);
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean handleFault(final SOAPMessageContext messageContext) {
        return false;
    }

    @Override
    public void close(final MessageContext messageContext) {
    }
}
