/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.signserver.ejbca.peerconnector.util.ByteArrayUtils;

/**
 * Base message format.
 * 
 *  4 bytes     base version = 0, BigEndian encoding (for future use if we want to add some checksum or additional message protection)
 *  4 bytes     X = name length, BigEndian encoding
 *  X bytes     name, UTF-8 encoded string limited to AZaz0-9_
 *  4 bytes     sourceId, BigEndian encoding (generated att app server startup and kept during the runtime)
 *  8 bytes     messageId, BigEndian encoding (atomic incremented for each message sent from app server)
 *  4 bytes     specific message version (to be used by inheriting classes), BigEndian encoding
 *  4 bytes     Y = non-critical header extension length, BigEndian encoding
 *  Y bytes     non-critical header extension (for future use)
 *  4 bytes     Z = data length, BigEndian encoding
 *  Z bytes     data
 * 
 * @version $Id$
 */
public class PeerMessage implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final AtomicLong messageIdCounter = new AtomicLong(0);
    private static final Logger log = Logger.getLogger(PeerMessage.class);
    protected static final int BASE_MESSAGE_VERSION = 0;

    private final int baseMessageVersion;
    private final byte[] messageTypeBytes;
    private final String messageType;
    private int sourceId;
    private final long messageId;
    private final int specificMessageVersion;
    private byte[] data;
    
    // Transient meta information for incoming messages
    private transient AuthenticationToken authenticationToken = null;
    private transient ByteArrayOutputStream outgoingDataBaos = null;
    private transient ByteBuffer incomingDataByteBuffer = null;

    /** Constructor used when parsing incoming peer messages. */
    protected PeerMessage(final String peerMessageType, final PeerMessage peerMessage) {
        if (!peerMessageType.equals(peerMessage.messageType)) {
            throw new IllegalStateException("Unable to create a message of type " + peerMessageType + " from message of type " + peerMessage.messageType + ".");
        }
        this.messageTypeBytes = peerMessage.messageTypeBytes;
        this.messageType = peerMessage.messageType;
        this.sourceId = peerMessage.sourceId;
        this.messageId = peerMessage.messageId;
        this.baseMessageVersion = peerMessage.baseMessageVersion;
        this.data = peerMessage.data;
        this.authenticationToken = peerMessage.authenticationToken;
        this.specificMessageVersion = peerMessage.specificMessageVersion;
        if (data!=null) {
            incomingDataByteBuffer = ByteBuffer.wrap(data);
        }
    }

    /** Constructor for simple messages or derived classes */
    public PeerMessage(final String messageType) {
        this(messageType, 0);
    }

    /** Constructor for derived classes that can handle versioning */
    protected PeerMessage(final String messageType, final int specificMessageVersion) {
        messageTypeBytes = messageType.getBytes();
        if (messageType == null || !new String(messageTypeBytes, StandardCharsets.UTF_8).equals(messageType)) {
            throw new InvalidParameterException("messageType must be UTF-8 encoded and never null.");
        }
        this.messageType = messageType;
        this.sourceId = 0;  // Set when sent
        this.messageId = messageIdCounter.incrementAndGet();
        this.baseMessageVersion = BASE_MESSAGE_VERSION;
        this.specificMessageVersion = specificMessageVersion; 
        this.data = null;
    }
    
    /**
     * Construct a message from the raw byte array.
     * 
     * @param rawMessage bytes received from peer
     * @param authenticationToken the peer's credentials if this is a request or null if this is a response.
     */
    public PeerMessage(final byte[] rawMessage, final AuthenticationToken authenticationToken) {
        final ByteBuffer bb = ByteBuffer.wrap(rawMessage);
        baseMessageVersion = bb.getInt();
        if (baseMessageVersion>BASE_MESSAGE_VERSION) {
            // Allow non critical information to be added to the message format, but warn
            log.info("Received a newer version of the message than this instance can handle in full. Some data might not be parsed correctly."
                    +" This version " + BASE_MESSAGE_VERSION + ", peer version " + baseMessageVersion);
        }
        final int messageTypeBytesLength = bb.getInt();
        if (messageTypeBytesLength<1 || messageTypeBytesLength>250) {
            throw new InvalidParameterException("Unknown or invalid message format. MessageType was " + messageTypeBytesLength + " bytes.");
        }
        messageTypeBytes = new byte[messageTypeBytesLength];
        bb.get(messageTypeBytes);
        try {
            messageType = new String(messageTypeBytes, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);  // Fatal
        }
        sourceId = bb.getInt();
        messageId = bb.getLong();
        specificMessageVersion = bb.getInt(); 
        final int headerExtensionLength = bb.getInt();
        if (headerExtensionLength>0) {
            log.info("Unknown header extension of " + headerExtensionLength + " bytes ignored.");
            final byte[] headerExtension = new byte[ByteArrayUtils.assertReasonableAllocationSizeBytes(headerExtensionLength)];
            bb.get(headerExtension);
        }
        final int dataLength = bb.getInt();
        if (bb.remaining()!=dataLength) {
            throw new InvalidParameterException("Unknown or invalid message format. Insufficient data of " + bb.remaining() + " bytes remaining in buffer when " + dataLength + " requested.");
        }
        if (dataLength>0) {
            data = new byte[ByteArrayUtils.assertReasonableAllocationSizeBytes(dataLength)];
            bb.get(data);
        } else {
            data = null;
        }
        this.authenticationToken = authenticationToken;
    }

    /** @return the message as a raw array of bytes to send. */
    public byte[] getAsByteArray() {
        this.sourceId = getLocalSourceId();
        final int baseMessageVersion = this.baseMessageVersion;
        final int messageTypeBytesLength = messageTypeBytes.length;
        final byte[] messageTypeBytes = this.messageTypeBytes;
        final int initatorId = this.sourceId;
        final long messageId = this.messageId;
        appendFinished();
        final byte[] data = this.data;
        final int dataLength = data.length;
        final ByteBuffer bb = ByteBuffer.allocate(4+4+messageTypeBytesLength+4+8+4+4+0+4+dataLength);
        bb.putInt(baseMessageVersion);
        bb.putInt(messageTypeBytesLength);
        bb.put(messageTypeBytes);
        bb.putInt(initatorId);
        bb.putLong(messageId);
        bb.putInt(specificMessageVersion);
        bb.putInt(0);   // Currently no header extension
        bb.putInt(dataLength);
        bb.put(data);
        return bb.array();
    }

    /** Called when no more data will be appended. Must be called so peer message can be serialized and sent over remote EJB interfaces. */
    protected void appendFinished() {
        if (this.data==null) {
            data = getByteArrayOutputStream().toByteArray();
        }
    }

    public String getMessageType() {
        return messageType;
    }

    @Override
    public String toString() {
        return messageType + " data: "+(data==null?"0":data.length)+" byte(s).";
    }

    public int getSourceId() { return sourceId; }

    /** @return the authenticationToken that sent this message (incoming only) */
    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    /** @return a unique source identifier within the cluster this instance is running. */
    public static int getLocalSourceId() {
        return Math.abs(CesecoreConfiguration.getNodeIdentifier().hashCode());
    }

    /** @return the message version for the specific type that inherited this class */
    protected int getSpecificMessageVersion() { return specificMessageVersion; }

    //
    // Helper functions for nicer conversion of the data between bytes and object
    //
    
    private ByteArrayOutputStream getByteArrayOutputStream() {
        if (outgoingDataBaos==null) {
            outgoingDataBaos = new ByteArrayOutputStream();
        }
        return outgoingDataBaos;
    }

    private void appendRawByteArray(final byte[] value) {
        try {
            getByteArrayOutputStream().write(value);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    protected int appendPrimitiveInt(final int value) {
        appendRawByteArray(ByteArrayUtils.getIntAsBytes(value));
        return value;
    }
    protected int nextPrimitiveInt() {
        return incomingDataByteBuffer.getInt();
    }

    protected long appendPrimitiveLong(final long value) {
        appendRawByteArray(ByteArrayUtils.getLongAsBytes(value));
        return value;
    }
    protected long nextPrimitiveLong() {
        return incomingDataByteBuffer.getLong();
    }

    protected boolean appendPrimitiveBoolean(final boolean value) {
        appendRawByteArray(ByteArrayUtils.getBooleanAsByte(value));
        return value;
    }
    protected boolean nextPrimitiveBoolean() {
        return ByteArrayUtils.getNextBoolean(incomingDataByteBuffer);
    }

    protected byte[] appendPrimitiveByteArray(final byte[] value) {
        appendRawByteArray(ByteArrayUtils.getByteArrayObjectAsBytes(value));
        return value;
    }
    protected byte[] nextPrimitiveByteArray() {
        return ByteArrayUtils.getNextByteArrayObject(incomingDataByteBuffer);
    }

    protected Integer appendObjectInteger(final Integer value) {
        appendRawByteArray(ByteArrayUtils.getIntegerObjectAsBytes(value));
        return value;
    }
    protected Integer nextObjectInteger() {
        return ByteArrayUtils.getNextIntegerObject(incomingDataByteBuffer);
    }

    protected Long appendObjectLong(final Long value) {
        appendRawByteArray(ByteArrayUtils.getLongObjectAsBytes(value));
        return value;
    }
    protected Long nextObjectLong() {
        return ByteArrayUtils.getNextLongObject(incomingDataByteBuffer);
    }

    protected String appendObjectStringUtf8(final String value) {
        appendRawByteArray(ByteArrayUtils.getUtf8StringObjectAsBytes(value));
        return value;
    }
    protected String nextObjectStringUtf8() {
        return ByteArrayUtils.getNextUtf8StringObject(incomingDataByteBuffer);
    }

    protected List<String> appendObjectUtf8StringList(final List<String> value) {
        appendRawByteArray(ByteArrayUtils.getUtf8StringListAsBytes(value));
        return value;
    }
    protected List<String> nextObjectUtf8StringList() {
        return ByteArrayUtils.getNextUtf8StringList(incomingDataByteBuffer);
    }
}
