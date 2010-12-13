/*
 * SCUBA smart card framework.
 *
 * Copyright (C) 2009  The SCUBA team.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * $Id: $
 */

package net.sourceforge.scuba.tlv;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import net.sourceforge.scuba.util.Hex;

/**
 * Generic data structure for storing Tag Length Value (TLV) objects encoded
 * according to the Basic Encoding Rules (BER). Written by Martijn Oostdijk (MO)
 * and Cees-Bart Breunesse (CB) of the Security of Systems group (SoS) of the
 * Institute of Computing and Information Sciences (ICIS) at Radboud University
 * (RU). Based on ISO 7816-4 Annex D (which apparently is based on ISO 8825
 * and/or X.208, X.209, X.680, X.690). See <a
 * href="http://en.wikipedia.org/wiki/ASN.1">ASN.1</a>.
 * 
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 * @author Cees-Bart Breunesse (ceesb@cs.ru.nl)
 * @version $Revision: 227 $
 */
public class BERTLVObject
{
	private static final SimpleDateFormat SDF = new SimpleDateFormat("yyMMddhhmmss'Z'");

	/** Universal tag class. */
	public static final int UNIVERSAL_CLASS = 0;
	/** Application tag class. */
	public static final int APPLICATION_CLASS = 1;
	/** Context specific tag class. */
	public static final int CONTEXT_SPECIFIC_CLASS = 2;
	/** Private tag class. */
	public static final int PRIVATE_CLASS = 3;

	/** Universal tag type. */
	public static final int BOOLEAN_TYPE_TAG = 0x01, INTEGER_TYPE_TAG = 0x02,
	BIT_STRING_TYPE_TAG = 0x03, OCTET_STRING_TYPE_TAG = 0x04,
	NULL_TYPE_TAG = 0x05, OBJECT_IDENTIFIER_TYPE_TAG = 0x06,
	OBJECT_DESCRIPTOR_TYPE_TAG = 0x07, EXTERNAL_TYPE_TAG = 0x08,
	REAL_TYPE_TAG = 0x09, ENUMERATED_TYPE_TAG = 0x0A,
	EMBEDDED_PDV_TYPE_TAG = 0x0B, UTF8_STRING_TYPE_TAG = 0x0C,
	SEQUENCE_TYPE_TAG = 0x10, SET_TYPE_TAG = 0x11,
	NUMERIC_STRING_TYPE_TAG = 0x12, PRINTABLE_STRING_TYPE_TAG = 0x13,
	T61_STRING_TYPE_TAG = 0x14, IA5_STRING_TYPE_TAG = 0x16,
	UTC_TIME_TYPE_TAG = 0x17, GENERALIZED_TIME_TYPE_TAG = 0x18,
	GRAPHIC_STRING_TYPE_TAG = 0x19, VISIBLE_STRING_TYPE_TAG = 0x1A,
	GENERAL_STRING_TYPE_TAG = 0x1B, UNIVERSAL_STRING_TYPE_TAG = 0x1C,
	BMP_STRING_TYPE_TAG = 0x1E;

	/** Tag. */
	private int tag;

	/** Length. */
	private int length;

	/** Value, is usually just a byte[]. */
	private Object value;

	/**
	 * Constructs a new TLV object with tag <code>tag</code> containing data
	 * <code>value</code>.
	 * 
	 * @param tag tag of TLV object
	 * @param value data of TLV object
	 * @throws IOException if something goes wrong.
	 */
	public BERTLVObject(int tag, Object value) {
		this(tag, value, true);
	}

	/**
	 * Constructs a new TLV object with tag <code>tag</code> containing data
	 * <code>value</code>.
	 * 
	 * @param tag tag of TLV object
	 * @param value data of TLV object
	 * @param interpretValue whether the embedded byte[] values should be
	 *                        interpreted/parsed. Some ASN1 streams don't like that :( 
	 * @throws IOException if something goes wrong.
	 */
	public BERTLVObject(int tag, Object value, boolean interpretValue) {
		try {
			this.tag = tag;
			this.value = value;
			if (value instanceof byte[]) {
				this.length = ((byte[])value).length;
			} else if (value instanceof BERTLVObject) {
				this.value = new BERTLVObject[1];
				((BERTLVObject[])this.value)[0] = (BERTLVObject)value;
			} else if (value instanceof BERTLVObject[]) {
				this.value = value;
			} else if (value instanceof Byte) {
				this.length = 1;
				this.value = new byte[1];
				((byte[])this.value)[0] = ((Byte)value).byteValue();
			} else if (value instanceof Integer) {
				this.value = new BERTLVObject[1];
				((BERTLVObject[])this.value)[0] = new BERTLVObject(INTEGER_TYPE_TAG, value);
			} else {
				throw new IllegalArgumentException("Cannot encode value of type: " + value.getClass());
			}
			if (value instanceof byte[] && interpretValue) {
				this.value = interpretValue(tag, (byte[])value);
			}
			// reconstructLength();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static BERTLVObject getInstance(
			InputStream in) throws IOException {
		BERTLVInputStream tlvIn = (in instanceof BERTLVInputStream) ? (BERTLVInputStream)in : new BERTLVInputStream(in);
		int tag = tlvIn.readTag();
		tlvIn.readLength();
		byte[] valueBytes = tlvIn.readValue();
		BERTLVObject result = new BERTLVObject(tag, valueBytes);
		return result;
	}

	private static Object interpretValue(int tag, byte[] valueBytes) {
		if (isPrimitive(tag)) {
			return interpretPrimitiveValue(tag, valueBytes);
		} else {
			/*
			 * Not primitive, the value itself consists of 0 or more BER-TLV
			 * objects.
			 */
			try {
				return interpretCompoundValue(tag, valueBytes);
			} catch (IOException ioe) {
				return new BERTLVObject[0];
			}
		}
	}

	/*
	 * Primitive, the value consists of 0 or more Simple-TLV objects, or
	 * just (application-dependent) bytes. If tag is not known (or
	 * universal) we assume the value is just bytes.
	 */
	private static Object interpretPrimitiveValue(int tag, byte[] valueBytes) {
		if (getTagClass(tag) == UNIVERSAL_CLASS)
			switch (tag) {
			case INTEGER_TYPE_TAG:
			case BIT_STRING_TYPE_TAG:
			case OCTET_STRING_TYPE_TAG:
			case NULL_TYPE_TAG:
			case OBJECT_IDENTIFIER_TYPE_TAG:
				return valueBytes;
			case UTF8_STRING_TYPE_TAG:
			case PRINTABLE_STRING_TYPE_TAG:
			case T61_STRING_TYPE_TAG:
			case IA5_STRING_TYPE_TAG:
			case VISIBLE_STRING_TYPE_TAG:
			case GENERAL_STRING_TYPE_TAG:
			case UNIVERSAL_STRING_TYPE_TAG:
			case BMP_STRING_TYPE_TAG:
				return new String(valueBytes);
			case UTC_TIME_TYPE_TAG:
				try { return SDF.parse(new String(valueBytes)); } catch (ParseException pe) { }
			}
		return valueBytes;
	}

	private static BERTLVObject[] interpretCompoundValue(int tag, byte[] valueBytes)
	throws IOException {
		Collection<BERTLVObject> subObjects = new ArrayList<BERTLVObject>();
		BERTLVInputStream in = new BERTLVInputStream(new ByteArrayInputStream(valueBytes));
		int length = valueBytes.length;
		try {
			while (length > 0) {
				BERTLVObject subObject = BERTLVObject.getInstance(in);
				length -= subObject.getLength();
				subObjects.add(subObject);
			}
		} catch (EOFException eofe) { }
		BERTLVObject[] result = new BERTLVObject[subObjects.size()];
		subObjects.toArray(result);
		return result;
	}

	private static int getTagClass(int tag) {
		int i = 3;
		for (; i >= 0; i--) {
			int mask = (0xFF << (8 * i));
			if ((tag & mask) != 0x00) { break; }
		}
		int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
		switch (msByte & 0xC0) {
		case 0x00: return UNIVERSAL_CLASS;
		case 0x40: return APPLICATION_CLASS;
		case 0x80: return CONTEXT_SPECIFIC_CLASS;
		case 0xC0:
		default: return PRIVATE_CLASS;
		}
	}

	/****************************************************************************
	 * Adds
	 * <code>object</object> as subobject of <code>this</code> TLV object when
	 * <code>this</code> is not a primitive object.
	 * 
	 * @param object to add as a subobject.
	 */
	public void addSubObject(BERTLVObject object) {
		Collection<BERTLVObject> subObjects = new ArrayList<BERTLVObject>();

		if (value == null) {
			value = new BERTLVObject[1];
		} else if (value instanceof BERTLVObject[]){
			subObjects.addAll(Arrays.asList((BERTLVObject[])value));
		} else if (value instanceof BERTLVObject){
			/* NOTE: Should never happen if indeed !isPrimitive... */
			subObjects.add((BERTLVObject)value);
			value = new BERTLVObject[2];
		} else {
			throw new IllegalStateException("Error: Unexpected value in BERTLVObject");
		}
		subObjects.add(object);
		value = subObjects.toArray((BERTLVObject[])value);
		reconstructLength();
	}

	public int getTag() {
		return tag;
	}

	/**
	 * Reconstructs the length of the encoded value.
	 */
	public void reconstructLength() {
		/* NOTE: needed after sub-objects have been added. */
		length = getValueAsBytes(tag, value).length;
	}

	public int getLength() {
		return length;
	}

	/**
	 * The encoded value.
	 * 
	 * @return the encoded value
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * This object, including tag and length, as byte array.
	 * 
	 * @return this object, including tag and length, as byte array
	 */
	public byte[] getEncoded() {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(getTagAsBytes(tag));
			out.write(getLengthAsBytes(getLength()));
			out.write(getValueAsBytes(tag, value));
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		return out.toByteArray();
	}

	/**
	 * Gets the first sub-object (including this object) whose tag equals
	 * <code>tag</code>.
	 * 
	 * @param tag the tag to search for
	 * @return the first
	 */
	public BERTLVObject getSubObject(int tag) {
		if (this.tag == tag) {
			return this;
		} else if (value instanceof BERTLVObject[]) {
			BERTLVObject[] children = (BERTLVObject[])value;
			for (int i = 0; i < children.length; i++) {
				BERTLVObject child = children[i];
				BERTLVObject candidate = child.getSubObject(tag);
				if (candidate != null) { return candidate; }
			}
		}
		return null;
	}

	/**
	 * Gets the first sub-object (including this object) following the tags in
	 * tagPath.
	 * 
	 * @param tagPath the path to follow
	 * @param offset in the tagPath
	 * @param length of the tagPath
	 * @return the first
	 */
	public BERTLVObject getSubObject(int[] tagPath, int offset, int length) {
		if (length == 0) {
			return this;
		} else {
			BERTLVObject child = getSubObject(tagPath[offset]);
			if (child != null) { return child.getSubObject(tagPath, offset + 1,
					length - 1); }
		}
		return null;
	}

	/****************************************************************************
	 * Returns the indexed child (starting from 0) or null otherwise.
	 * 
	 * @param index
	 * @return the object pointed to by index.
	 */
	public BERTLVObject getChildByIndex(int index) {

		if (value instanceof BERTLVObject[]) {
			BERTLVObject[] children = (BERTLVObject[])value;
			return children[index];
		}

		return null;
	}

	/**
	 * A textual (nested tree-like) representation of this object. Always ends in
	 * newline character, no need to add it yourself.
	 * 
	 * @return a textual representation of this object.
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return toString(0);
	}

	private String toString(int indent) {
		byte[] prefixBytes = new byte[indent];
		Arrays.fill(prefixBytes, (byte)' ');
		String prefix = new String(prefixBytes);
		StringBuffer result = new StringBuffer();
		result.append(prefix);
		result.append(tagToString());
		result.append(" ");
		result.append(Integer.toString(getLength()));
		result.append(" ");
		if (value instanceof byte[]) {
			byte[] valueData = (byte[])value;
			result.append("'0x");
			if (indent + 2 * valueData.length <= 60) {
				result.append(Hex.bytesToHexString(valueData));
			} else {
				result
				.append(Hex.bytesToHexString(valueData, 0, (50 - indent) / 2));
				result.append("...");
			}
			result.append("'\n");
		} else if (value instanceof BERTLVObject[]) {
			result.append("{\n");
			BERTLVObject[] subObjects = (BERTLVObject[])value;
			for (int i = 0; i < subObjects.length; i++) {
				result.append(subObjects[i].toString(indent + 3));
			}
			result.append(prefix);
			result.append("}\n");
	} else {
		result.append("\"");
		result.append(value != null ? value.toString() : "null");
		result.append("\"\n");
	}
		return result.toString();
	}

	private String tagToString() {
		if (getTagClass(tag) == UNIVERSAL_CLASS) {
			if (isPrimitive(tag)) {
				switch (tag & 0x1F) {
				case BOOLEAN_TYPE_TAG:
					return "BOOLEAN";
				case INTEGER_TYPE_TAG:
					return "INTEGER";
				case BIT_STRING_TYPE_TAG:
					return "BIT_STRING";
				case OCTET_STRING_TYPE_TAG:
					return "OCTET_STRING";
				case NULL_TYPE_TAG:
					return "NULL";
				case OBJECT_IDENTIFIER_TYPE_TAG:
					return "OBJECT_IDENTIFIER";
				case REAL_TYPE_TAG:
					return "REAL";
				case UTF8_STRING_TYPE_TAG:
					return "UTF_STRING";
				case PRINTABLE_STRING_TYPE_TAG:
					return "PRINTABLE_STRING";
				case T61_STRING_TYPE_TAG:
					return "T61_STRING";
				case IA5_STRING_TYPE_TAG:
					return "IA5_STRING";
				case VISIBLE_STRING_TYPE_TAG:
					return "VISIBLE_STRING";
				case GENERAL_STRING_TYPE_TAG:
					return "GENERAL_STRING";
				case UNIVERSAL_STRING_TYPE_TAG:
					return "UNIVERSAL_STRING";
				case BMP_STRING_TYPE_TAG:
					return "BMP_STRING";
				case UTC_TIME_TYPE_TAG:
					return "UTC_TIME";
				case GENERALIZED_TIME_TYPE_TAG:
					return "GENERAL_TIME";
				}
			} else {
				switch (tag & 0x1F) {
				case ENUMERATED_TYPE_TAG:
					return "ENUMERATED";
				case SEQUENCE_TYPE_TAG:
					return "SEQUENCE";
				case SET_TYPE_TAG:
					return "SET";
				}
			}
		}
		return "'0x" + Hex.intToHexString(tag) + "'";
	}
	
	private static boolean isPrimitive(int tag) {
		int i = 3;
		for (; i >= 0; i--) {
			int mask = (0xFF << (8 * i));
			if ((tag & mask) != 0x00) { break; }
		}
		int msByte = (((tag & (0xFF << (8 * i))) >> (8 * i)) & 0xFF);
		boolean result = ((msByte & 0x20) == 0x00);
		return result;
	}
	
	public static int getTagLength(int tag) {
		return getTagAsBytes(tag).length;
	}
	
	public static int getLengthLength(int length) {
		return getLengthAsBytes(length).length;
	}
	
	/**
	 * The tag bytes of this object.
	 * 
	 * @return the tag bytes of this object.
	 */
	public static byte[] getTagAsBytes(int tag) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int byteCount = (int)(Math.log(tag) / Math.log(256)) + 1;
		for (int i = 0; i < byteCount; i++) {
			int pos = 8 * (byteCount - i - 1);
			out.write((tag & (0xFF << pos)) >> pos);
		}
		byte[] tagBytes = out.toByteArray();
		switch (getTagClass(tag)) {
		case APPLICATION_CLASS:
			tagBytes[0] |= 0x40;
			break;
		case CONTEXT_SPECIFIC_CLASS:
			tagBytes[0] |= 0x80;
			break;
		case PRIVATE_CLASS:
			tagBytes[0] |= 0xC0;
			break;
		}
		if (!isPrimitive(tag)) {
			tagBytes[0] |= 0x20;
		}
		return tagBytes;
	}

	/**
	 * The length bytes of this object.
	 * 
	 * @return length of encoded value as bytes
	 */
	public static byte[] getLengthAsBytes(int length) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		if (length < 0x80) {
			/* short form */
			out.write(length);
		} else {
			int byteCount = log(length, 256);
			out.write(0x80 | byteCount);
			for (int i = 0; i < byteCount; i++) {
				int pos = 8 * (byteCount - i - 1);
				out.write((length & (0xFF << pos)) >> pos);
			}
		}
		return out.toByteArray();
	}
	
	private static int log(int n, int base) {
		int result = 0;
		while (n > 0) {
			n = n / base;
			result ++;
		}
		return result;
	}

	/**
	 * The value of this object as a byte array. Almost the same as getEncoded(),
	 * but this one skips the tag and length of <code>this</code> BERTLVObject.
	 * 
	 * @return the value of this object as a byte array
	 */
	private static byte[] getValueAsBytes(int tag, Object value) {
		if (value == null) {
			System.out.println("DEBUG: object has no value: tag == "
					+ Integer.toHexString(tag));
		}
		if (isPrimitive(tag)) {
			if (value instanceof byte[]) {
				return (byte[])value;
			} else if (value instanceof String) {
				return ((String)value).getBytes();
			} else if (value instanceof Date) {
				return SDF.format((Date)value).getBytes();
			} else if (value instanceof Integer) {
				int intValue = ((Integer)value).intValue();
				int byteCount = Integer.bitCount(intValue) / 8 + 1;
				byte[] result = new byte[byteCount];
				for (int i = 0; i < byteCount; i++) {
					int pos = 8 * (byteCount - i - 1);
					result[i] = (byte)((intValue & (0xFF << pos)) >> pos);
				}
				return result;
			} else if (value instanceof Byte) {
				byte[] result = new byte[1];
				result[0] = ((Byte)value).byteValue();
				return result;
			}
		}
		if (value instanceof BERTLVObject[]) {
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			BERTLVObject[] children = (BERTLVObject[])value;
			for (int i = 0; i < children.length; i++) {
				try {
					result.write(children[i].getEncoded());
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return result.toByteArray();
		}

		/* NOTE: Not primitive, and also not instance of BERTLVObject[]... */
		if (value instanceof byte[]) {
			System.err.println("DEBUG: WARNING: BERTLVobject with non-primitive tag "
					+ Hex.intToHexString(tag) + " has byte[] value");
			return (byte[])value;
		}
		throw new IllegalStateException("Cannot decode value of "
				+ value.getClass() + " (tag = " + Hex.intToHexString(tag) + ")");
	}
}
