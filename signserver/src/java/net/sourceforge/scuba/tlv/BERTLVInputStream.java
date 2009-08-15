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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Stack;

/**
 * TLV input stream.
 * 
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 */
public class BERTLVInputStream extends InputStream
{
	/** Carrier. */
	private DataInputStream in;

	private State state;
	private State markedState;

	/**
	 * Constructs a new TLV stream based on another stream.
	 * 
	 * @param in a TLV object
	 */
	public BERTLVInputStream(InputStream in) {
		this.in = new DataInputStream(in);
		state = new State();
		markedState = null;
	}

	/**
	 * Reads a tag.
	 *
	 * @return the tag just read
	 *
	 * @throws IOException if reading goes wrong
	 */
	public int readTag() throws IOException {
		int tag = -1;
		int bytesRead = 0;
		try {
			int b = in.readUnsignedByte(); bytesRead++;
			while (b == 0x00 || b == 0xFF) {
				b = in.readUnsignedByte(); bytesRead++; /* skip 00 and FF */
			}
			switch (b & 0x1F) {
			case 0x1F:
				tag = b; /* We store the first byte including LHS nibble */
				b = in.readUnsignedByte(); bytesRead++;
				while ((b & 0x80) == 0x80) {
					tag <<= 8;
					tag |= (b & 0x7F);
					b = in.readUnsignedByte(); bytesRead++;
				}
				tag <<= 8;
				tag |= (b & 0x7F);
				/*
				 * Byte with MSB set is last byte of
				 * tag...
				 */
				break;
			default:
				tag = b;
			break;
			}
			state.setTagRead(tag, bytesRead);
			return tag;
		} catch (IOException e) {
			throw e;
		}
	}

	/**
	 * Reads a length.
	 *
	 * @return the length just read
	 *
	 * @throws IOException if reading goes wrong
	 */
	public int readLength() throws IOException {
		try {
			if (!state.isAtStartOfLength()) { throw new IllegalStateException("Not at start of length"); }
			int bytesRead = 0;
			int length = 0;
			int b = in.readUnsignedByte(); bytesRead++;
			if ((b & 0x80) == 0x00) {
				/* short form */
				length = b;
			} else {
				/* long form */
				int count = b & 0x7F;
				length = 0;
				for (int i = 0; i < count; i++) {
					b = in.readUnsignedByte(); bytesRead++;
					length <<= 8;
					length |= b;
				}
			}
			state.setLengthRead(length, bytesRead);
			return length;
		} catch (IOException e) {
			throw e;
		}
	}

	/**
	 * Reads a value.
	 *
	 * @return the value just read
	 *
	 * @throws IOException if reading goes wrong
	 */
	public byte[] readValue() throws IOException {
		try {
			int length = state.getLength();
			byte[] value = new byte[length];
			in.readFully(value);
			state.updateValueBytesRead(length);
			return value;
		} catch (IOException e) {
			throw e;
		}
	}

	private long skipValue() throws IOException {
		if (state.isAtStartOfTag()) { return 0; }
		if (state.isAtStartOfLength()) { return 0; }
		int bytesLeft = state.getValueBytesLeft();
		return skip(bytesLeft);
	}

	/**
	 * Skips in this stream until a given tag is found (depth first).
	 * The stream is positioned right after the first occurrence of the tag.
	 * 
	 * @param searchTag the tag to search for
	 *
	 * @throws IOException
	 */
	public void skipToTag(int searchTag) throws IOException {
		while (true) {
			/* Get the next tag. */
			int tag = -1;
			if (state.isAtStartOfTag()) {
				/* Nothing. */
			} else if (state.isAtStartOfLength()) {
				readLength();
				if (isPrimitive(state.getTag())) { skipValue(); }
			} else {
				if (isPrimitive(state.getTag())) { skipValue(); }

			}
			tag = readTag();
			if  (tag == searchTag) { return; }

			if (isPrimitive(tag)) {
				int length = readLength();
				int skippedBytes = (int)skipValue();
				if (skippedBytes >= length) {
					/* Now at next tag. */
					continue;
				} else {
					/* Could only skip less than length bytes,
					 * we're lost, probably at EOF. */
					break;
				}
			}
		}
	}

	/**
	 * Returns an estimate of the number of bytes that can be read (or 
	 * skipped over) from this input stream without blocking by the next
	 * invocation of a method for this input stream.
	 * 
	 * @return a number of bytes
	 * 
	 * @throws IOException if something goes wrong
	 */
	public int available() throws IOException {
		return in.available();
	}

	/**
	 * Reads the next byte of data from the input stream.
	 * 
	 * @return a byte
	 * 
	 * @throws IOException if reading goes wrong
	 */
	public int read() throws IOException {
		int result = in.read();
		if (result < 0) { return -1; }
		state.updateValueBytesRead(1);
		return result;
	}

	/**
	 * Attempts to skip over <code>n</code> bytes.
	 * 
	 * @return the actual number of bytes skipped
	 * 
	 * @throws IOException if something goes wrong
	 */
	public long skip(long n) throws IOException {
		if (n <= 0) { return 0; }
		long result = in.skip(n);
		state.updateValueBytesRead((int)result);
		return result;
	}

	/**
	 * Marks the underlying input stream if supported.
	 * 
	 * @param readLimit limit for marking
	 */
	public synchronized void mark(int readLimit) {
		in.mark(readLimit);
		markedState = (State)state.clone();
	}

	/**
	 * Whether marking and resetting are supported.
	 * We support this whenever the underlying input stream supports it.
	 * 
	 * @return whether mark and reset are supported
	 */
	public boolean markSupported() {
		return in.markSupported();
	}

	/**
	 * Resets the underlying input stream if supported.
	 * 
	 * @throws IOException if something goes wrong
	 */
	public synchronized void reset() throws IOException {
		if (!markSupported()) {
			throw new IOException("mark/reset not supported");
		}
		in.reset();
		state = markedState;
		markedState = null;
	}

	/**
	 * Closes this input stream.
	 * 
	 * @throws IOException if something goes wrong
	 */
	public void close() throws IOException {
		in.close();
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

	/**
	 * State keeps track of where we are in the TLV stream.
	 */
	private class State implements Cloneable
	{
		/** Which tags have we seen thus far? */
		private Stack<TLStruct> state;
		
		/** FIXME: These are probably redundant... */
		private boolean isAtStartOfTag, isAtStartOfLength, isReadingValue;

		/*
		 * TFF: ^TLVVVVVV
		 * FTF: T^LVVVVVV
		 * FFT: TL^VVVVVV
		 * FFT: TLVVVV^VV
		 * TFF: ^
		 */
		
		public State() {
			state = new Stack<TLStruct>();
			isAtStartOfTag = true;
			isAtStartOfLength = false;
			isReadingValue = false;
		}
		
		private State(Stack<TLStruct> state, boolean isAtStartOfTag, boolean isAtStartOfLength, boolean isReadingValue) {
			this.state = state;
			this.isAtStartOfTag = isAtStartOfTag;
			this.isAtStartOfLength = isAtStartOfLength;
			this.isReadingValue = isReadingValue;
		}

		public boolean isAtStartOfTag() {
			return isAtStartOfTag;
		}

		public boolean isAtStartOfLength() {
			return isAtStartOfLength;
		}
		
		public boolean isReadingValue() {
			return isReadingValue;
		}

		public int getTag() {
			if (state.isEmpty()) {
				throw new IllegalStateException("Tag not yet read.");
			}
			TLStruct currentObject = state.peek();
			return currentObject.getTag();
		}

		public int getLength() {
			if (state.isEmpty()) {
				throw new IllegalStateException("Length not yet read.");
			}
			TLStruct currentObject = state.peek();
			int length = currentObject.getLength();
			if (length < 0) {
				throw new IllegalStateException("Length not yet read.");
			}
			return length;
		}

		public int getValueBytesLeft() {
			if (state.isEmpty()) {
				throw new IllegalStateException("Not yet reading value.");
			}
			TLStruct currentObject = state.peek();
			int currentLength = currentObject.getLength();
			if (currentLength < 0) {
				throw new IllegalStateException("Not yet reading value.");
			}
			int currentBytesRead = currentObject.getValueBytesRead();
			return currentLength - currentBytesRead;
		}

		public void setTagRead(int tag, int bytesRead) {
			/* Length is set to -1, we will update it when we encounter it */
			TLStruct obj = new TLStruct(tag, -1, 0);
			if (!state.isEmpty()) {
				TLStruct parent = state.peek();
				parent.updateValueBytesRead(bytesRead);
			}
			state.push(obj);
			isAtStartOfTag = false;
			isAtStartOfLength = true;
			isReadingValue = false;
		}

		public void setLengthRead(int length, int bytesRead) {
			if (length < 0) {
				throw new IllegalArgumentException("Cannot set negative length (length = " + length + ").");
			}
			TLStruct obj = state.pop();
			if (!state.isEmpty()) {
				TLStruct parent = state.peek();
				parent.updateValueBytesRead(bytesRead);
			}
			obj.setLength(length);
			state.push(obj);
			isAtStartOfTag = false;
			isAtStartOfLength = false;
			isReadingValue = true;
		}

		public void updateValueBytesRead(int n) {
			if (state.isEmpty()) { return; }
			TLStruct currentObject = state.peek();
			int bytesLeft = currentObject.getLength() - currentObject.getValueBytesRead();
			if (n > bytesLeft) {
				throw new IllegalArgumentException("Cannot read " + n + " bytes! Only " + bytesLeft + " bytes left in this TLV object " + currentObject);
			}
			currentObject.updateValueBytesRead(n);
			int currentLength = currentObject.getLength();
			if (currentObject.getValueBytesRead() == currentLength) {
				state.pop();
				/* Stand back! I'm going to try recursion! Update parent(s)... */
				updateValueBytesRead(currentLength);
				isAtStartOfTag = true;
				isAtStartOfLength = false;
				isReadingValue = false;
			} else {
				isAtStartOfTag = false;
				isAtStartOfLength = false;
				isReadingValue = true;
			}
		}
		
		@SuppressWarnings("unchecked")
		public Object clone() {
			return new State((Stack<TLStruct>)state.clone(), isAtStartOfTag, isAtStartOfLength, isReadingValue);
		}
		
		public String toString() {
			return state.toString();
		}

		private class TLStruct implements Cloneable
		{
			private int tag, length, valueBytesRead;

			public TLStruct(int tag, int length, int valueBytesRead) { this.tag = tag; this.length = length; this.valueBytesRead = valueBytesRead; }

			public void setLength(int length) { this.length = length; }

			public int getTag() { return tag; }

			public int getLength() { return length; }

			public int getValueBytesRead() { return valueBytesRead; }

			public void updateValueBytesRead(int n) { this.valueBytesRead += n; }

			public Object clone() { return new TLStruct(tag, length, valueBytesRead); }

			public String toString() { return "[TLStruct " + Integer.toHexString(tag) + ", " + length + ", " + valueBytesRead + "]"; }
		}
	}
}
