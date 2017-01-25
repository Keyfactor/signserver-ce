package org.odftoolkit.odfdom.type;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype signedZeroToHundredPercent}
 */
public class SignedZeroToHundredPercent implements OdfDataType{
	private double mN;

	/**
	 * Allocates a SignedZeroToHundredPercent object representing the n argument
	 *
	 * @param n
	 *            the value of the SignedZeroToHundredPercent
	 * @throws IllegalArgumentException if the given argument is not a valid SignedZeroToHundredPercent
	 */
	public SignedZeroToHundredPercent(double n) throws IllegalArgumentException {
		if( n > 1 || n < -1)
			throw new IllegalArgumentException("parameter is invalidate for datatype SignedZeroToHundredPercent");
		mN = n;
	}

	/**
	 * Returns a String Object representing this SignedZeroToHundredPercent's value
	 *
	 * @return return a string representation of the value of this SignedZeroToHundredPercent
	 *         object
	 */
	@Override
	public String toString() {
		return Double.toString(mN * 100) + "%";
	}

	/**
	 * Returns a SignedZeroToHundredPercent instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a SignedZeroToHundredPercent instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid SignedZeroToHundredPercent
	 */
	public static SignedZeroToHundredPercent valueOf(String stringValue)
			throws IllegalArgumentException {
		if ((stringValue == null) || (stringValue.length() == 0)) {
			return new SignedZeroToHundredPercent(0.0);
		}

		int n = stringValue.indexOf("%");
		if (n != -1) {
			return new SignedZeroToHundredPercent(Double.valueOf(stringValue.substring(0, n)).doubleValue() / 100);
		} else {
			throw new IllegalArgumentException("parameter is invalidate for datatype SignedZeroToHundredPercent");
		}
	}

	/**
	 * Returns the value of this SignedZeroToHundredPercent object as a double primitive
	 *
	 * @return the primitive double value of this SignedZeroToHundredPercent object.
	 */
	public double doubleValue() {
		return mN;
	}

	/**
	 * check if the specified Double instance is a valid {@odf.datatype signedZeroToHundredPercent} data type
	 *
	 * @param doubleValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype signedZeroToHundredPercent} data type
	 *         false otherwise
	 */
	public static boolean isValid(Double doubleValue) {
		if ( (doubleValue != null) && (doubleValue.doubleValue() <= 1) && 
				(doubleValue.doubleValue() >= -1)) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * check if the specified String instance is a valid {@odf.datatype 'signedZeroToHundredPercent'} data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype 'signedZeroToHundredPercent'} data type
	 *         false otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^-?([0-9]?[0-9](\\.[0-9]*)?|100(\\.0*)?|\\.[0-9]+)%$"))) {
			return false;
		} else {
			return true;
		}
	}
}
