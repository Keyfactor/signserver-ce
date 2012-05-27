package org.odftoolkit.odfdom.type;
/**
 * This class represents the in OpenDocument format used data type {@odf.datatype nonNegativeDecimal}
 */
public class NonNegativeDecimal implements OdfDataType {
	private double mN;

	/**
	 * Allocates a NonNegativeDecimal object representing the n argument
	 * 
	 * @param n
	 *            the value of the NonNegativeDecimal
	 * @throws IllegalArgumentException
	 *             if the given argument is not a valid NonNegativeDecimal
	 */
	public NonNegativeDecimal(double n) throws IllegalArgumentException {
		if (n < 0)
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype NonNegativeDecimal");
		mN = n;
	}

	/**
	 * Returns a String Object representing this NonNegativeDecimal's value
	 * 
	 * @return return a string representation of the value of this
	 *         NonNegativeDecimal object
	 */
	@Override
	public String toString() {
		return Double.toString(mN);
	}

	/**
	 * Returns a NonNegativeDecimal instance representing the specified String
	 * value
	 * 
	 * @param stringValue
	 *            a String value
	 * @return return a NonNegativeDecimal instance representing stringValue
	 * @throws IllegalArgumentException
	 *             if the given argument is not a valid NonNegativeDecimal
	 */
	public static NonNegativeDecimal valueOf(String stringValue)
			throws IllegalArgumentException {
		String aTmp = stringValue.trim();
		double n = Double.valueOf(aTmp);
		return new NonNegativeDecimal(n);
	}

	/**
	 * Returns the value of this NonNegativeDecimal object as a double primitive
	 * 
	 * @return the primitive double value of this NonNegativeDecimal object.
	 */
	public double doubleValue() {
		return mN;
	}

	/**
	 * check if the specified Double instance is a valid {@odf.datatype nonNegativeDecimal} data
	 * type
	 * 
	 * @param doubleValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype nonNegativeDecimal}
	 *         data type false otherwise
	 */
	public static boolean isValid(Double doubleValue) {
		if ((doubleValue != null) && (doubleValue.doubleValue() >= 0)) {
			return true;
		} else {
			return false;
		}
	}
}
