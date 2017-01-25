/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * Copyright 2009 IBM. All rights reserved.
 * 
 * Use is subject to license terms.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0. You can also
 * obtain a copy of the License at http://odftoolkit.org/docs/license.txt
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ************************************************************************/
package org.odftoolkit.odfdom.type;

/**
 * This class represents the in OpenDocument format used data type {@odf.datatype color}
 */
public class Color implements OdfDataType {
	private String mColor;

	/**
	 * Construct Color by the parsing the given string
	 *
	 * @param color
	 *            The String to be parsed into Color
	 * @throws IllegalArgumentException if the given argument is not a valid Color
	 */
	public Color(String color) throws IllegalArgumentException {
		if ((color == null) || (!color.matches("^#[0-9a-fA-F]{6}$"))) {
			throw new IllegalArgumentException(
					"parameter is invalidate for datatype Color");
		}
		mColor = color;
	}

	/**
	 * Returns a String Object representing this Color's value which is in hex
	 * format
	 *
	 * @return return a string representation of the value of this Color object
	 */
	@Override
	public String toString() {
		return mColor;
	}

	/**
	 * Returns a Color instance representing the specified String value
	 *
	 * @param stringValue
	 *            a String value
	 * @return return a Color instance representing stringValue
	 * @throws IllegalArgumentException if the given argument is not a valid Color
	 */
	public static Color valueOf(String stringValue)
			throws IllegalArgumentException {
		return new Color(stringValue);
	}

	/**
	 * check if the specified String is a valid {@odf.datatype color}  data type
	 *
	 * @param stringValue
	 *            the value to be tested
	 * @return true if the value of argument is valid for {@odf.datatype color} data type false
	 *         otherwise
	 */
	public static boolean isValid(String stringValue) {
		if ((stringValue == null) || (!stringValue.matches("^#[0-9a-fA-F]{6}$"))) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Map a Color datatype from the rgb format to Hex value
	 * Value have to be trimmed (no spaces around) and lower caser
	 *
	 * @param colorValue The color value to be mapped
	 * @return the converted color from rgb format to hex format
	 */
	public static String mapColorFromRgbToHex(String colorValue) {
		if (colorValue.startsWith("rgb")) {
			colorValue = colorValue.substring(3);
			colorValue = colorValue.substring(colorValue.indexOf("(") + 1,
					colorValue.indexOf(")"));
			String[] rgbValues = colorValue.split(",");
			if (rgbValues.length == 3) {
				int r = Integer.parseInt(rgbValues[0].trim());
				int g = Integer.parseInt(rgbValues[1].trim());
				int b = Integer.parseInt(rgbValues[2].trim());
				String rs = Integer.toHexString(r);
				String gs = Integer.toHexString(g);
				String bs = Integer.toHexString(b);
				String hexColor = "#";
				if (r < 16) {
					hexColor += "0";
				}
				hexColor += rs;
				if (g < 16) {
					hexColor += "0";
				}
				hexColor += gs;

				if (b < 16) {
					hexColor += "0";
				}
				hexColor += bs;
				return hexColor;
			}
		}
		return colorValue;
	}
}
