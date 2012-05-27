/************************************************************************
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 *
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
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
package org.odftoolkit.odfdom.doc.number;

import org.odftoolkit.odfdom.OdfElement;
import org.odftoolkit.odfdom.OdfFileDom;
import org.odftoolkit.odfdom.dom.OdfNamespaceNames;
import org.odftoolkit.odfdom.dom.attribute.number.NumberFormatSourceAttribute;
import org.odftoolkit.odfdom.dom.element.number.NumberDateStyleElement;
import org.odftoolkit.odfdom.dom.element.number.NumberMonthElement;

/**
 * Convenient functionalty for the parent ODF OpenDocument element
 *
 * This class lets you create a date style from a format string.
 * The format string is given in the same form as Java's
 * SimpleDateFormat class.
 *
 * The characters used are:
 * <pre>
G  	Era designator       AD
y 	Year                 1996; 96
Q	Quarter in Year      2 -- not in Java; in ODF
M 	Month in year        July; Jul; 07
w 	Week in year         27
W 	Week in month        -- not in ODF
D 	Day in year          -- not in ODF
d 	Day in month         10
F 	Day of week in month -- not in ODF
E 	Day in week          Tuesday; Tue
a 	Am/pm marker         PM
H 	Hour in day (0-23)   0
k 	Hour in day (1-24)   -- not in ODF
K 	Hour in am/pm (0-11) -- not in ODF
h 	Hour in am/pm (1-12) -- depends on AM/PM marker
m 	Minute in hour       30
s 	Second in minute     55
S 	Millisecond          -- not in ODF
z 	Time zone            -- not in ODF
Z 	Time zone RFC822     -- not in ODF
 * </pre>
 *  The G, E, and y specifiers are in long form if there are more then 3 in a row.
 *  The Q specifier is in long form if there are more than 2 in a row.
 *  The d, h, and m specifiers are in long form if there is more than one in a row.
 */
public class OdfNumberDateStyle extends NumberDateStyleElement {

    private String styleName;
    private String calendarName;

    public OdfNumberDateStyle(OdfFileDom ownerDoc) {
        super(ownerDoc);
    }

    /** Creates a new instance of DateStyleFromFormat.
     * @param ownerDoc document that this format belongs to
     * @param format format string for the date/time
     * @param styleName name of this style
     */
    OdfNumberDateStyle(OdfFileDom ownerDoc, String format, String styleName) {
        this(ownerDoc, format, styleName, null);
    }

    /** Creates a new instance of DateStyleFromFormat.
     * @param ownerDoc document that this format belongs to
     * @param format format string for the date/time
     * @param styleName name of this style
     * @param calendarName name of the calendar this date style belongs to
     */
    public OdfNumberDateStyle(OdfFileDom ownerDoc, String format, String styleName,
            String calendarName) {
        super(ownerDoc);
        this.styleName = styleName;
        this.calendarName = calendarName;
        buildFromFormat(format);
    }

    /**
     * Creates a &lt;number:date-style&gt; element based upon format.
     * @param format the format string
     */
    public void buildFromFormat(String format) {
        String actionChars = "GyQMwdEaHhms";
        int actionCount = 0;

        char ch;
        String textBuffer = "";
        boolean endQuote = false;

        int i = 0;

        this.setStyleNameAttribute(styleName);
        this.setNumberFormatSourceAttribute(NumberFormatSourceAttribute.Value.LANGUAGE.toString());

        while (i < format.length()) {
            ch = format.charAt(i);
            if (actionChars.indexOf(ch) >= 0) {
                appendText(textBuffer);
                textBuffer = "";
                actionCount = 0;
                while (i < format.length() && format.charAt(i) == ch) {
                    actionCount++;
                    i++;
                }
                processChar(ch, actionCount);
            } else if (ch == '\'') {
                endQuote = false;
                i++;
                while (i < format.length() && (!endQuote)) {
                    ch = format.charAt(i);
                    if (ch == '\'') // check to see if this is really the end
                    {
                        if (i + 1 < format.length() && format.charAt(i + 1) == '\'') {
                            i++;
                            textBuffer += "'";
                        } else {
                            endQuote = true;
                        }
                    } else {
                        textBuffer += ch;
                    }
                    i++;
                }
            } else {
                textBuffer += ch;
                i++;
            }
        }
        appendText(textBuffer);
    }

    /**
     *	Place pending text into a &lt;number:text&gt; element.
     * @param textBuffer pending text
     */
    private void appendText(String textBuffer) {
        OdfNumberText textElement = null;
        if (!textBuffer.equals("")) {
            textElement = new OdfNumberText((OdfFileDom) this.getOwnerDocument());
            textElement.setTextContent(textBuffer);
            this.appendChild(textElement);
        }
    }

    /**
     * Process a formatting character.
     * These elements are built "by hand" rather than
     * @param ch the formatting character to process
     * @param count the number of occurrences of this character
     */
    private void processChar(char ch, int count) {
        OdfFileDom ownerDoc = (OdfFileDom) this.getOwnerDocument();
        switch (ch) {
            case 'G':
                OdfNumberEra era =
                    new OdfNumberEra(ownerDoc);
                era.setNumberStyleAttribute(isLongIf(count > 3));
                if (calendarName != null) {
                    era.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(era);
                break;
            case 'y':
                OdfNumberYear year =
                    new OdfNumberYear(ownerDoc);
                year.setNumberStyleAttribute(isLongIf(count > 3));
                if (calendarName != null) {
                    year.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(year);
                break;
            case 'Q':
                OdfNumberQuarter quarter =
                    new OdfNumberQuarter(ownerDoc);
                quarter.setNumberStyleAttribute(isLongIf(count > 2));
                if (calendarName != null) {
                    quarter.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(quarter);
                break;
            case 'M':
                OdfNumberMonth month =
                    new OdfNumberMonth(ownerDoc);
                month.setNumberTextualAttribute(count > 2);
                month.setNumberStyleAttribute(isLongIf(count % 2 == 0));
                if (calendarName != null) {
                    month.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(month);
              break;
            case 'w':
                OdfNumberWeekOfYear weekOfYear =
                    new OdfNumberWeekOfYear(ownerDoc);
                if (calendarName != null) {
                    weekOfYear.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(weekOfYear);
                break;
            case 'd':
                OdfNumberDay day =
                    new OdfNumberDay(ownerDoc);
                day.setNumberStyleAttribute(isLongIf(count > 1));
                if (calendarName != null) {
                    day.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(day);
                break;
            case 'E':
                OdfNumberDayOfWeek dayOfWeek =
                    new OdfNumberDayOfWeek(ownerDoc);
                dayOfWeek.setNumberStyleAttribute(isLongIf(count > 3));
                if (calendarName != null) {
                    dayOfWeek.setNumberCalendarAttribute(calendarName);
                }
                this.appendChild(dayOfWeek);
                break;
            case 'a':
                OdfNumberAmPm ampm =
                    new OdfNumberAmPm(ownerDoc);
                this.appendChild(ampm);
                break;
            case 'H':
            case 'h':
                OdfNumberHours hours =
                    new OdfNumberHours(ownerDoc);
                hours.setNumberStyleAttribute(isLongIf(count > 1));
                this.appendChild(hours);
                break;
            case 'm':
                OdfNumberMinutes minutes =
                    new OdfNumberMinutes(ownerDoc);
                minutes.setNumberStyleAttribute(isLongIf(count > 1));
                this.appendChild(minutes);
                break;
            case 's':
                OdfNumberSeconds seconds =
                    new OdfNumberSeconds(ownerDoc);
                seconds.setNumberStyleAttribute(isLongIf (count > 1));
                this.appendChild(seconds);
                break;
        }
    }

    /**
     * Add long or short style to an element.
     * @param isLong true if this is number:style="long"; false if number:style="short"
     * @return the string "long" or "short"
     */
    private String isLongIf(boolean isLong) {
        return ((isLong) ? "long" : "short");
    }
}