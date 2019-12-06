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
package org.odftoolkit.odfdom.pkg.manifest;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class OdfFileEntry {

//    private Logger mLog = Logger.getLogger(OdfFileEntry.class.getName());    
    private String mPath;
    private String mMediaType = "";
    private int mSize = -1;
    private EncryptionData _encryptionData;    // The following static attributes are used for JDK 5 media type detection
    private static Map<String, String> MEDIA_TYPE_MAP = null;
    private static final String DEFAULT_TYPE = "application/octet-stream";
    private static final String APPLICATION_POSTSCRIPT = "application/postscript";
    private static final String APPLICATION_RTF = "application/rtf";
    private static final String APPLICATION_X_TEX = "application/x-tex";
    private static final String APPLICATION_X_TEXINFO = "application/x-texinfo";
    private static final String APPLICATION_X_TROFF = "application/x-troff";
    private static final String AUDIO_BASIC = "audio/basic";
    private static final String AUDIO_MIDI = "audio/midi";
    private static final String AUDIO_X_AIFC = "audio/x-aifc";
    private static final String AUDIO_X_AIFF = "audio/x-aiff";
    private static final String AUDIO_X_MPEG = "audio/x-mpeg";
    private static final String AUDIO_X_WAV = "audio/x-wav";
    private static final String IMAGE_GIF = "image/gif";
    private static final String IMAGE_IEF = "image/ief";
    private static final String IMAGE_JPEG = "image/jpeg";
    private static final String IMAGE_PNG = "image/png";
    private static final String IMAGE_TIFF = "image/tiff";
    private static final String IMAGE_X_XWINDOWDUMP = "image/x-xwindowdump";
    private static final String TEXT_HTML = "text/html";
    private static final String TEXT_PLAIN = "text/plain";
    private static final String TEXT_XML = "text/xml";    
    private static final String VIDEO_MEPG = "video/mpeg";
    private static final String VIDEO_QUICKTIME = "video/quicktime";
    private static final String VIDEO_X_MSVIDEO = "video/x-msvideo";

    public OdfFileEntry() {
    }

    public OdfFileEntry(String path, String mediaType) {
        mPath = path;
        mMediaType = (mediaType == null ? "" : mediaType);
        mSize = 0;
    }

    public OdfFileEntry(String path, String mediaType, int size) {
        mPath = path;
        mMediaType = mediaType;
        mSize = size;
    }

    public void setPath(String path) {
        mPath = path;
    }

    public String getPath() {
        return mPath;
    }

    public void setMediaType(String mediaType) {
        mMediaType = (mediaType == null ? "" : mediaType);
    }

    public String getMediaType() {
        return mMediaType;
    }

    /**
     * Get the media type from the given file reference
     * 
     * @param fileRef the reference to the file the media type is questioned
     * 
     * @return the mediaType string of the given file reference
     */
    public static String getMediaType(String fileRef) {
        String mediaType = null;
        try {
            // use 'JavaBeans Activation Framework' if available (as library or as part of JDK 6)
            Class<?> mimetypesClass = Class.forName("javax.activation.MimetypesFileTypeMap");
            Method getContentTypeMethod = mimetypesClass.getMethod("getContentType", String.class);
            mediaType = (String) getContentTypeMethod.invoke(getContentTypeMethod, fileRef);
        } catch (Exception e) {
            // otherwise (JDK 5 without library of 'JavaBeans Activation Framework')
            // use local fallback implementation
//          mLog.fine("Using own mediatype handling as 'JavaBeans Activation Framework' not found: " +  e.getMessage());
            mediaType = findMediaType(fileRef);
        }
        return mediaType;
    }

    /** Own mediatype functionality which can be removed as soon JDK 6 is base line */
    private static String findMediaType(String fileRef) {
        String fileSuffix = null;
        String mediaType = null;

        int suffixStart = fileRef.lastIndexOf(".");
        // default mediatype, if no dot exists        
        if (suffixStart < 0) {
            mediaType = DEFAULT_TYPE;
        } else {
            fileSuffix = fileRef.substring(suffixStart + 1);
            // default mediattype, if the file ends with a dot, the suffix is empty
            if (fileSuffix.length() == 0) {
                mediaType = DEFAULT_TYPE;
            } else {
                if (MEDIA_TYPE_MAP == null) {
                    initializeMediaTypeMap();
                }
                mediaType = MEDIA_TYPE_MAP.get(fileSuffix.toLowerCase());
                // default mediatype, if no mediatype for this suffix exists
                if (mediaType == null) {
                    mediaType = DEFAULT_TYPE;
                }
            }
        }
        return mediaType;
    }
    // initializes Map for suffix to media type mapping
    private static void initializeMediaTypeMap() {
        MEDIA_TYPE_MAP = new HashMap<String, String>(39);
        MEDIA_TYPE_MAP.put("ai", APPLICATION_POSTSCRIPT);
        MEDIA_TYPE_MAP.put("eps", APPLICATION_POSTSCRIPT);
        MEDIA_TYPE_MAP.put("ps", APPLICATION_POSTSCRIPT);
        MEDIA_TYPE_MAP.put("rtf", APPLICATION_RTF);
        MEDIA_TYPE_MAP.put("tex", APPLICATION_X_TEX);
        MEDIA_TYPE_MAP.put("texi", APPLICATION_X_TEXINFO);
        MEDIA_TYPE_MAP.put("texinfo", APPLICATION_X_TEXINFO);
        MEDIA_TYPE_MAP.put("t", APPLICATION_X_TROFF);
        MEDIA_TYPE_MAP.put("tr", APPLICATION_X_TROFF);
        MEDIA_TYPE_MAP.put("roff", APPLICATION_X_TROFF);
        MEDIA_TYPE_MAP.put("au", AUDIO_BASIC);
        MEDIA_TYPE_MAP.put("midi", AUDIO_MIDI);
        MEDIA_TYPE_MAP.put("mid", AUDIO_MIDI);
        MEDIA_TYPE_MAP.put("aifc", AUDIO_X_AIFC);
        MEDIA_TYPE_MAP.put("aif", AUDIO_X_AIFF);
        MEDIA_TYPE_MAP.put("aiff", AUDIO_X_AIFF);
        MEDIA_TYPE_MAP.put("mpeg", AUDIO_X_MPEG);
        MEDIA_TYPE_MAP.put("mpg", AUDIO_X_MPEG);
        MEDIA_TYPE_MAP.put("wav", AUDIO_X_WAV);
        MEDIA_TYPE_MAP.put("gif", IMAGE_GIF);
        MEDIA_TYPE_MAP.put("ief", IMAGE_IEF);
        MEDIA_TYPE_MAP.put("jpeg", IMAGE_JPEG);
        MEDIA_TYPE_MAP.put("jpg", IMAGE_JPEG);
        MEDIA_TYPE_MAP.put("jpe", IMAGE_JPEG);
        MEDIA_TYPE_MAP.put("png", IMAGE_PNG);
        MEDIA_TYPE_MAP.put("tiff", IMAGE_TIFF);
        MEDIA_TYPE_MAP.put("tif", IMAGE_TIFF);
        MEDIA_TYPE_MAP.put("xwd", IMAGE_X_XWINDOWDUMP);
        MEDIA_TYPE_MAP.put("html", TEXT_HTML);
        MEDIA_TYPE_MAP.put("htm", TEXT_HTML);
        MEDIA_TYPE_MAP.put("xhtml", TEXT_HTML);
        MEDIA_TYPE_MAP.put("txt", TEXT_PLAIN);
        MEDIA_TYPE_MAP.put("text", TEXT_PLAIN);
        MEDIA_TYPE_MAP.put("xml", TEXT_XML);        
        MEDIA_TYPE_MAP.put("mpeg", VIDEO_MEPG);
        MEDIA_TYPE_MAP.put("mpg", VIDEO_MEPG);
        MEDIA_TYPE_MAP.put("mpe", VIDEO_MEPG);
        MEDIA_TYPE_MAP.put("qt", VIDEO_QUICKTIME);
        MEDIA_TYPE_MAP.put("mov", VIDEO_QUICKTIME);
        MEDIA_TYPE_MAP.put("avi", VIDEO_X_MSVIDEO);
    }

    public void setSize(int size) {
        mSize = size;
    }

    /**
     * get the size or -1 if not set
     */
    public int getSize() {
        return mSize;
    }

    public void setEncryptionData(EncryptionData encryptionData) {
        _encryptionData = encryptionData;
    }

    public EncryptionData getEncryptionData() {
        return _encryptionData;
    }
}

