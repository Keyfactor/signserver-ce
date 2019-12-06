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
package org.signserver.client.cli.enterprise;

import org.signserver.client.cli.defaultimpl.InputSource;
import org.signserver.client.cli.defaultimpl.OutputCollector;
import org.signserver.client.cli.defaultimpl.AbstractFileSpecificHandler;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.signserver.common.IllegalRequestException;
import java.util.Arrays;
import java.io.BufferedInputStream;
import java.io.RandomAccessFile;
import java.io.BufferedOutputStream;
import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.nio.ByteBuffer;
import org.bouncycastle.util.encoders.Hex;
import java.nio.ByteOrder;
import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.util.Enumeration;
import java.io.InputStream;
import java.util.zip.Deflater;
import java.io.FileOutputStream;
import java.util.zip.Deflater;
import java.util.zip.CRC32;
import org.apache.log4j.Logger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.BufferUnderflowException;
import java.util.List;
import java.util.ArrayList;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.transform.OutputKeys;
import java.util.zip.Inflater;
import org.signserver.module.msauthcode.common.AppxHelper;


/**
 * Implementation of FileSpecificHandler for MSI installer packages.
 *
 */
public class AppxFileSpecificHandler extends AbstractFileSpecificHandler {

    private AppxHelper.EocdField eocdValues;
    private long longNewCentralDirOffset;
    private RandomAccessFile rafOutput;
    private byte[] byteArrReconstructedCentralDirRecords;

    public AppxFileSpecificHandler(File inFile, File outFile) {
        super(inFile, outFile);
    }

    @Override
    public boolean isSignatureInputHash() {
        return true;
    }

    @Override
    public InputSource produceSignatureInput(String algorithm) throws NoSuchAlgorithmException, IOException, IllegalRequestException {

        rafOutput = closeLater(new RandomAccessFile(getOutFile(), "rw"));
        RandomAccessFile rafInput = closeLater(new RandomAccessFile(getInFile(), "r"));

        // Wrapper for tracking new central directory offset after repackaging Appx file
        AppxHelper.CentralDirectoryOffset offset = new AppxHelper.CentralDirectoryOffset();

        // Reconstructed central directory after repackaging Appx file
        ByteArrayOutputStream baosReconstructedCentralDirRecords = new ByteArrayOutputStream();

        // EOCD field data - used to reconstruct EOCD
        eocdValues = new AppxHelper.EocdField();

        final byte[] digest = AppxHelper.produceSignatureInput(rafInput, rafOutput, algorithm, offset, baosReconstructedCentralDirRecords, eocdValues);

        // Set modified values
        this.longNewCentralDirOffset = offset.getCentralDirOffset();
        this.byteArrReconstructedCentralDirRecords = baosReconstructedCentralDirRecords.toByteArray();

        return new InputSource(new ByteArrayInputStream(digest), digest.length);

    }

    @Override
    public void assemble(final OutputCollector oc) throws IOException {

        AppxHelper.assemble(this.rafOutput, oc.toByteArray(), this.longNewCentralDirOffset, this.byteArrReconstructedCentralDirRecords, this.eocdValues);

    }

    @Override
    public String getFileTypeIdentifier() {
        return "APPX";
    }



}
