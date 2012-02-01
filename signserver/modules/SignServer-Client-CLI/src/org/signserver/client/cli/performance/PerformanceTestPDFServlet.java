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
package org.signserver.client.cli.performance;

import com.lowagie.text.Document;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfWriter;
import java.awt.Color;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartRenderingInfo;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.LogarithmicAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.entity.StandardEntityCollection;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.StandardXYItemRenderer;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

/**
 * Used for both loading the PDF servlet with requests and doing PDF-specific
 * postprocessing.
 *
 * @version $Id$
 */
public class PerformanceTestPDFServlet implements PerformanceTestTask {

	// Some reasonable test parameters
	static final int MIN_PDF_SIZE = 10 * 1000;
	static final int MAX_PDF_SIZE = 5 * 1000 * 1000;
	static final int DIFFERENT_PDF_SIZES = 20;

        private static final String REQUEST_CONTENT_BOUNDRY = "\r\n--signserver\r\n";
        private static final String REQUEST_CONTENT_WORKERNAME =
                REQUEST_CONTENT_BOUNDRY
                + "Content-Disposition: form-data; name=\"workerName\"\r\n\r\n"
                + "PDFSigner";
	private final static String REQUEST_CONTENT_FILE = REQUEST_CONTENT_BOUNDRY
		+ "Content-Disposition: form-data; name=\"datafile\"; filename=\"test.pdf\"\r\n"
		+ "Content-Type: application/pdf\r\n"
		+ "Content-Transfer-Encoding: binary\r\n\r\n";
	private final static String REQUEST_CONTENT_END = "\r\n--signserver--\r\n";
	private static final String PDF_CONTENT = "This is a test document for the PDF signer.";

	private String baseURLString = null;
	private ArrayList<byte[]> pdfs = new ArrayList<byte[]>();
	private long startTime = 0;
	private long runTime = 0;

	/** @see org.signserver.client.PerformanceTestTask */
	public boolean invoke(int threadId) {
		if (startTime == 0) {
			startTime = System.currentTimeMillis();
		}
		byte[] testPDF = pdfs.get((int) ((System.currentTimeMillis() - startTime) * ((long) pdfs.size()) / runTime));
		URL target;
		try {
			target = new URL(baseURLString);
			InetAddress addr = InetAddress.getByName(target.getHost());
			Socket socket = new Socket(addr, target.getPort());
			OutputStream raw = socket.getOutputStream();
			final int contentLength =
                                REQUEST_CONTENT_WORKERNAME.length()
                                + REQUEST_CONTENT_FILE.length()
                                + testPDF.length
                                + REQUEST_CONTENT_END.length();
			final String command =
				"POST "+target.getPath() + "pdf HTTP/1.0\r\n"
				+ "Content-Type: multipart/form-data; boundary=signserver\r\n"
				+ "Content-Length: " + contentLength + "\r\n"
				+ "\r\n";
			raw.write(command.getBytes());
                        raw.write(REQUEST_CONTENT_WORKERNAME.getBytes());
			raw.write(REQUEST_CONTENT_FILE.getBytes());
			raw.write(testPDF);
			raw.write(REQUEST_CONTENT_END.getBytes());
			raw.flush( );

			InputStream in = socket.getInputStream();
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			int len = 0;
			byte[] buf = new byte[1024];
			while ((len = in.read(buf)) > 0) {
				os.write(buf, 0, len);
			}
			in.close();
			os.close();
			byte[] inbytes = os.toByteArray();

			PdfReader pdfReader = new PdfReader(inbytes);
			if (!new String(pdfReader.getPageContent(1)).contains(PDF_CONTENT)) {
				System.err.println("Did not get the same document back..");
				return false;
			}
			pdfReader.close();
			raw.close();
			socket.close();
		} catch (IOException e) {
			System.err.println("testPDF.length=" + testPDF.length + "," + e.getMessage());
			//e.printStackTrace();
			return false;
		}
		return true;
	}

	/** @see org.signserver.client.PerformanceTestTask */
	@SuppressWarnings("unchecked")
	public Object setup(Object setupData, long timeToRun, String baseURLString) {
		this.runTime = timeToRun;
		if (!baseURLString.endsWith("/")) {
			baseURLString += "/";
		}
		this.baseURLString = baseURLString;
		if (setupData != null) {
			pdfs = (ArrayList<byte[]>) setupData;
		} else {
			// Generate some testing PDFs
			for (int i=0; i<DIFFERENT_PDF_SIZES; i++) {
				try {
					// y = ((max-min)/(n-1)^2) * x^2 + min
					int size = ((MAX_PDF_SIZE - MIN_PDF_SIZE) * i * i/ ((DIFFERENT_PDF_SIZES-1)*(DIFFERENT_PDF_SIZES-1))) + MIN_PDF_SIZE;
					pdfs.add(createTestPDF(size));
				} catch (Exception e) {
					e.printStackTrace();
					break;
				}
			}
		}
		return pdfs;
	}

	/**
	 * Creates a new PDF document by adding the same paragraph over and over.
	 * @param requestSize is the requested size of the PDF in bytes 
	 */
	private byte[] createTestPDF(int requestSize) throws Exception {
		// Create a sample PDF-file
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Document pdfDocument = new Document(PageSize.A4, 50, 50, 50, 50);
		PdfWriter.getInstance(pdfDocument, baos);
		pdfDocument.open();
		pdfDocument.add(new Paragraph(PDF_CONTENT));
		final String DUMMYTEXT = "qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxc";
		int maxIteration = requestSize/20;
		for (int i=0; i<maxIteration; i++) {
			pdfDocument.add(new Paragraph(DUMMYTEXT));
		}
		pdfDocument.close();
		baos.flush();
		System.out.println("Created new PDF-document of " + baos.toByteArray().length + " bytes.");
		return baos.toByteArray();
	}

	//Time;Invocations per 60 seconds;Invocations per second;Total PDF size in bytes in interval;Average PDF size in bytes;PDF size in bytes per second
	private final int COLUMN_TIME = 0;
	private final int COLUMN_INVOCATIONS_PER_SECOND = 2;
	private final int COLUMN_AVERAGE_PDF_SIZE = 4;
	private final int COLUMN_DATAFLOW = 5;
	

	/** @see org.signserver.client.PerformanceTestTask */
	public void createDiagrams(String currentFileName, String statisticsDirectory, ArrayList<String> explanationRow, ArrayList<ArrayList<Double>> processedData) {
		explanationRow.set(COLUMN_DATAFLOW, "Data throughput (bytes/second)");	// Set nicer explanation

		if (!statisticsDirectory.endsWith("/")) {
			statisticsDirectory += "/";
		}
		// Diagram: X: Avg PDF Size Y1: Invocations/second Y2: PDF data/second
		createDiagram(statisticsDirectory, explanationRow, processedData, COLUMN_AVERAGE_PDF_SIZE, COLUMN_INVOCATIONS_PER_SECOND, COLUMN_DATAFLOW);
		// Diagram: X: Time Y1: Invocations/second Y2: PDF average size
		createDiagram(statisticsDirectory, explanationRow, processedData, COLUMN_TIME, COLUMN_INVOCATIONS_PER_SECOND, COLUMN_AVERAGE_PDF_SIZE);
		// Diagram: X: Time Y1: PDF average size Y2: Data flow
		createDiagram(statisticsDirectory, explanationRow, processedData, COLUMN_TIME, COLUMN_AVERAGE_PDF_SIZE, COLUMN_DATAFLOW);
	}

	/**
	 * Create and write diagrams to disk.
	 */
	private void createDiagram(String statisticsDirectory, ArrayList<String> explanationRow, ArrayList<ArrayList<Double>> processedData, int xRow, int y1Row, int y2Row) {
		final XYSeries s1 = new XYSeries(explanationRow.get(y1Row));
		final XYSeries s2 = new XYSeries(explanationRow.get(y2Row));
		for (ArrayList<Double> currentRow : processedData) {
			s1.add(currentRow.get(xRow), currentRow.get(y1Row));
			s2.add(currentRow.get(xRow), currentRow.get(y2Row));
		}
		final XYSeriesCollection dataset1 = new XYSeriesCollection();
		dataset1.addSeries(s1);
		final XYSeriesCollection dataset2 = new XYSeriesCollection();
		dataset2.addSeries(s2);
		final JFreeChart chart = ChartFactory.createXYLineChart("Test result " + xRow + "" + y1Row + "" + y2Row, explanationRow.get(xRow),
				explanationRow.get(y1Row) ,dataset1, PlotOrientation.VERTICAL, true, true, false);
		final XYPlot plot = chart.getXYPlot();
		if (y1Row == COLUMN_INVOCATIONS_PER_SECOND) {
			final NumberAxis axis1 = new LogarithmicAxis(explanationRow.get(y1Row));
			plot.setRangeAxis(0, axis1);
		}
		final NumberAxis axis2 = new NumberAxis(explanationRow.get(y2Row));
		axis2.setAutoRangeIncludesZero(false);
		plot.setRangeAxis(1, axis2);
		plot.setDataset(1, dataset2);
		plot.mapDatasetToRangeAxis(1, 1);
		final StandardXYItemRenderer renderer2 = new StandardXYItemRenderer();
		renderer2.setSeriesPaint(0, Color.BLUE);
		plot.setRenderer(1, renderer2);
		final ChartRenderingInfo info = new ChartRenderingInfo(new StandardEntityCollection());
		final File file = new File(statisticsDirectory + "PDF Signatures" + "-" + xRow + "" + y1Row + "" + y2Row + ".png");
        int imageWidth = 800;
        int imageHeight = 600;
        try {
    		System.out.println("Writing diagram to " + file.getName());
    		System.out.flush();
			ChartUtilities.saveChartAsPNG(file, chart, imageWidth, imageHeight, info);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}	
