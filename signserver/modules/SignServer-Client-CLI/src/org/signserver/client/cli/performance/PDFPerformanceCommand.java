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

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Used both for loading a server during performance testing and postprocessing resulting CSV statistics.
 */
public class PDFPerformanceCommand extends AbstractCommand {

	private final static String[] testModules = {PerformanceTestPDFServlet.class.getName() };

	private long totalInvocations;
	private String baseURLString = null;

    public String getDescription() {
        return "Run PDF performance testing";
    }

    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length==0) {
			String basicUsage = "Parameters: <test | postprocess>\n";
			throw new IllegalCommandArgumentsException(basicUsage);
		}

		if (args[0].equalsIgnoreCase("test")) {
			runTest(args);
		} else {
			postProcessRawData(args);
		}
        return 0;
    }

	/**
	 * Perform postprocessing for all supported modules
	 */
	private void postProcessRawData(String[] args) {
		String statisticsDirectory = null;
		File dir = null;
		final String info = "Parameters: <directory of CSV files from statistics collection> <time interval size in seconds> <offset in seconds from the first value>\n";
		
		if (args.length>1) {
			statisticsDirectory = args[1];
			dir = new File(statisticsDirectory);
			if (!dir.isDirectory()) {
				System.out.println(info);
				return;
			}
		} else {
			System.out.println(info);
			return;
		}
		long timeInterval = 5 * 1000;
		if (args.length>2) {
			timeInterval = Long.parseLong(args[2]) * 1000;
		}
		System.out.println("Time interval: " + timeInterval/1000 + " seconds.\n");
		long timeOffset = 0 * 1000;
		if (args.length>3) {
			timeOffset = Long.parseLong(args[3]) * 1000;
		}
		System.out.println("Offset: " + timeOffset/1000 + " seconds.\n");
		File[] csvFiles = dir.listFiles(new CSVFilter());
		if (csvFiles.length == 0) {
			System.out.println(info);
			return;
		}
		// Process each CSV file and calculate averages and derivate
		for (File file : csvFiles) {
			// TODO: Start a new thread for each file to better use several cores.. or try something else..
			if (file.getName().contains("-processed.csv")) {
				continue;
			}
			System.out.println("Processing " + file.getName() + "\n");
			try {
				BufferedReader br = new BufferedReader(new FileReader(file));
				String str = br.readLine();
				if (str == null) {
					continue;
				}
				String[] columns = str.split(";");
				ArrayList<ArrayList<Long>> roundedData = new ArrayList<ArrayList<Long>>();
				ArrayList<Long> uniqueTimes = new ArrayList<Long>();
				long startTime = 0;
				while ((str = br.readLine()) != null) {
					ArrayList<Long> row = new ArrayList<Long>();
					String[] values = str.split(";");
					if (startTime == 0) {
						startTime = Long.parseLong(values[(values.length-1)]);
					}
					long currentTime = Long.parseLong(values[(values.length-1)]);
					if (currentTime >= startTime + timeOffset) {
						currentTime -= currentTime % timeInterval;	// Round down time to nearest value in interval
						if (!uniqueTimes.contains(currentTime)) {
							uniqueTimes.add(currentTime);
						}
						for (int i=0; i<values.length-1; i++) {
							row.add(Long.parseLong(values[i]));
						}
						row.add(currentTime);
						roundedData.add(row);
					}
				}
				br.close();
				ArrayList<String> explanationRow = new ArrayList<String>();
				explanationRow.add(columns[columns.length-1]);	// Add time first
				explanationRow.add("Invocations per "  + timeInterval/1000 + " seconds");	// and then the total in the time interval
				explanationRow.add("Invocations per second");	// and then the total in the time interval
				for (int i=0; i<columns.length-1; i++) {
					explanationRow.add("Total " + columns[i] + " in interval");
					explanationRow.add("Average " + columns[i]);
					explanationRow.add(columns[i] + " per second");
				}
				// Loop trough unique times and sum the other column, calculate average and time-derivate
				ArrayList<ArrayList<Double>> processedData = new ArrayList<ArrayList<Double>>();
				List<Long> uniqueTimesSubset = uniqueTimes.subList(1, uniqueTimes.size() - 1);	// Ignore first and last interval
				for (Long currentTime : uniqueTimesSubset) {
					long currentFound = 0;
					ArrayList<Double> sums = new ArrayList<Double>();
					for (ArrayList<Long> point : roundedData) {
						if (point.get(point.size()-1).longValue() == currentTime.longValue()) {
							currentFound++;
							// Sum all fields, but time
							for (int i=0; i<point.size()-1; i++) {
								if (sums.size() == i) {
									sums.add(new Double(point.get(i)));
								} else {
									sums.set(i, new Double(point.get(i)) + sums.get(i));
								}
							}
						}
					}
					ArrayList<Double> processedRow = new ArrayList<Double>();
					processedRow.add(new Double(currentTime));	// The rounded time
					processedRow.add(new Double(currentFound));	// The number of invocations at this rounded time
					processedRow.add(new Double(currentFound) / new Double(timeInterval/1000));	// The number of invocations / second
					for (Double value : sums) {
						processedRow.add(value);    // Actual value
						processedRow.add(value / new Double(currentFound));    // Average
						processedRow.add(value / new Double(timeInterval/1000));    // Per second
					}
					processedData.add(processedRow);
				}
				File outFile = new File(file.getCanonicalPath().replace(".csv", "-processed.csv"));
				BufferedWriter bw = new BufferedWriter(new FileWriter(outFile));
				for (int i=0; i<explanationRow.size(); i++) {
					bw.write((i==0 ? "" : ";") + explanationRow.get(i));
				}
				bw.newLine();
				for (ArrayList<Double> currentRow : processedData) {
					for (int i=0; i<currentRow.size(); i++) {
						String value = "" + new Double(currentRow.get(i) + 0.5).longValue();
						bw.write((i==0 ? "" : ";") + value);
					}
					bw.newLine();
				}
				bw.close();
				for (String moduleName : testModules) {
					PerformanceTestTask performanceTestTask = (PerformanceTestTask) Class.forName(moduleName).newInstance();
					performanceTestTask.createDiagrams(file.getName(), statisticsDirectory, explanationRow, processedData);
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (InstantiationException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Perform performance test for all supported modules
	 */
	private void runTest(String[] args) {
		int threads = 10;
		long runTime = 300 * 1000;
		if (args.length>1) {
			runTime = Long.parseLong(args[1]) * 1000;
		}
		if (args.length>2) {
			threads = Integer.parseInt(args[2]);
		}
		if (args.length>3) {
			baseURLString = args[3];
		} else {
			baseURLString = "http://localhost:8080/signserver/";
		}
		String info =
			"To enable collection of statistics on the target server(s) be sure it's configured properly. \n " +
			"See the file 'sample-configs/qs_pdfsigner_withcsvfilestatistics_configuration.properties for an example configuration"+
			"\n\n" +
			"Parameters: <runtime for each test seconds> <number of threads> <base-URL>\n\n" +
			"Runtime: " + runTime/1000 + " seconds\n" +
			"Threads: " + threads + "\n" +
			"Base URL: " + baseURLString + "\n\n";
		System.out.println(info);
		for (int i=0; i<testModules.length; i++) {
			System.out.println("Starting test " + testModules[i]);
			runTest(testModules[i], runTime, threads);
		}
	}

	/**
	 * Create a set of threads for current test module. 
	 */
	private long runTest(String className, long timeToRun, int numberOfThreads) {
		totalInvocations = 0;
		ArrayList<Thread> threads = new ArrayList<Thread>();
		Object setupData = null;
		for (int i = 0; i<numberOfThreads; i++) {
			PerformanceTestTask performanceTestTask = null;
			try {
				Class<?> implClass = Class.forName(className);
				performanceTestTask = (PerformanceTestTask) implClass.newInstance();
			} catch (Exception e) {
				e.printStackTrace();
				return 0;
			}
			setupData = performanceTestTask.setup(setupData, timeToRun, baseURLString);
			Thread thread = new Thread(new RepetetiveTask(performanceTestTask, i, timeToRun), "Thread-"+i);
			thread.start();
			threads.add(thread);
		}
		for (Thread thread : threads) {
			try {
				thread.join();
			} catch (InterruptedException e) {
				System.err.println("Error while waiting for task to finish: " + e.getMessage());
			}
		}
		return totalInvocations;
	}

	/**
	 * Used to sum the invocations from all the different threads
	 */
	private synchronized void addFinishedInvocations(long invocations) {
		this.totalInvocations += invocations;
	}

	/**
	 * Performs a task for a requested amount of time.
	 */
	private class RepetetiveTask implements Runnable {
		private PerformanceTestTask performanceTestTask = null;
		private int threadId = 0;
		private long runTime = 0;
		private long startTime = 0;

		protected RepetetiveTask(PerformanceTestTask performanceTestTask, int threadId, long runTime) {
			this.performanceTestTask = performanceTestTask;
			this.threadId = threadId;
			this.runTime = runTime;
			this.startTime = System.currentTimeMillis();
		}

		public void run() {
			try {
				long i = 0;
				while (System.currentTimeMillis() - startTime < runTime) {
					if (!performanceTestTask.invoke(threadId)) {
						break;
					}
					i++;
					Thread.yield();
				}
				addFinishedInvocations(i);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/** Allow pattern "*.csv".  */
	private class CSVFilter implements FilenameFilter {
		public boolean accept(File dir, String name) {
			return (name.toLowerCase().endsWith(".csv"));
		}
	}
}
