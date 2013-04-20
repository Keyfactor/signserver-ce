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
package org.signserver.server.statistics.csvfilewriter;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.IStatisticsCollector;
import org.signserver.server.statistics.StatisticsEntry;

/**
 * Use this class to collect data at specific points in time and write them to a CSV file.
 * 
 * It supports both just event count and custom data
 *
 * Configuration: 
 * STATISTICS.CSVFILE.COLUMNHEADER.n the column header where n should be a number between 0 and 255
 * STATISTICS.CSVFILE.COLUMNCUSTOMKEY.n The key used to fetch values from the custom data in the event, a number between 0 and 255
 * STATISTICS.CSVFILE.OUTPUTDIR the directory  to write the CSV to.
 * STATISTICS.CSVFILE.MINFLUSHINTERVAL minimum number of seconds between disk writes (default is 3 seconds);
 */
public class CSVFileStatisticsCollector implements IStatisticsCollector {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CSVFileStatisticsCollector.class);
    
    public static final String TIME_NAME = "Time";
    public static final String PROPERTY_COLUMNHEADER = "STATISTICS.CSVFILE.COLUMNHEADER.";
    public static final String PROPERTY_COLUMNCUSTOMKEY = "STATISTICS.CSVFILE.COLUMNCUSTOMKEY.";
    public static final String PROPERTY_OUTPUTDIR_NAME = "STATISTICS.CSVFILE.OUTPUTDIR";
    public static final String PROPERTY_MINFLUSHINTERVAL_NAME = "STATISTICS.CSVFILE.MINFLUSHINTERVAL";
    private static final String DEFAULT_MINFLUSHINTERVAL = "3000";
    private static long minimumFlushInterval;
    private long lastFlush = 0;
    private int workerId;
    private boolean missConfigured = false;
    private ArrayList<String> columnHeaders;
    private ArrayList<String> customDataKeys;
    private File file;
    private ArrayList<ArrayList<String>> writeCache = new ArrayList<ArrayList<String>>();
    
    private Boolean locked = false;

    public CSVFileStatisticsCollector() {
    }

    /**
     * Initializes the CSV File Writer statistics collector.
     */
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        this.workerId = workerId;
        file = getOutputFile(config);
        columnHeaders = getColumnHeaders(config);
        customDataKeys = getColumnValues(config);
        minimumFlushInterval = getMinimumFlushInterval(config);
    }

    @Override
    public void addEvent(Event event) throws SignServerException {
        if (!missConfigured) {
            if (customDataKeys.isEmpty()) {
                addRow();
            } else {
                ArrayList<String> values = new ArrayList<String>();
                for (String customKey : customDataKeys) {
                    Integer value = event.getCustomData().get(customKey);
                    if (value == null) {
                        values.add("");
                    } else {
                        values.add(value.toString());
                    }
                }
                addRow(values);
            }
        }
    }

    /**
     * Add a single timestamp.
     */
    private void addRow() {
        ArrayList<String> strings = new ArrayList<String>();
        addRow(strings, true);
    }

    /**
     * Add an array of values and a timestamp.
     */
    private void addRow(ArrayList<String> strings) {
        addRow(strings, true);
    }

    /**
     * Add new line of variables to cache and flush cache to CSV-file if it's been more
     * than STATISTICS.CSVFILE.MINFLUSHINTERVAL seconds since last time.
     * 
     * @param strings variables to add to CSV
     * @param addTime adds the current time in milliseconds to the last column
     */
    private void addRow(ArrayList<String> strings, boolean addTime) {
        // Synchronized does not work when the method contains disk IO operations..
        while (!setLock(true)) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                LOG.error(e);
            }
        }
        if (addTime) {
            strings.add("" + System.currentTimeMillis());
        }
        writeCache.add(strings);
        if (lastFlush + minimumFlushInterval < System.currentTimeMillis()) {
            lastFlush = System.currentTimeMillis();
            try {
                String data = "";
                if (!file.exists()) {
                    new File(file.getParent()).mkdirs();
                    file.createNewFile();
                    for (String header : columnHeaders) {
                        if (data.equals("")) {
                            data += header;
                        } else {
                            data += ";" + header;
                        }
                    }
                    data += "\n";
                }
                FileOutputStream fos = new FileOutputStream(file, true);
                for (ArrayList<String> currentRow : writeCache) {
                    Iterator<String> i = currentRow.iterator();
                    while (i.hasNext()) {
                        if (data.equals("") || data.endsWith("\n")) {
                            data += i.next();
                        } else {
                            data += ";" + i.next();
                        }
                    }
                    data += "\n";
                }
                fos.write(data.getBytes());
                fos.close();
                writeCache = new ArrayList<ArrayList<String>>();
            } catch (IOException e) {
                LOG.error("Could not write to output file \"" + file.getName() + "\". Disabling collection.", e);
                missConfigured = true;
            }
        }
        setLock(false);
    }

    /**
     * Method not supported, will always return an empty list.
     * @see org.signserver.server.statistics.IStatisticsCollector#fetchStatistics(java.lang.String, java.util.Date, java.util.Date)
     */
    @Override
    public List<StatisticsEntry> fetchStatistics(String type, Date startTime,
            Date endTime) {
        return new ArrayList<StatisticsEntry>();
    }

    @Override
    public void flush() {
        file.delete();
    }

    /**
     * Method used to fetch the output file from the configuration parameters.
     * @param config
     * @return
     */
    private File getOutputFile(WorkerConfig config) {
        String outputPath = config.getProperty(PROPERTY_OUTPUTDIR_NAME);
        if (outputPath == null) {
            LOG.error("Error CSVFileStatisticsCollector for worker with id '" + workerId + "' is missconfigured, be sure to set the property " + PROPERTY_OUTPUTDIR_NAME + " for this worker.");
            missConfigured = true;
            return null;
        }
        File dir = new File(outputPath.trim());
        if (dir.exists() && !dir.isDirectory()) {
            LOG.error("Error CSVFileStatisticsCollector for worker with id '" + workerId + "' is missconfigured, the file pointed to by " + PROPERTY_OUTPUTDIR_NAME + " have the value " + outputPath + " that doesn't seem to be a valid directiry.");
            missConfigured = true;
            return null;
        }
        if (dir.exists() && !dir.canWrite()) {
            LOG.error("Error CSVFileStatisticsCollector for worker with id '" + workerId + "' is missconfigured, the file pointed to by " + PROPERTY_OUTPUTDIR_NAME + " have the value " + outputPath + " that doesn't the running user doesn't have write access to.");
            missConfigured = true;
            return null;
        }
        Random rand = new Random();
        File file = new File(outputPath + File.separator + "workerid-" + workerId + "-stats" + rand.nextInt() + ".csv");

        return file;
    }

    private long getMinimumFlushInterval(WorkerConfig config) {
        long retval = Long.parseLong(DEFAULT_MINFLUSHINTERVAL);
        try {
            retval = Long.parseLong(config.getProperty(PROPERTY_MINFLUSHINTERVAL_NAME, DEFAULT_MINFLUSHINTERVAL));
        } catch (NumberFormatException e) {
            LOG.error("Error CSVFileStatisticsCollector for worker with id '" + workerId + "' is missconfigured, the property " + PROPERTY_MINFLUSHINTERVAL_NAME + " having the value " + config.getProperty(PROPERTY_MINFLUSHINTERVAL_NAME) + " can only contain digits, using the default value.");
        }
        return retval;
    }

    private ArrayList<String> getColumnHeaders(WorkerConfig config) {
        return SignServerUtil.getCollectionOfValuesFromProperties(PROPERTY_COLUMNHEADER, config);
    }

    private ArrayList<String> getColumnValues(WorkerConfig config) {
        return SignServerUtil.getCollectionOfValuesFromProperties(PROPERTY_COLUMNCUSTOMKEY, config);
    }

    /**
     * Request new mutex lock state.
     * @param state true to get lock, false to release
     * @return true if successful
     */
    private synchronized boolean setLock(boolean state) {
        if (state) {
            if (locked) {
                return false;
            }
            locked = true;
        } else {
            locked = false;
        }
        return true;
    }
}
