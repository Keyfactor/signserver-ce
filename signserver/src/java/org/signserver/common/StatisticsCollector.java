package org.signserver.common;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.InitialContext;

import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;

/**
 * Use this class to collect data at specific points in time and write them to a CSV file.
 * 
 * Typical use for collecting a single variable and the time:
 * 	private final StatisticsCollector statisticsCollector = StatisticsCollector.getInstance(this.getClass().getName(), "Variable name");
 * ...
 * 			if (statisticsCollector != null) {
 * 				statisticsCollector.addRow(""+count);
 * 			}
 *
 * Configuration:
 * GLOB.STATISTICS.ENABLED true|false
 * GLOB.STATISTICS.OUTPUTDIR where to write the CSV
 * GLOB.STATISTICS.MINFLUSHINTERVAL minimum number of seconds between disk writes 
 */
public class StatisticsCollector {
	private static final Logger log = Logger.getLogger(StatisticsCollector.class);
	private static final HashMap<String, StatisticsCollector> instances = new HashMap<String, StatisticsCollector>();

	public static final String TIME_NAME = "Time";
	public static final String PROPERTY_COLLECT_NAME = "STATISTICS.ENABLED";
	public static final String PROPERTY_OUTPUTDIR_NAME = "STATISTICS.OUTPUTDIR";
	public static final String PROPERTY_MINFLUSHINTERVAL_NAME = "STATISTICS.MINFLUSHINTERVAL";

	private static Context initalContext = null;
	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static Boolean isEnabled = null;
	private static String outputDirectory = null;
	private static long minimumFlushInterval = 3 * 1000;
	private long lastFlush = 0;

	private ArrayList<String> names = null;
	private File file = null;
	private ArrayList<ArrayList<String>> writeCache = new ArrayList<ArrayList<String>>();

	private StatisticsCollector() { }
	private StatisticsCollector(String filename, ArrayList<String> names) {
		this.names = names;
		this.names.add(TIME_NAME);
		file = new File(filename);
	}

	/**
	 * Get the initial naming context
	 */
	private static Context getInitialContext() throws Exception {
		if (initalContext == null) {
			Hashtable<String, String> props = new Hashtable<String, String>();
			props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
			props.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
			props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
			initalContext = new InitialContext(props);
		}
		return initalContext;
	}

	/**
	 * Returns the instance for the requested tag or null if collection is disabled. Use this if you only collect time data.
	 * @param identifier can be the classname of the using class
	 */
	public static synchronized StatisticsCollector getInstance(String identifier) {
		ArrayList<String> names = new ArrayList<String>();
		return getInstance(identifier, names);
	}
	
	/**
	 * Returns the instance for the requested tag or null if collection is disabled. Use this is you have a single variable.
	 * @param identifier can be the classname of the using class
	 * @param name for the parameter that are added later
	 */
	public static synchronized StatisticsCollector getInstance(String identifier, String singleName) {
		ArrayList<String> names = new ArrayList<String>();
		names.add(singleName);
		return getInstance(identifier, names);
	}
	
	/**
	 * Returns the instance for the requested tag or null if collection is disabled.
	 * @param identifier can be the classname of the using class
	 * @param names the for each parameter that are added later (use same order)
	 */
	public static synchronized StatisticsCollector getInstance(String identifier, ArrayList<String> names) {
		if (isEnabled == null) {
			// Fetch configuration from database
			if (gCSession == null) {
				try {
					gCSession = (IGlobalConfigurationSession.IRemote) getInitialContext().lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
				} catch (Exception e) {
					log.error(e);
					return null;
				}
			}
			GlobalConfiguration gc = gCSession.getGlobalConfiguration();
			isEnabled = "true".equalsIgnoreCase(gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, PROPERTY_COLLECT_NAME));
			outputDirectory = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, PROPERTY_OUTPUTDIR_NAME);
			String tmp = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL, PROPERTY_MINFLUSHINTERVAL_NAME);
			if (tmp != null) {
				minimumFlushInterval = Long.parseLong(tmp) * 1000;
			}
			if (outputDirectory == null) {
				isEnabled = false;
			}
		}
		if (!isEnabled) {
			return null;
		}
		// Return existing instance or create new one
		StatisticsCollector instance = instances.get(identifier);
		if (instance == null) {
			new File(outputDirectory).mkdirs();
			String filename = outputDirectory;
			if (!filename.endsWith(File.separator)) {
				filename += File.separator;
			}
			filename += identifier + ".csv";
			instance = new StatisticsCollector(filename, names);
		}
		return instance;
	}

	/**
	 * Add a single timestamp.
	 */
	public void addRow() {
		ArrayList<String> strings = new ArrayList<String>();
		addRow(strings, true);
	}

	/**
	 * Add a single value and a timestamp.
	 */
	public void addRow(String singleValue) {
		ArrayList<String> strings = new ArrayList<String>();
		strings.add(singleValue);
		addRow(strings, true);
	}

	/**
	 * Add an array of values and a timestamp.
	 */
	public void addRow(ArrayList<String> strings) {
		addRow(strings, true);
	}
	
	private Boolean locked = false;
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

	/**
	 * Add new line of variables to cache and flush cache to CSV-file if it's been more
	 * than GLOB.STATISTICS.MINFLUSHINTERVAL seconds since last time.
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
				log.error(e);
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
					for (String name : names) {
						if (data.equals("")) {
							data += name;
						} else {
							data += ";" + name;
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
				log.error("Could not write to output file \"" + file.getName() + "\". Disabling collection.", e);
				isEnabled = false;
			}
		}
		setLock(false);
	}
}
