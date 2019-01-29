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
package org.signserver.admin.cli.defaultimpl;

import java.io.FileInputStream;
import java.io.*;
import java.util.Enumeration;
import java.util.Properties;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * Sets properties from a given property file.
 * 
 * See the manual for the syntax of the property file
 *
 * @version $Id$
 */
public class SetPropertiesCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Sets properties from a given property file";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver setproperties <propertyfile>\n"
                    + "Example 1: signserver setproperties mysettings.properties\n"
                    + "Example 2: signserver setproperties -host node3.someorg.com mysettings.properties\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            
            Properties properties = loadProperties(args[0]);
            
            //1. we create File with our new properties and check if File is readable
            File propFile = new File(args[0]);            
            
            //2. now we create PrintStream object required for SetPropertiesHelper
            PrintStream ps = new PrintStream(propFile);
            InputStream is = new FileInputStream(propFile);
            
            SetPropertiesHelper helper = new SetPropertiesHelper(getOutputStream());
            getOutputStream().println("Configuring properties as defined in the file : " + args[0]);
            helper.process(properties);

            this.getOutputStream().println("\n\t\t === End of Set PropertiesCommand ====");
            return 0;
        } catch (Exception e) {
            if ("java.lang.ClassNotFoundException: javax.persistence.PersistenceException".equals(e.getMessage())) {
                throw new CommandFailureException("Persistence failure. Check that the worker name does not already exist.");
            } else {
                throw new UnexpectedCommandFailureException(e);
            }
        }
    }

    private Properties loadProperties(String path) {
        
        //GM init properties class
        Properties props = new Properties();
        
        //GM get loader from current thread
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        //System.out.println("\n === GM SPComm loader: " + loader);//OK
            
        // load NEW properties from file gmNEW.properties
        InputStream stream = loader.getResourceAsStream(path);
        //System.out.println("\n === GM SPComm stream : " + stream.toString());//OK?      
        
        // GM: create File with New properties and check it!
        try {
            File propFile = new File(path);
            //System.out.println("\n === GM File path: " + propFile.getAbsolutePath());//OK
            //System.out.println("\n === GM File.canRead() : " + propFile.canRead());//true
            //System.out.println("\n === GM File.length() : " + propFile.length());//1075
            
            //GM: Alternative way to load Properties using InputStream!!!
            props.load(stream); //1. first load InputStream
            props.load(new FileInputStream(path));// 2. load FileInputStream
            
            //System.out.println("\t === GM SPComm 115 props.Names : " + props.stringPropertyNames());//
            
            //GM: Print out ALL key=value properties that have been set
            for(String key : props.stringPropertyNames()) {
                String value = props.getProperty(key);
                //System.out.println("\t *** GM SPComm 120: Key:"+key+"-value:"+value);//
            }
            
            // check ALL key=value pairs using Iterator!
            Enumeration<?> iter = props.keys();
            
            //System.out.println("\n\t +++ GM SPComm126 props.keys()=iter="+iter.toString());//OK
            
            //GeoMat // check ALL key=value pairs using Iterator!
            while (iter.hasMoreElements()) {
                String key = (String) iter.nextElement();
                //System.out.println("\t +++ GM SPComm131: Key="+key);//NOP
                //processKey(key.toUpperCase(), props.getProperty(key));
                //System.out.println("\t +++ GM(SPComm133) Key:Value=" + key.toUpperCase()+":"+props.getProperty(key));
            }
            
            //System.out.println("\n === GM InputStream(stream).available : " + stream.available());//OK
            //BufferedReader brf = new BufferedReader( new FileReader(path) );
            //props.load(stream);// what do we get here???
          
            //System.out.println("\n === GM props.toString() :" + props.entrySet());//{}
            
            
        } catch (Exception e) {
            getOutputStream().println("Error reading property file : " + path);
            System.exit(-1);
        }

        return props;
    }
}
