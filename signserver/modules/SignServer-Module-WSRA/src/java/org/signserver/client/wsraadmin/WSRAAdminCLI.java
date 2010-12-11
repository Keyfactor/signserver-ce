package org.signserver.client.wsraadmin;

import java.io.File;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContextType;
import javax.persistence.spi.PersistenceUnitTransactionType;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.AnnotationConfiguration;
import org.hibernate.ejb.EntityManagerImpl;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.beans.AuthDataBean;
import org.signserver.module.wsra.beans.BackupRestoreBean;
import org.signserver.module.wsra.beans.CertificateDataBean;
import org.signserver.module.wsra.beans.DataBankDataBean;
import org.signserver.module.wsra.beans.OrganizationDataBean;
import org.signserver.module.wsra.beans.PricingDataBean;
import org.signserver.module.wsra.beans.ProductDataBean;
import org.signserver.module.wsra.beans.ProductsInOrganizationDataBean;
import org.signserver.module.wsra.beans.TokenDataBean;
import org.signserver.module.wsra.beans.TransactionDataBean;
import org.signserver.module.wsra.beans.UserAliasDataBean;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.common.WSRAConstants.OrganizationStatus;
import org.signserver.module.wsra.common.WSRAConstants.PricingStatus;
import org.signserver.module.wsra.common.WSRAConstants.ProductStatus;
import org.signserver.module.wsra.core.DBManagers;
import org.signserver.module.wsra.core.DataBankManager;
import org.signserver.module.wsra.core.DataConfigurationManager;
import org.signserver.module.wsra.core.DataFileParser;
import org.signserver.module.wsra.core.ProductMapper;

/**
 * CLI Tool used to perform validation lookups from
 * command line. Main target is to be used from scripts
 * for various usages. 
 * 
 * 
 * @author Philip Vendil 13 sep 2008
 *
 * @version $Id$
 */
public class WSRAAdminCLI {
	
	@SuppressWarnings("unused")
	private static final Logger log = Logger.getLogger(WSRAAdminCLI.class);

	WSRAAdminCLI(){}
	
	public static final String OPTION_HELP = "help";
	public static final String OPTION_CONFIGFILE = "config";
	public static final String OPTION_DATAFILE = "data";
	public static final String OPTION_TYPE = "type";
	public static final String OPTION_ACTION = "action";
	public static final String OPTION_INCLUDEUSERS = "includeusers";
	public static final String OPTION_NAME = "name";
	public static final String OPTION_NEWSTATUS = "newstatus";

	public static final int RETURN_ERROR = -2;
	public static final int RETURN_BADARGUMENT = -1;
	public static final int RETURN_OK = 0;

	

	private boolean includeUsers = false;
	private String configFilePath = null;
	private ActionType action = null;
	private DataConfigurationManager.Type type = null;
	private String dataFilePath;
	private String name;
	private String newstatus;
	private OrganizationStatus orgStatus =null;
	private ProductStatus prodStatus = null;
	private PricingStatus priceStatus = null;
	
	private enum ActionType{
		DUMP,
		ADD,
		CHANGESTATUS,
		REMOVE
	}

	
	private WSRAAdminCLI(String[] args){
		
		SignServerUtil.installBCProvider();
		
		Option help = new Option( OPTION_HELP, false, "Display this info" );				
		Option incUsers = new Option( OPTION_INCLUDEUSERS, false, "Include users in organization import (Default is false)." );
						
		
		OptionBuilder.withArgName( "action-name" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "The action to perform, one of 'add','dump','changestatus','remove'. (Required)" );        		 
		Option actionOption = OptionBuilder.create( OPTION_ACTION);
		
		OptionBuilder.withArgName( "config-file" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Path cli configuration file. (./wsraadmin_config.properties' is used if not specified)." );        		 
		Option configOption = OptionBuilder.create( OPTION_CONFIGFILE );
		
		OptionBuilder.withArgName( "data-file" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Path to XML data file (Required for 'add' and 'dump')." );        		 
		Option dataFileOption = OptionBuilder.create( OPTION_DATAFILE );
		
		OptionBuilder.withArgName( "type-name" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Type of data to perform action on, one of 'ALL','ORGANIZATIONS','PRODUCTS','PRICES','PRODUCTMAPPINGS'." );        		 
		Option typeOption = OptionBuilder.create( OPTION_TYPE );
		
		OptionBuilder.withArgName( "object-name" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "Name, product number or priceclass of object to change status of." );        		 
		Option nameOption = OptionBuilder.create( OPTION_NAME);
		
		OptionBuilder.withArgName( "status-name" );
		OptionBuilder.hasArg();
        OptionBuilder.withDescription( "The new status of the object." );        		 
		Option newstatusOption = OptionBuilder.create( OPTION_NEWSTATUS);
		
	
	    Options options = new Options();
	    options.addOption(help);
	    options.addOption(incUsers);
	    options.addOption(actionOption);
	    options.addOption(configOption);
	    options.addOption(dataFileOption);
	    options.addOption(nameOption);
	    options.addOption(typeOption);
	    options.addOption(newstatusOption);

	     CommandLineParser parser = new GnuParser();
	      try {
	    	  CommandLine cmd = parser.parse( options, args);
	          if (cmd.hasOption(OPTION_HELP)) {
	        	  printUsage(options);
	          }
	          	          
	          includeUsers = cmd.hasOption(OPTION_INCLUDEUSERS);
	          	          
	          if(cmd.hasOption(OPTION_ACTION) && cmd.getOptionValue(OPTION_ACTION) != null){
	        	   String actionString = cmd.getOptionValue(OPTION_ACTION);
	        	   try{	        		   
	        	     action = ActionType.valueOf(actionString.toUpperCase());
	        	   }catch(IllegalArgumentException e){
	        		   System.err.println("Error, illegal action type '"+ actionString + "' of option -" + OPTION_ACTION);
	        		   printUsage(options);
	        	   }
	          }else{
	        	  System.err.println("Error, an action must be specified with the -" + OPTION_ACTION + " option.");
	        	  printUsage(options);
	          }
	          
	          if(cmd.hasOption(OPTION_TYPE) && cmd.getOptionValue(OPTION_TYPE) != null){
	        	   String typeString = cmd.getOptionValue(OPTION_TYPE);
	        	   try{
	        	     type = DataConfigurationManager.Type.valueOf(typeString.toUpperCase());
	        	   }catch(IllegalArgumentException e){
	        		   System.err.println("Error, illegal type '"+ typeString + "' of option -" + OPTION_TYPE);
	        		   printUsage(options);
	        	   }
	          }else{
	        	  System.err.println("Error, a type must be specified with the -" + OPTION_TYPE + " option.");
	        	  printUsage(options);
	          }

	          configFilePath = cmd.getOptionValue(OPTION_CONFIGFILE);
	          if(configFilePath == null){
	        	  configFilePath = "./wsraadmin.properties";
	          }

	          File f = new File(configFilePath);
	          if(!f.exists() || !f.canRead() || f.isDirectory()){
	        	  System.err.println("Error, configuration file " + configFilePath + " not found. Check that it exists and is readable.");
	        	  printUsage(options);
	          }
	          
	          
	          if(action == ActionType.ADD || action == ActionType.DUMP){
	        	  dataFilePath = cmd.getOptionValue(OPTION_DATAFILE);
	        	  if(dataFilePath != null){
	        		  f = new File(dataFilePath);
	        		  if(action == ActionType.ADD){
	        			  if(!f.exists() || !f.canRead() || f.isDirectory()){
	        				  System.err.println("Error, xml data file " + dataFilePath + " couldn't be found or read.");
	        				  printUsage(options);
	        			  }
	        		  }
	        	  }else{
	        		  System.err.println("Error, a path to the xml data file must be supplied with the  -"+ OPTION_DATAFILE + " option.");
	        		  printUsage(options);
	        	  }
	          }
	          
	          if(action == ActionType.CHANGESTATUS || action == ActionType.REMOVE){
	        	  name = cmd.getOptionValue(OPTION_NAME);
	        	  if(name == null){	        		  
	        		  System.err.println("Error, a name of the object to change status of must be supplied with the  -"+ OPTION_NAME + " option.");
	        		  printUsage(options);
	        	  }
	          }  	        	  	        
	          if(action == ActionType.CHANGESTATUS){
	        	  newstatus = cmd.getOptionValue(OPTION_NEWSTATUS);
	        	  if(newstatus == null){
	        		  System.err.println("Error, parameter " +OPTION_NEWSTATUS + " must be specified when changing status.");
			          printUsage(options); 
	        	  }
	        	  newstatus = newstatus.toUpperCase();
	        	  if(type == DataConfigurationManager.Type.ALL){
	        	    System.err.println("Error, type 'ALL' isn't supported for changestatus action.");
		        	printUsage(options);
	        	  }
	        	  if(type == DataConfigurationManager.Type.ORGANIZATIONS){
	        		  try{
	        			orgStatus  = OrganizationStatus.valueOf(newstatus);  
	        		  }catch(IllegalArgumentException e){
	        		    System.err.println("Error, unsupported status '" + newstatus + "' for type  "+ type );
	        		    printUsage(options);
	        		  }
	        	  }
	        	  if(type == DataConfigurationManager.Type.PRODUCTS){
	        		  try{
	        			  prodStatus  = ProductStatus.valueOf(newstatus);  
	        		  }catch(IllegalArgumentException e){
	        			  System.err.println("Error, unsupported status '" + newstatus + "' for type  "+ type );
	        			  printUsage(options);
	        		  }
	        	  }
	        	  if(type == DataConfigurationManager.Type.PRICES){
	        		  try{
	        			  priceStatus  = PricingStatus.valueOf(newstatus);  
	        		  }catch(IllegalArgumentException e){
	        			  System.err.println("Error, unsupported status '" + newstatus + "' for type  "+ type );
	        			  printUsage(options);
	        		  }
	        	  }
	        	  if(type == DataConfigurationManager.Type.PRODUCTMAPPINGS){	        		  
	        	      System.err.println("Error, cannot change status of product mappings.");
	        		  printUsage(options);	        		  
	        	  }

	          }
	          
	          if(action == ActionType.REMOVE){
	        	  if(type != DataConfigurationManager.Type.PRODUCTMAPPINGS){
	        		  System.err.println("Error, only product mappings can be removed.");
	        		  printUsage(options);
	        	  }
	          }

	      } catch (ParseException e) {
	    	  System.err.println( "Error occurred when parsing options.  Reason: " + e.getMessage() );
	    	  printUsage(options);
	      }

		  if(args.length < 1){
			  printUsage(options);
		  }
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {		
		int result = RETURN_BADARGUMENT;
		try {
			WSRAAdminCLI cli = new WSRAAdminCLI(args);
			result = cli.run();
		} catch (Exception e) {
			if(!e.getClass().getSimpleName().equals("ExitException")){
			  
			  System.err.println("Error occured during execution : " + e.getClass().getName());
			  if(e.getMessage() != null){
				  System.err.println("  Message : " + e.getMessage());
			  }
			  result = RETURN_ERROR;
			}
		}
		System.exit(result);
	}
	
	private int run() throws Exception {		
		
		// 1. set up db
		ConfigFileParser cfp = new ConfigFileParser(configFilePath);
		EntityManager workerEntityManager = getEntityManager(cfp);
		
		if(action == ActionType.ADD){
			System.out.println("Adding configuration from data file : " + dataFilePath);
			DataConfigurationManager dcm = new DataConfigurationManager(workerEntityManager);
			DataFileParser dfp = new DataFileParser(dataFilePath);
			dcm.storeConfiguration(type, dfp.getData(), includeUsers, false);
			closeDB(cfp,workerEntityManager);
			System.out.println("Configuration uploaded SUCCESSFULLY");
		}
        if(action == ActionType.DUMP){
        	System.out.println("Dumping configuration to data file : " + dataFilePath);
			DataConfigurationManager dcm = new DataConfigurationManager(workerEntityManager);
			BackupRestoreBean brb = dcm.dumpConfiguration(type, includeUsers, false);			
			DataFileParser dfp = new DataFileParser(brb);
			dfp.dumpData(dataFilePath);			
			System.out.println("Configuration dumped SUCCESSFULLY");
		}
        if(action == ActionType.CHANGESTATUS){
    		DBManagers db = new DBManagers(new WorkerConfig(),workerEntityManager,
    				new HashSet<Class<?>>(),new HashSet<Class<?>>(),null,null,""); 
			if(orgStatus != null){
				OrganizationDataBean odb = db.om.findOrganization(name);
				if(odb == null){
					System.out.println("Organization with name : " + name + " not found.");
				}else{
					odb.setStatus(orgStatus);
					workerEntityManager.getTransaction().begin();
					db.om.editOrganization(odb);
					workerEntityManager.getTransaction().commit();
					closeDB(cfp,workerEntityManager);
					System.out.println("Organization with name : " + name + " have status :" + orgStatus);
				}
			}
			if(priceStatus != null){
				PricingDataBean pdb = db.pm.findPrice(name);
				if(pdb == null){
					System.out.println("Price with priceclass : " + name + " not found.");
				}else{
					pdb.setStatus(priceStatus);
					workerEntityManager.getTransaction().begin();
					db.pm.editPrice(pdb);
					workerEntityManager.getTransaction().commit();
					closeDB(cfp,workerEntityManager);
					System.out.println("Organization with name : " + name + " have status : " + priceStatus);
				}
			}
			if(prodStatus != null){
				ProductDataBean pdb = db.pm.findProduct(name);
				if(pdb == null){
					System.out.println("Product with product number : " + name + " not found.");
				}else{
					pdb.setStatus(prodStatus);
					workerEntityManager.getTransaction().begin();
					db.pm.editProduct(pdb);
					workerEntityManager.getTransaction().commit();
					closeDB(cfp,workerEntityManager);
					System.out.println("Product with product number : " + name + " have status : " + prodStatus);
				}
			}
		}
        if(action == ActionType.REMOVE){
        	System.out.println("Removing product mapping : " + name);
			DataBankManager dbm = new DataBankManager(workerEntityManager);
			ProductMapper pMapper = new ProductMapper(dbm);			
			workerEntityManager.getTransaction().begin();
			pMapper.removeProductMapping(name);
			workerEntityManager.getTransaction().commit();
			closeDB(cfp,workerEntityManager);
			System.out.println("Product mapping removal was SUCCESSFUL");
			 
		}
		
       

		return RETURN_OK;
	}
	
    private void closeDB(ConfigFileParser cfp, EntityManager workerEntityManager) {
    	Properties p = cfp.getHibernateConfiguration();
		if(p.getProperty("hibernate.dialect") != null && p.getProperty("hibernate.dialect").trim().equals("org.hibernate.dialect.HSQLDialect")){

			workerEntityManager.getTransaction().begin();
			workerEntityManager.createNativeQuery("SHUTDOWN").executeUpdate();
			workerEntityManager.getTransaction().commit();
		}
		
	}

	private EntityManager getEntityManager(ConfigFileParser cfp) {
    	AnnotationConfiguration ac = new AnnotationConfiguration();
		Properties props = cfp.getHibernateConfiguration();
		
		ac.addAnnotatedClass(UserDataBean.class);
		ac.addAnnotatedClass(UserAliasDataBean.class);
		ac.addAnnotatedClass(OrganizationDataBean.class);
		ac.addAnnotatedClass(DataBankDataBean.class);
		ac.addAnnotatedClass(TokenDataBean.class);
		ac.addAnnotatedClass(AuthDataBean.class);
		ac.addAnnotatedClass(CertificateDataBean.class);
		ac.addAnnotatedClass(PricingDataBean.class);
		ac.addAnnotatedClass(ProductDataBean.class);
		ac.addAnnotatedClass(ProductsInOrganizationDataBean.class);
		ac.addAnnotatedClass(TransactionDataBean.class);
		ac.setProperties(props);
		SessionFactory sf = ac.buildSessionFactory();
		
		return EntityManagerUtil.createEntityManager(sf,PersistenceContextType.TRANSACTION,PersistenceUnitTransactionType.RESOURCE_LOCAL,true,new Properties());
	}





	private static void printUsage(Options options){
		HelpFormatter formatter = new HelpFormatter();
		
		formatter.printHelp( "Usage: java -jar wsraadmin.jar <options>\n", options );
		formatter.printOptions(new PrintWriter(System.out), 80, options, 2, 0);
		System.out.println("\n\n");
		System.out.println("Example usages:\n");
		System.out.println("  java -jar wsraadmin.jar -action add -type all -data <datafile.xml>");
		System.out.println("    Adds all sections of the data configuration to database.\n");
		System.out.println("  java -jar wsraadmin.jar -action add -type products -data <datafile.xml>");
		System.out.println("    Adds only the product configuration to database.\n");
		System.out.println("  java -jar wsraadmin.jar -action dump -type all -data <datafile.xml>");
		System.out.println("    Dumps all the supported configurations from database into xml file.\n");
		System.out.println("  java -jar wsraadmin.jar -action remove -type productmapping -name <productmappingname>");
		System.out.println("    Removes the specified product mapping from database.\n");
		System.out.println("  java -jar wsraadmin.jar -action changestatus -type organization -name <name> -newstatus ARCHIVED");
		System.out.println("    Changes the status of the organization with given name to ARCHIVED.\n");
		System.out.println("\n");
		System.exit(RETURN_BADARGUMENT);
	
	}


	

}
