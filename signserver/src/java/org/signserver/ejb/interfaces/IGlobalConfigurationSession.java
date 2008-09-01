
package org.signserver.ejb.interfaces;

import javax.ejb.Local;
import javax.ejb.Remote;

import org.signserver.common.ResyncException;

/**
 * Common interface containing all the session bean methods
 */

public interface IGlobalConfigurationSession
{
   /**
    * Method setting a global configuration property. For node. prefix will the node id be appended.
    * @param scope one of the GlobalConfiguration.SCOPE_ constants
    * @param key of the property should not have any scope prefix, never null
    * @param value the value, never null.
    */
   void setProperty( java.lang.String scope,java.lang.String key,java.lang.String value );

   /**
    * Method used to remove a property from the global configuration.
    * @param scope one of the GlobalConfiguration.SCOPE_ constants
    * @param key of the property should start with either glob. or node., never null
    * @return true if removal was successful, othervise false.
    */
   boolean removeProperty( java.lang.String scope,java.lang.String key );

   /**
    * Method that returns all the global properties with Global Scope and Node scopes properties for this node.
    * @return A GlobalConfiguration Object, never null
    */
   org.signserver.common.GlobalConfiguration getGlobalConfiguration(  );

   /**
    * Help method that returns all worker, either signers or services defined in the global configuration.
    * @param workerType can either be GlobalConfiguration.WORKERTYPE_ALL, _SIGNERS or _SERVICES
    * @return A List if Integers of worker Ids, never null.
    */
   java.util.List<Integer> getWorkers( int workerType );

   /**
    * Method that is used after a database crash to restore all cached data to database.
    * @throws ResyncException if resync was unsuccessfull
    */
   void resync(  )
      throws org.signserver.common.ResyncException;

   /**
    * Method to reload all data from database.
    */
   public void reload(  );
   
   @Remote 
   public interface IRemote extends IGlobalConfigurationSession {
	   public static final String JNDI_NAME = "signserver/GlobalConfigurationSessionBean/remote";
   }

   @Local 
   public interface ILocal extends IGlobalConfigurationSession {
	   public static final String JNDI_NAME = "signserver/GlobalConfigurationSessionBean/local";
   }

}
