package org.signserver.common.clusterclassloader;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.FlushModeType;
import javax.persistence.LockModeType;
import javax.persistence.Query;
import javax.transaction.RollbackException;
import javax.transaction.Synchronization;
import javax.transaction.SystemException;
import javax.transaction.xa.XAResource;

public class TEntityManager implements EntityManager {
	
	public boolean beginCalled = false;
	public boolean commitCalled = false;
	public boolean rollbackCalled = false;
	
	public boolean isActive = false;

	public void clear() {
	}

	
	public void close() {
	}

	
	public boolean contains(Object arg0) {		
		return false;
	}

	
	public Query createNamedQuery(String arg0) {		
		return null;
	}

	
	public Query createNativeQuery(String arg0) {		
		return null;
	}

	
	@SuppressWarnings("unchecked")
	public Query createNativeQuery(String arg0, Class arg1) {		
		return null;
	}

	
	public Query createNativeQuery(String arg0, String arg1) {		
		return null;
	}

	
	public Query createQuery(String arg0) {		
		return null;
	}

	
	public <T> T find(Class<T> arg0, Object arg1) {		
		return null;
	}

	
	public void flush() {	

	}

	
	public Object getDelegate() {
		
		return null;
	}

	
	public FlushModeType getFlushMode() {
		
		return null;
	}

	
	public <T> T getReference(Class<T> arg0, Object arg1) {
		
		return null;
	}

	
	public EntityTransaction getTransaction() {
		
		return new TTransaction();
	}

	
	public boolean isOpen() {
		
		return false;
	}

	
	public void joinTransaction() {
	}

	
	public void lock(Object arg0, LockModeType arg1) {		
	}

	
	public <T> T merge(T arg0) {
		
		return null;
	}

	
	public void persist(Object arg0) {
		

	}

	
	public void refresh(Object arg0) {
		

	}

	
	public void remove(Object arg0) {
		

	}

	
	public void setFlushMode(FlushModeType arg0) {
		

	}

	
	public class TTransaction implements EntityTransaction{

		
		public void commit() {
			commitCalled = true;
			
		}

		
		public boolean delistResource(XAResource arg0, int arg1)
				throws IllegalStateException, SystemException {
			
			return false;
		}

		
		public boolean enlistResource(XAResource arg0)
				throws RollbackException, IllegalStateException,
				SystemException {
			
			return false;
		}

		
		public int getStatus() throws SystemException {
			
			return 0;
		}

		
		public void registerSynchronization(Synchronization arg0)
				throws RollbackException, IllegalStateException,
				SystemException {
			
			
		}

		
		public void rollback() {
			rollbackCalled = true;			
		}

		
		public void setRollbackOnly(){			
			
		}

		public void begin(){
			beginCalled = true;
		}


		public void setTransactionTimeout(int arg0) throws SystemException {			
			
		}

		
		public boolean getRollbackOnly() {
			return false;
		}

		
		public boolean isActive() {
			return isActive;
		}
		
	}
}

