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

package org.signserver.rmiClient.impl;
 
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.ServerError;
import java.rmi.ServerException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.rmi.Server;
import org.signserver.rmi.TryAgainException;
import org.signserver.rmiClient.IError;
import org.signserver.rmiClient.IErrorCallback;
import org.signserver.rmiClient.ISigner;

import se.primeKey.pkcs15.PathForCTIAObj;
import se.primeKey.securityProvider.PrimeKey;
import se.primeKey.smartCard.CHVDialogExtended;
import se.primeKey.utils.CHVDialogExtendedFactoryImpl;
import se.primeKey.utils.PrimeLog;
import se.primeKey.utils.PrimeProperties;
import se.primeKey.utils.RMISSLClientSocketFactory;
import se.primeKey.utils.SSLContextForRMI;


/**
 * @author lars
 *
 */
public class SignerImpl implements ISigner {
    private int nrOfRunnerObjects = 0;
    private int nrOfRunnerObjectsHighScore = 0;
    private final ServerAdepter[] servers;
    private final IErrorCallback errorCallback;
    /**
     * @param serverNames
     * @param callback
     * @param kspwd
     * @param kpwd
     * @throws Exception
     */
    public SignerImpl( String[] serverNames, IErrorCallback callback,
                       String kspwd, String kpwd ) throws Exception {
        super();
        errorCallback = callback;
        servers = new ServerAdepter[serverNames.length];
        final String regPortS;
        {
            Properties prop = new PrimeProperties(this);
            final String keyStoreName = prop.getProperty("keyStoreName");
            regPortS = prop.getProperty("registryPortRMI");
            final KeyStore keyStore;
            final KeyStore trustedStore;
            final String keyPassword;
            if ( keyStoreName==null ) {
                keyStore = CardKeyStore.getIt(kspwd);
                trustedStore = KeyStore.getInstance("JKS");
                trustedStore.load( null, "foo123".toCharArray() );
                {
                    Certificate certChain[] =
                        keyStore.getCertificateChain(getPrivateKeyAlias(keyStore));
                    Certificate cert = certChain[certChain.length-1];
                    PrimeLog.debug("trusted cert: " + cert);
                    trustedStore.setCertificateEntry("dummy", cert);
                }
                keyPassword = null;
            } else {
                final String keyStorePassword;
                if ( kspwd==null ) {
                    keyStorePassword =prop.getProperty("keyStorePassword");
                    String tmpKeyPassword = prop.getProperty("keyPassword");
                    if ( tmpKeyPassword!=null )
                        keyPassword = tmpKeyPassword;
                    else
                        keyPassword = keyStorePassword;
                } else {
                    keyStorePassword = kspwd;
                    keyPassword = kpwd!=null ? kpwd : kspwd;
                }
                keyStore = KeyStore.getInstance("JKS");
                keyStore.load( getClass().getResourceAsStream(keyStoreName),
                               keyStorePassword.toCharArray() );
                trustedStore = keyStore;
            }
            SSLContextForRMI.setKeyStore( keyStore, trustedStore, getPrivateKeyAlias(keyStore), keyPassword );
        }
        for ( int i=0; i<servers.length; i++ )
            servers[i] = new ServerAdepter(serverNames[i], regPortS);
    }
    static private class CardKeyStore {
        static {
            Security.insertProviderAt( new PrimeKey(), 2 );
        }
        static private class MyDialog implements CHVDialogExtended {
            Map authObjs;
            final PrintStream printStream;
            final String password;
            MyDialog(String kspwd) {
                super();
                printStream = System.out;
                password = kspwd;
            }
            public String getCHV(int chvNumber) {
                if ( password==null ) {
                    {
                        final String label;
                        Integer key=new Integer(chvNumber);
                        if ( authObjs!=null )
                            label=((PathForCTIAObj)authObjs.get(key)).getLabel().toString();
                        else
                            label="PIN"+key;
                        
                        System.err.print("give PIN \""+label+"\" password: ");
                    }
                    try {
                        return new BufferedReader(new InputStreamReader(System.in)).readLine().toUpperCase();
                    } catch (IOException e){
                        return null;
                    }
                } else
                    return password.toUpperCase();
            }
            public void setAutObjs(Map m) {
                authObjs=m;
            }
            public void promtForCardInsertion() {
                printStream.println("please insert card.");
            }
            public void promtForCardRemoval() {
                printStream.println("please remove card.");
            }
            public void infoCardInserted() {
                printStream.println("card inserted");
            }
			public boolean isExiting() {
				// TODO Auto-generated method stub
				return false;
			}
        }
        static KeyStore getIt(String kspwd) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
            KeyStore keyStore = KeyStore.getInstance("PKCS15KS");
            keyStore.load( new CHVDialogExtendedFactoryImpl(new MyDialog(kspwd)) );
            return keyStore;
        }
    }
    private class ServerAdepter {
        private final String lookupArg;
        private final String hostAddress;
        private Server server;
        private MyRunner nextRun;
        private boolean isRunning;
        ServerAdepter(String serverName, String regPortS) throws UnknownHostException {
            hostAddress = InetAddress.getByName(serverName.trim()).getHostAddress();
            String tmpLookup = "rmi://"+hostAddress;
            if ( regPortS != null )
                tmpLookup += ":" + regPortS;
            tmpLookup += "/SignServer";
            lookupArg = tmpLookup;
            PrimeLog.debug("host address: " + hostAddress + ", lookup arg: " + lookupArg);
        }
        synchronized private void newRun(MyRunner runner) {
            if ( isRunning )
                nextRun = runner;
            else {
                isRunning = true;
                nextRun = null;
                new Thread(runner).start();
            }
        }
        synchronized private void runQuit() {
            if ( nextRun!=null ) {
                isRunning = true;
                new Thread(nextRun).start();
                nextRun = null;
            } else
                isRunning = false;
        }
        private abstract class MyRunner implements Runnable {
            public MyRunner() {
                super();
                synchronized( SignerImpl.this ) {
                    if (++nrOfRunnerObjects > nrOfRunnerObjectsHighScore) {
                        PrimeLog.debug("New nr of threads high score is " + nrOfRunnerObjects + " objects.");
                        nrOfRunnerObjectsHighScore = nrOfRunnerObjects;
                    }
                }
            }
            /* (non-Javadoc)
             * @see java.lang.Runnable#run()
             */
            public abstract void run();
            public void finalize() throws Throwable {
                synchronized( SignerImpl.this ) {
                    nrOfRunnerObjects--;
                }
                super.finalize();
            }
        }
        private class SignData extends MyRunner {
            final private int signerID;
            final private ISignRequest request;
            final private Result result;
            SignData( int id, ISignRequest req, Result r ) {
                signerID = id;
                request = req;
                result = r;
            }
            /* (non-Javadoc)
             * @see java.lang.Runnable#run()
             */
            public void run() {
                try {
                    startServer();
                    boolean notOK = true;
                    while( notOK )
                        try {
                            result.setResult(server.signData(signerID, request, getSessionID()));
                            notOK = false;
                        } catch( ServerException e ) {
                            if ( !(e.getCause() instanceof TryAgainException) )
                                throw e;
                            notOK = true;
                        }
                } catch (Throwable e) {
                    manageConnection(e);
                    result.reportError(e, hostAddress);
                } finally {
                    runQuit();
                }
            }
        }
        private class Ping extends MyRunner {
            final private Result result;
            Ping( Result r ) {
                result = r;
            }
            /* (non-Javadoc)
             * @see java.lang.Runnable#run()
             */
            public void run() {
                try {
                    startServer();
                    boolean notOK = true;
                    while( notOK )
                        try {
                            result.setResult(server.ping(getSessionID()));
                            notOK = false;
                        } catch( ServerException e ) {
                            if ( !(e.getCause() instanceof TryAgainException) )
                                throw e;
                            notOK = true;
                        }
                } catch (Throwable e) {
                    manageConnection(e);
                    result.reportError(e, hostAddress);
                } finally {
                    runQuit();
                }
            }
        }
        private void manageConnection(Throwable e) {
            if ( !(e instanceof ServerException || e instanceof ServerError) )
                server = null;
        }
        private byte[] getSessionID() throws Exception {
            byte[] sessionId;
            do { 
                server.wakeUp();
                sessionId = RMISSLClientSocketFactory.getSessionID(hostAddress);
            } while( sessionId == null );
            return sessionId;
        }

        private void startServer() throws MalformedURLException, RemoteException, NotBoundException {
            if ( server==null ) {
                server = (Server)Naming.lookup(lookupArg);
                PrimeLog.debug(lookupArg + " " + server);
            }
        }
        void signData(  int signerID, ISignRequest request, Result result ) {
    	    newRun( new SignData(signerID, request, result) );
    	}
        void ping( Result result ) {
    	    newRun( new Ping(result) );
    	}
    }

    private String getPrivateKeyAlias(KeyStore keyStore) throws KeyStoreException {
        Enumeration e = keyStore.aliases();
        while( e.hasMoreElements() ) {
            String alias = (String)e.nextElement();
            if ( alias.toLowerCase().indexOf("aut") >= 0 || !e.hasMoreElements() )
                return alias;
        }
        return null;
    }
    /* (non-Javadoc)
     * @see org.signserver.rmiClient.ISigner#signData(int, org.signserver.common.ISignRequest)
     */
    public ISignResponse signData(int signerID, ISignRequest request) {
        Result result = new Result(servers.length);
        for ( int i=0; i<servers.length; i++)
            servers[i].signData(signerID, request, result);
        return (ISignResponse)result.getResult();
    }
    /* (non-Javadoc)
     * @see org.signserver.rmiClient.ISigner#ping()
     */
    public String ping() {
        Result result = new Result(servers.length);
        for ( int i=0; i<servers.length; i++)
            servers[i].ping(result);
        return (String)result.getResult();
    }
    private class Result {
        /**
         * @author lars
         *
         */
        private class MyError implements IError {
            final private String host;
            final private Throwable throwed;
            final private String description;
            /**
             * 
             */
            public MyError(Throwable t, String h) {
                super();
                host = h;
                if ( t instanceof ServerException || t instanceof ServerError ) {
                    description = "Internal problem in server " + host + ". See throwed object.";
                    while ( t instanceof RemoteException ) {
                        Throwable tmp = t.getCause();
                        if ( tmp!=null )
                            t = tmp;
                        else
                            break;
                    }
                } else
                    description = "Communication problem with " + host + ". See throwed object";
                throwed = t;
            }

            /* (non-Javadoc)
             * @see org.signserver.rmiClient.IError#getThrowed()
             */
            public Throwable getThrowed() {
                return throwed;
            }

            /* (non-Javadoc)
             * @see org.signserver.rmiClient.IError#getDescription()
             */
            public String getDescription() {
                return description;
            }

            /* (non-Javadoc)
             * @see org.signserver.rmiClient.IError#getHostName()
             */
            public String getHostName() {
                return host;
            }

        }
        private Object value;
        private int nrOfServersWithNoError;
        /**
         * @param length
         */
        public Result(int length) {
            nrOfServersWithNoError = length;
        }
        synchronized void setResult( Object o ) {
            value = o;
            notifyAll();
        }
        synchronized void reportError(Throwable e, String host) {
            nrOfServersWithNoError--;
            errorCallback.exceptionThrowed(new MyError(e, host));
            if ( nrOfServersWithNoError <= 0 )
                notifyAll();
        }
        synchronized Object getResult() {
            while( value==null && nrOfServersWithNoError > 0 )
                try {
                    wait();
                } catch (InterruptedException e) {
                    new Error(e);
                }
            return value;
        }
    }
}
