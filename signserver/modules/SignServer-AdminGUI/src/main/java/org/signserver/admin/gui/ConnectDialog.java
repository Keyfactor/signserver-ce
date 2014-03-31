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
package org.signserver.admin.gui;

import java.awt.Frame;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.admin.gui.adminws.gen.AdminWS;
import org.signserver.admin.gui.adminws.gen.AdminWSService;


/**
 * Dialog for connection and authentication settings.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class ConnectDialog extends javax.swing.JDialog {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ConnectDialog.class);

    private static final String DEFAULT_URL = "https://localhost:8443/signserver";
    private static final String WS_PATH = "/AdminWSService/AdminWS?wsdl";

    private ConnectSettings settings;
    private AdminWS ws;
    private String serverHost;
    
    private static final File LEGACY_DEFAULT_CONNECT_FILE =
            new File("default_connect.properties");
    private static final File DEFAULT_CONNECT_FILE =
            new File("admingui_default.properties");
    private static final File CONNECT_FILE = new File("admingui.properties");

    private static final String TRUSTSTORE_TYPE_PEM = "PEM";
    private static final String TRUSTSTORE_TYPE_KEYSTORE = "Use keystore";

    private static final String[] TRUSTSTORE_TYPES = new String[] {
        TRUSTSTORE_TYPE_KEYSTORE,
        "JKS",
        "PKCS12",
        TRUSTSTORE_TYPE_PEM
    };

    private final File connectFile;
    private final File defaultConnectFile;
    private final File baseDir;
    
    private static final HostnameVerifier DEFAULT_HOSTNAME_VERIFIER = HttpsURLConnection.getDefaultHostnameVerifier();
    
    private X509Certificate adminCertificate;
    
    /** Cache of loaded (PKCS#11 currently only) keystores, to not create a new one when already logged in. */
    private static final Map<String, KeyStore> LOADED_KESTORES = new HashMap<String, KeyStore>();

    /** Creates new form ConnectDialog. */
    public ConnectDialog(final Frame parent, final boolean modal,
            File connectFile, File defaultConnectFile, File baseDir) {
        super(parent, modal);
        initComponents();
        truststoreTypeComboBox.setModel(
                new DefaultComboBoxModel(TRUSTSTORE_TYPES));

        if (defaultConnectFile == null) {
            defaultConnectFile = DEFAULT_CONNECT_FILE;
        }
        if (connectFile == null) {
            connectFile = CONNECT_FILE;
        }
        if (baseDir == null) {
            baseDir = connectFile.getParentFile().getParentFile();
        }
        this.connectFile = connectFile;
        this.defaultConnectFile = defaultConnectFile;
        this.baseDir = baseDir;

        if (connectFile.exists()) {
            loadSettingsFromFile(connectFile);
        } else if (LEGACY_DEFAULT_CONNECT_FILE.exists()) {
            loadSettingsFromFile(LEGACY_DEFAULT_CONNECT_FILE);
        } else {
            loadSettingsFromFile(defaultConnectFile);
        }
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        passwordPanel = new javax.swing.JPanel();
        passwordLabel = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        hostnameMismatchConfirmPanel = new javax.swing.JPanel();
        hostnameLabel = new javax.swing.JLabel();
        hostnameField = new javax.swing.JTextField();
        commonNameLabel = new javax.swing.JLabel();
        mismatchLabel = new javax.swing.JLabel();
        commonNameField = new javax.swing.JTextField();
        subjectAltNamesPanel = new javax.swing.JScrollPane();
        subjectAltNamesList = new javax.swing.JList();
        subjectAltNameLabel = new javax.swing.JLabel();
        confirmationLabel = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        urlTextField = new javax.swing.JTextField();
        jPanel2 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        truststoreFilePathTextField = new javax.swing.JTextField();
        truststoreTypeComboBox = new javax.swing.JComboBox();
        truststoreFilePathLabel = new javax.swing.JLabel();
        truststoreBrowseButton = new javax.swing.JButton();
        truststorePasswordLabel = new javax.swing.JLabel();
        truststorePasswordField = new javax.swing.JPasswordField();
        jPanel4 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        keystoreFilePathTextField = new javax.swing.JTextField();
        keystoreTypeComboBox = new javax.swing.JComboBox();
        jLabel9 = new javax.swing.JLabel();
        keystoreBrowseButton = new javax.swing.JButton();
        connectButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        defaultsButton = new javax.swing.JButton();

        passwordLabel.setText("Enter password:");

        passwordField.setText("jPasswordField1");

        javax.swing.GroupLayout passwordPanelLayout = new javax.swing.GroupLayout(passwordPanel);
        passwordPanel.setLayout(passwordPanelLayout);
        passwordPanelLayout.setHorizontalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(passwordField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE)
                    .addComponent(passwordLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 380, Short.MAX_VALUE))
                .addContainerGap())
        );
        passwordPanelLayout.setVerticalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passwordLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(passwordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        hostnameLabel.setText("Remote hostname used:");

        hostnameField.setEditable(false);
        hostnameField.setText("jTextField1");

        commonNameLabel.setText("Subject common name in remote certificate:");

        mismatchLabel.setText("Remote hostname doesn't match certificate");

        commonNameField.setEditable(false);
        commonNameField.setText("jTextField1");

        subjectAltNamesList.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Name", "Value" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        subjectAltNamesPanel.setViewportView(subjectAltNamesList);

        subjectAltNameLabel.setText("Subject alternative names:");

        confirmationLabel.setText("Do you want to connect anyway?");

        javax.swing.GroupLayout hostnameMismatchConfirmPanelLayout = new javax.swing.GroupLayout(hostnameMismatchConfirmPanel);
        hostnameMismatchConfirmPanel.setLayout(hostnameMismatchConfirmPanelLayout);
        hostnameMismatchConfirmPanelLayout.setHorizontalGroup(
            hostnameMismatchConfirmPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hostnameMismatchConfirmPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(hostnameMismatchConfirmPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(mismatchLabel)
                    .addComponent(hostnameLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(hostnameField, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(commonNameLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(commonNameField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(subjectAltNamesPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(subjectAltNameLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE)
                    .addComponent(confirmationLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 558, Short.MAX_VALUE))
                .addContainerGap())
        );
        hostnameMismatchConfirmPanelLayout.setVerticalGroup(
            hostnameMismatchConfirmPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(hostnameMismatchConfirmPanelLayout.createSequentialGroup()
                .addComponent(mismatchLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hostnameLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(hostnameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(commonNameLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(commonNameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(subjectAltNameLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(subjectAltNamesPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 162, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(confirmationLabel))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Connect to SignServer");
        setLocationByPlatform(true);

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Web Service"));

        jLabel1.setText("URL:");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(urlTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(urlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Truststore"));

        jLabel2.setText("Type:");

        truststoreTypeComboBox.setEditable(true);
        truststoreTypeComboBox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                truststoreTypeComboBoxActionPerformed(evt);
            }
        });

        truststoreFilePathLabel.setText("Truststore file path:");

        truststoreBrowseButton.setText("...");
        truststoreBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                truststoreBrowseButtonActionPerformed(evt);
            }
        });

        truststorePasswordLabel.setText("Password:");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(truststorePasswordField, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                    .addComponent(truststoreFilePathLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 208, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(truststoreTypeComboBox, 0, 254, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addComponent(truststoreFilePathTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 432, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(truststoreBrowseButton, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(truststorePasswordLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 215, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(truststoreTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststoreFilePathLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(truststoreFilePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(truststoreBrowseButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststorePasswordLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststorePasswordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder("Keystore"));

        jLabel8.setText("Type:");

        keystoreTypeComboBox.setEditable(true);
        keystoreTypeComboBox.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "JKS", "PKCS12", "Windows-MY", "PKCS11" }));

        jLabel9.setText("Keystore file path:");

        keystoreBrowseButton.setText("...");
        keystoreBrowseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                keystoreBrowseButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel8, javax.swing.GroupLayout.PREFERRED_SIZE, 208, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keystoreTypeComboBox, 0, 254, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addComponent(keystoreFilePathTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 432, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keystoreBrowseButton, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(keystoreTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel9)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(keystoreFilePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(keystoreBrowseButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        connectButton.setText("Connect");
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        defaultsButton.setText("Load defaults");
        defaultsButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                defaultsButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanel4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(defaultsButton)
                        .addGap(18, 18, 18)
                        .addComponent(cancelButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(connectButton)))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {cancelButton, connectButton});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(connectButton)
                    .addComponent(cancelButton)
                    .addComponent(defaultsButton))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        dispose();
        SignServerAdminGUIApplication.getApplication().exit(evt);
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
        settings = new ConnectSettings();
        settings.setUrl(urlTextField.getText());
        settings.setTruststoreType((String) truststoreTypeComboBox.getSelectedItem());
        settings.setTruststoreFile(truststoreFilePathTextField.getText());
        settings.setTruststorePassword(truststorePasswordField.getPassword());
        settings.setKeystoreType((String) keystoreTypeComboBox.getSelectedItem());
        settings.setKeystoreFile(keystoreFilePathTextField.getText());
//        settings.setKeystorePassword(keystorePasswordField.getPassword());

        try {
            Properties properties = new Properties();
            properties.put("url", settings.getUrl());
            properties.put("truststoreType", settings.getTruststoreType());
            properties.put("truststoreFile", settings.getTruststoreFile());
            properties.put("truststorePassword", new String(settings.getTruststorePassword()));
            properties.put("keystoreType", settings.getKeystoreType());
            properties.put("keystoreFile", settings.getKeystoreFile());
            properties.store(new FileOutputStream(connectFile),
                    "Connect settings");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Could not save configuration:\n"
                    + ex.getMessage(), "Connect", JOptionPane.WARNING_MESSAGE);
        }

        try {

            final String urlstr = settings.getUrl() + WS_PATH;
            serverHost = getSimplifiedHostAddress(settings.getUrl());

                KeyStore.CallbackHandlerProtection pp = new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

                    @Override
                    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                        for (Callback callback : callbacks) {
                            if (callback instanceof PasswordCallback) {
                                final PasswordCallback pc = (PasswordCallback) callback;
                                passwordLabel.setText(pc.getPrompt());
                                passwordField.setText("");
                                JOptionPane.showMessageDialog(
                                        ConnectDialog.this, passwordPanel,
                                        "Connect", JOptionPane.PLAIN_MESSAGE);
                                if (passwordField.getPassword() != null) {
                                    pc.setPassword(passwordField.getPassword());
                                }
                            } else {
                                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
                            }
                        }
                    }
                });

                final KeyStore keystore;
                final KeyManagerFactory kKeyManagerFactory = KeyManagerFactory.getInstance("SunX509");

                if (settings.getKeystoreType().contains("Windows")) {
                    // CSP
                    keystore = getLoadedKeystoreCSP(settings.getKeystoreType(), pp);
                    kKeyManagerFactory.init(keystore, null);
                } else if (settings.getKeystoreType().equals("PKCS11")) {
                    // PKCS11
                    keystore = getLoadedKeystorePKCS11("PKCS11",
                            getResolvedPath(settings.getKeystoreFile()),
                            settings.getKeystorePassword(), pp);
                    kKeyManagerFactory.init(keystore, null);
                } else {
                    // PKCS12 must use BC as provider but not JKS
                    final String provider;
                    if (settings.getKeystoreType().equals("PKCS12")) {
                        provider = "BC";
                    } else {
                        provider = null;
                }

                    // Ask for password
                    char[] authcode;
                    passwordLabel.setText("Enter password for keystore:");
                    passwordField.setText("");
                    JOptionPane.showMessageDialog(
                            ConnectDialog.this, passwordPanel,
                            "Connect", JOptionPane.PLAIN_MESSAGE);
                    if (passwordField.getPassword() != null) {
                        authcode = passwordField.getPassword();
                    } else {
                        authcode = null;
                    }
    
                    // Other keystores for instance JKS
                    keystore = getLoadedKeystore(getResolvedPath(settings.getKeystoreFile()),
                            authcode,
                            settings.getKeystoreType(),
                            provider);
                 
                    // JKS has password on keys and need to be inited with password
                    if (settings.getKeystoreType().equals("JKS")) {
                        kKeyManagerFactory.init(keystore, authcode);
                    } else {
                        kKeyManagerFactory.init(keystore, null);
                    }
                }

                final KeyStore keystoreTrusted;
                if (TRUSTSTORE_TYPE_PEM.equals(settings.getTruststoreType())) {
                    keystoreTrusted = KeyStore.getInstance("JKS");
                    keystoreTrusted.load(null, null);
                    final Collection certs = CertTools.getCertsFromPEM(
                            new FileInputStream(getResolvedPath(settings.getTruststoreFile())));
                    int i = 0;
                    for (Object o : certs) {
                        if (o instanceof Certificate) {
                            keystoreTrusted.setCertificateEntry("cert-" + i,
                                    (Certificate) o);
                            i++;
                        }
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loaded " + i + " certs to truststore");
                    }
                } else if (TRUSTSTORE_TYPE_KEYSTORE.equals(
                        settings.getTruststoreType())) {
                    keystoreTrusted = KeyStore.getInstance("JKS");
                    keystoreTrusted.load(null, null);
                    final Enumeration<String> aliases = keystore.aliases();
                    int i = 0;
                    while(aliases.hasMoreElements()) {
                        final String alias = aliases.nextElement();
                        if (keystore.isCertificateEntry(alias)) {
                            keystoreTrusted.setCertificateEntry(alias,
                                    keystore.getCertificate(alias));
                            i++;
                        }
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Loaded " + i + " certs to truststore");
                    }
                } else {
                    keystoreTrusted = KeyStore.getInstance(settings.getTruststoreType());
                    keystoreTrusted.load(new FileInputStream(getResolvedPath(settings.getTruststoreFile())), settings.getTruststorePassword());
                }

                final TrustManagerFactory tTrustManagerFactory = TrustManagerFactory.getInstance("SunX509");
                tTrustManagerFactory.init(keystoreTrusted);

                KeyManager[] keyManagers = kKeyManagerFactory.getKeyManagers();

        //        final SSLSocketFactory factory = sslc.getSocketFactory();
                List<GUIKeyManager> guiKeyManagers = new LinkedList<GUIKeyManager>();
                for (int i = 0; i < keyManagers.length; i++) {
                    if (keyManagers[i] instanceof X509KeyManager) {
                        final GUIKeyManager manager = new GUIKeyManager((X509KeyManager) keyManagers[i]);
                        keyManagers[i] = manager;
                        guiKeyManagers.add(manager);
                    }
                }

                // Now construct a SSLContext using these (possibly wrapped)
                // KeyManagers, and the TrustManagers. We still use a null
                // SecureRandom, indicating that the defaults should be used.
                SSLContext context = SSLContext.getInstance("TLS");
                
                if (LOG.isDebugEnabled()) {
                    StringBuilder buff = new StringBuilder();
                    buff.append("Available providers: \n");
                    for (Provider p : Security.getProviders()) {
                       buff.append(p).append("\n");
                    }
                    LOG.info(buff.toString());
                }
                
                context.init(keyManagers, tTrustManagerFactory.getTrustManagers(), new SecureRandom());

                // Finally, we get a SocketFactory, and pass it to SimpleSSLClient.
                SSLSocketFactory factory = context.getSocketFactory();
                
                HttpsURLConnection.setDefaultSSLSocketFactory(factory);
                
                final ConnectDialog parent = this;
                HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {

                    private X509Certificate verifiedCert = null;
                    
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        
                        if (!DEFAULT_HOSTNAME_VERIFIER.verify(hostname, session)) {
                            // don't show warning dialog more than once in a row for the same
                            // host cert
                            try {
                                final X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
                            
                                if (verifiedCert != null && verifiedCert.equals(cert)) {
                                    return true;
                                } else {
                                    final String dn = cert.getSubjectX500Principal().getName();
                                    final String cn = CertTools.getPartFromDN(dn, "CN");
                                    
                                    hostnameField.setText(hostname);
                                    commonNameField.setText(cn);

                                    final DefaultListModel listModel = new DefaultListModel();
                                    
                                    try {
                                        final Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
                                    
                                        if (altNames != null) {
                                            for (final List<?> altName : altNames) {
                                                final Integer type = (Integer) altName.get(0);
                                                final Object value = altName.get(1);
                                                final StringBuilder sb = new StringBuilder();
                                                
                                                if (type == 2) {
                                                    sb.append("DNS name: ");
                                                } else if (type == 7) {
                                                    sb.append("IP address: ");
                                                }
                                                sb.append(value.toString());
                                                listModel.addElement(sb.toString());
                                            }
                                        } else {
                                            subjectAltNamesList.setEnabled(false);
                                            listModel.addElement("No subject alternative names found in certificate");
                                        }
                                    } catch (CertificateParsingException e) {
                                        listModel.addElement("Failed to parse subject alternative names from certificate");
                                    }

                                    subjectAltNamesList.setModel(listModel);
                                    
                                    final int result = JOptionPane.showConfirmDialog(parent, hostnameMismatchConfirmPanel,
                                            "Hostname mismatch", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
                                    verifiedCert = cert;
                                    return result == JOptionPane.OK_OPTION;
                                }
                            } catch (SSLPeerUnverifiedException e) {
                                JOptionPane.showMessageDialog(parent, "Unable to verify peer",
                                        "Error", JOptionPane.ERROR_MESSAGE);
                                return false;
                            }
                        }
                        
                        return true;
                    }
                });

                AdminWSService service = new AdminWSService(
                        new URL(urlstr), new QName("http://adminws.signserver.org/", "AdminWSService"));
                ws = service.getAdminWSPort();
                
                // Search the key managers for the selected certificate
                for (GUIKeyManager manager : guiKeyManagers) {
                    adminCertificate = manager.getSelectedCertificate();
                    if (adminCertificate != null) {
                        break;
                    }
                }
                
                
            dispose();
        } catch (Exception ex) {
            LOG.error("Error connecting", ex);
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Connect", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_connectButtonActionPerformed

    private void truststoreBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_truststoreBrowseButtonActionPerformed
        final JFileChooser chooser = new JFileChooser();
        final File file = getResolvedPath(truststoreFilePathTextField.getText());
        chooser.setCurrentDirectory(file.getParentFile());
        chooser.setSelectedFile(file);
        final int result  = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            truststoreFilePathTextField.setText(
                    chooser.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_truststoreBrowseButtonActionPerformed

    private void keystoreBrowseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_keystoreBrowseButtonActionPerformed
        final JFileChooser chooser = new JFileChooser();
        final File file = getResolvedPath(keystoreFilePathTextField.getText());
        chooser.setCurrentDirectory(file.getParentFile());
        chooser.setSelectedFile(file);
        final int result  = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            keystoreFilePathTextField.setText(
                    chooser.getSelectedFile().getAbsolutePath());
        }
    }//GEN-LAST:event_keystoreBrowseButtonActionPerformed

    private void defaultsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_defaultsButtonActionPerformed
        loadSettingsFromFile(defaultConnectFile);
    }//GEN-LAST:event_defaultsButtonActionPerformed

    private void truststoreTypeComboBoxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_truststoreTypeComboBoxActionPerformed
        final String type = (String) truststoreTypeComboBox.getSelectedItem();
        truststorePasswordField.setEnabled(!TRUSTSTORE_TYPE_PEM.equals(type)
                && !TRUSTSTORE_TYPE_KEYSTORE.equals(type));
        truststorePasswordLabel.setEnabled(!TRUSTSTORE_TYPE_PEM.equals(type)
                && !TRUSTSTORE_TYPE_KEYSTORE.equals(type));
        truststoreFilePathLabel.setEnabled(
                !TRUSTSTORE_TYPE_KEYSTORE.equals(type));
        truststoreFilePathTextField.setEnabled(
                !TRUSTSTORE_TYPE_KEYSTORE.equals(type));
        truststoreBrowseButton.setEnabled(
                !TRUSTSTORE_TYPE_KEYSTORE.equals(type));
    }//GEN-LAST:event_truststoreTypeComboBoxActionPerformed

    private void loadSettingsFromFile(final File file) {
        try {
            final Properties defaults = new Properties();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to load from file " + file.getAbsolutePath());
            }
            defaults.load(new FileInputStream(file));

            ConnectSettings sett = new ConnectSettings();
            sett.setUrl(defaults.getProperty("url", DEFAULT_URL));
            sett.setTruststoreType(defaults.getProperty("truststoreType"));
            sett.setTruststoreFile(defaults.getProperty("truststoreFile"));
            if (defaults.getProperty("truststorePassword") != null) {
                sett.setTruststorePassword(defaults.getProperty("truststorePassword").toCharArray());
            }
            sett.setKeystoreType(defaults.getProperty("keystoreType"));
            sett.setKeystoreFile(defaults.getProperty("keystoreFile"));

            loadSettings(sett);
        } catch (IOException ex) {
            LOG.error("Load settings failed", ex);
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Reset defaults", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadSettings(ConnectSettings settings) {
        urlTextField.setText(settings.getUrl());
        truststoreTypeComboBox.setSelectedItem(settings.getTruststoreType());
        truststoreFilePathTextField.setText(settings.getTruststoreFile());
        if (settings.getTruststorePassword() != null) {
            truststorePasswordField.setText(new String(settings.getTruststorePassword())); // TODO
        }
        keystoreTypeComboBox.setSelectedItem(settings.getKeystoreType());
        keystoreFilePathTextField.setText(settings.getKeystoreFile());
//        if (settings.getKeystorePassword() != null) {
//            keystorePasswordField.setText(new String(settings.getKeystorePassword())); // TODO
//        }
    }

    public ConnectSettings getSettings() {
        return settings;
    }

    private static KeyStore getLoadedKeystorePKCS11(final String name, final File library, final char[] authCode, KeyStore.CallbackHandlerProtection callbackHandlerProtection) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final String keystoreName = library.getCanonicalPath();
        KeyStore keystore = LOADED_KESTORES.get(keystoreName);
        
        if (keystore == null) {
            final InputStream config = new ByteArrayInputStream(
                new StringBuilder().append("name=").append(name).append("\n")
                        .append("library=").append(library.getAbsolutePath())
                        .toString().getBytes());

            try {
                    Class<?> klass = Class.forName("sun.security.pkcs11.SunPKCS11");
                    // find constructor taking one argument of type InputStream
                    Class<?>[] parTypes = new Class[1];
                    parTypes[0] = InputStream.class;

                    Constructor<?> ctor = klass.getConstructor(parTypes);	        
                    Object[] argList = new Object[1];
                    argList[0] = config;
                    Provider provider = (Provider) ctor.newInstance(argList);

                    Security.addProvider(provider);

                    final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                            provider, callbackHandlerProtection);

                    keystore = builder.getKeyStore();
                    keystore.load(null, authCode);

                    final Enumeration<String> e = keystore.aliases();
                    while( e.hasMoreElements() ) {
                        final String keyAlias = e.nextElement();
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("******* keyAlias: " + keyAlias
                                    + ", certificate: "
                                    + ((X509Certificate) keystore.getCertificate(keyAlias))
                                        .getSubjectDN().getName());
                        }
                    }
                    LOADED_KESTORES.put(keystoreName, keystore);
            } catch (NoSuchMethodException nsme) {
                    throw new KeyStoreException("Could not find constructor for keystore provider.");
            } catch (InstantiationException ie) {
                    throw new KeyStoreException("Failed to instantiate keystore provider.");
            } catch (ClassNotFoundException ncdfe) {
                    throw new KeyStoreException("Unsupported keystore provider.");
            } catch (InvocationTargetException ite) {
                    throw new KeyStoreException("Could not initialize provider.");
            } catch (Exception e) {
                    throw new KeyStoreException("Error: " + e.getMessage());
            }
        }
        return keystore;
    }

    private static KeyStore getLoadedKeystoreCSP(final String storeType, KeyStore.CallbackHandlerProtection callbackHandlerProtection) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keystore;

        final KeyStore.Builder builder = KeyStore.Builder.newInstance(storeType,
                null, callbackHandlerProtection);

        keystore = builder.getKeyStore();
        keystore.load(null, null);

        final Enumeration<String> e = keystore.aliases();
        while( e.hasMoreElements() ) {
            final String keyAlias = e.nextElement();
            if (LOG.isDebugEnabled()) {
                LOG.debug("******* keyAlias: " + keyAlias
                        + ", certificate: "
                    + keystore.getCertificate(keyAlias));
            }

        }
        return keystore;
    }

    private KeyStore getLoadedKeystore(final File fileName, final char[] authcode, final String storeType,
            final String provider) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException {

        final KeyStore keystore;
        if (provider == null) {
            keystore = KeyStore.getInstance(storeType);
        } else {
            keystore = KeyStore.getInstance(storeType, provider);
        }

        InputStream in = null;
        try {
            if (fileName != null) {
                in = new FileInputStream(fileName);
            }
            keystore.load(in, authcode);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }

        return keystore;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelButton;
    private javax.swing.JTextField commonNameField;
    private javax.swing.JLabel commonNameLabel;
    private javax.swing.JLabel confirmationLabel;
    private javax.swing.JButton connectButton;
    private javax.swing.JButton defaultsButton;
    private javax.swing.JTextField hostnameField;
    private javax.swing.JLabel hostnameLabel;
    private javax.swing.JPanel hostnameMismatchConfirmPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JButton keystoreBrowseButton;
    private javax.swing.JTextField keystoreFilePathTextField;
    private javax.swing.JComboBox keystoreTypeComboBox;
    private javax.swing.JLabel mismatchLabel;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JLabel passwordLabel;
    private javax.swing.JPanel passwordPanel;
    private javax.swing.JLabel subjectAltNameLabel;
    private javax.swing.JList subjectAltNamesList;
    private javax.swing.JScrollPane subjectAltNamesPanel;
    private javax.swing.JButton truststoreBrowseButton;
    private javax.swing.JLabel truststoreFilePathLabel;
    private javax.swing.JTextField truststoreFilePathTextField;
    private javax.swing.JPasswordField truststorePasswordField;
    private javax.swing.JLabel truststorePasswordLabel;
    private javax.swing.JComboBox truststoreTypeComboBox;
    private javax.swing.JTextField urlTextField;
    // End of variables declaration//GEN-END:variables

    public AdminWS getWS() {
        return ws;
    }

    /**
     * @return Something to display as host address.
     */
    private String getSimplifiedHostAddress(String stringURL) {
        try {
            // Only use host:port and skip protocol and path
            URL url = new URL(stringURL);
            StringBuilder buff = new StringBuilder();
            buff.append(url.getHost());
            if (url.getPort() == -1) {
                if (url.getDefaultPort() != -1) {
                    buff.append(":").append(url.getDefaultPort());
                }
            } else {
                buff.append(":").append(url.getPort());
            }
            return buff.toString();
        } catch (MalformedURLException ex) {
            // Use the String in case it was not an correct URL
            return stringURL;
        }
    }

    /**
     * @return Address of the server to connect to in some human readable form.
     */
    public String getServerHost() {
        return serverHost;
    }

    /**
     * Resolves a possibly relative path against the base dir.
     * @param maybeRelativeFile Path that is either absolute or relative to the basedir
     * @return an absolute path
     */
    private File getResolvedPath(String maybeRelativeFile) {
        File file = new File(maybeRelativeFile);
        if (!file.isAbsolute()) {
            file = new File(baseDir, maybeRelativeFile);
        }
        return file;
    }

    /**
     * @return The selected certificate, if available otherwise null
     */
    public X509Certificate getAdminCertificate() {
        return adminCertificate;
    }

}
