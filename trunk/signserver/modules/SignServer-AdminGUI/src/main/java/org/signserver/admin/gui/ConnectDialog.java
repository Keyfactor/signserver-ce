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

import java.awt.Component;
import java.awt.Frame;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.naming.NamingException;
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
import javax.swing.SwingUtilities;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.util.CertTools;
import org.signserver.admin.gui.SignServerAdminGUIApplication.Protocol;
import org.signserver.admin.gui.adminws.gen.AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.AdminWS;
import org.signserver.admin.gui.adminws.gen.AdminWSService;
import org.signserver.admin.gui.adminws.gen.Order;
import org.signserver.admin.gui.adminws.gen.QueryCondition;
import org.signserver.admin.gui.adminws.gen.QueryOrdering;
import org.signserver.common.ArchiveMetadata;
import org.signserver.common.util.ExceptionUtils;


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

    private final ConnectSettings settings;
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
    private static final Map<String, KeyStore> LOADED_KESTORES = new HashMap<>();

    /** Flag indicating if connection succeeded. */
    private boolean connected;

    /** Creates new form ConnectDialog. */
    public ConnectDialog(final Frame parent, final boolean modal,
            File connectFile, File defaultConnectFile, File baseDir, boolean wsFlag) {
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
            this.settings = loadSettingsFromFile(connectFile);
        } else if (LEGACY_DEFAULT_CONNECT_FILE.exists()) {
            this.settings = loadSettingsFromFile(LEGACY_DEFAULT_CONNECT_FILE);
        } else {
            this.settings = loadSettingsFromFile(defaultConnectFile);
        }
        if (wsFlag) {
            jRadioButtonRemote.setSelected(true);
            jRadioButtonLocalRemoteActionPerformed(null);
        }
        getRootPane().setDefaultButton(connectButton);
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
        buttonGroup1 = new javax.swing.ButtonGroup();
        jPanelRemote1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        urlTextField = new javax.swing.JTextField();
        jPanelRemote2 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        truststoreFilePathTextField = new javax.swing.JTextField();
        truststoreTypeComboBox = new javax.swing.JComboBox();
        truststoreFilePathLabel = new javax.swing.JLabel();
        truststoreBrowseButton = new javax.swing.JButton();
        truststorePasswordLabel = new javax.swing.JLabel();
        truststorePasswordField = new javax.swing.JPasswordField();
        jPanelRemote3 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        keystoreFilePathTextField = new javax.swing.JTextField();
        keystoreTypeComboBox = new javax.swing.JComboBox();
        jLabel9 = new javax.swing.JLabel();
        keystoreBrowseButton = new javax.swing.JButton();
        connectButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        defaultsButton = new javax.swing.JButton();
        jLabelConnectTo = new javax.swing.JLabel();
        jPanelButtons = new javax.swing.JPanel();
        jRadioButtonLocal = new javax.swing.JRadioButton();
        jRadioButtonRemote = new javax.swing.JRadioButton();
        jLabelProgress = new javax.swing.JLabel();

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

        jPanelRemote1.setBorder(javax.swing.BorderFactory.createTitledBorder("Web Service"));

        jLabel1.setText("URL:");

        javax.swing.GroupLayout jPanelRemote1Layout = new javax.swing.GroupLayout(jPanelRemote1);
        jPanelRemote1.setLayout(jPanelRemote1Layout);
        jPanelRemote1Layout.setHorizontalGroup(
            jPanelRemote1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelRemote1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(urlTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 480, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanelRemote1Layout.setVerticalGroup(
            jPanelRemote1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote1Layout.createSequentialGroup()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(urlTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanelRemote2.setBorder(javax.swing.BorderFactory.createTitledBorder("Truststore"));

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

        javax.swing.GroupLayout jPanelRemote2Layout = new javax.swing.GroupLayout(jPanelRemote2);
        jPanelRemote2.setLayout(jPanelRemote2Layout);
        jPanelRemote2Layout.setHorizontalGroup(
            jPanelRemote2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelRemote2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(truststorePasswordField, javax.swing.GroupLayout.DEFAULT_SIZE, 480, Short.MAX_VALUE)
                    .addComponent(truststoreFilePathLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 480, Short.MAX_VALUE)
                    .addGroup(jPanelRemote2Layout.createSequentialGroup()
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 208, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(truststoreTypeComboBox, 0, 260, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelRemote2Layout.createSequentialGroup()
                        .addComponent(truststoreFilePathTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 438, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(truststoreBrowseButton, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(truststorePasswordLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 215, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanelRemote2Layout.setVerticalGroup(
            jPanelRemote2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote2Layout.createSequentialGroup()
                .addGroup(jPanelRemote2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(truststoreTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststoreFilePathLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelRemote2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(truststoreFilePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(truststoreBrowseButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststorePasswordLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(truststorePasswordField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanelRemote3.setBorder(javax.swing.BorderFactory.createTitledBorder("Keystore"));

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

        javax.swing.GroupLayout jPanelRemote3Layout = new javax.swing.GroupLayout(jPanelRemote3);
        jPanelRemote3.setLayout(jPanelRemote3Layout);
        jPanelRemote3Layout.setHorizontalGroup(
            jPanelRemote3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanelRemote3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel9, javax.swing.GroupLayout.DEFAULT_SIZE, 480, Short.MAX_VALUE)
                    .addGroup(jPanelRemote3Layout.createSequentialGroup()
                        .addComponent(jLabel8, javax.swing.GroupLayout.PREFERRED_SIZE, 208, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keystoreTypeComboBox, 0, 260, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanelRemote3Layout.createSequentialGroup()
                        .addComponent(keystoreFilePathTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 438, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(keystoreBrowseButton, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        jPanelRemote3Layout.setVerticalGroup(
            jPanelRemote3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelRemote3Layout.createSequentialGroup()
                .addGroup(jPanelRemote3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(keystoreTypeComboBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel9)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanelRemote3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
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

        jLabelConnectTo.setText("Connect to:");

        jPanelButtons.setLayout(new java.awt.FlowLayout(0));

        buttonGroup1.add(jRadioButtonLocal);
        jRadioButtonLocal.setText("Local SignServer");
        jRadioButtonLocal.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButtonLocalRemoteActionPerformed(evt);
            }
        });
        jPanelButtons.add(jRadioButtonLocal);

        buttonGroup1.add(jRadioButtonRemote);
        jRadioButtonRemote.setText("Remote SignServer");
        jRadioButtonRemote.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButtonLocalRemoteActionPerformed(evt);
            }
        });
        jPanelButtons.add(jRadioButtonRemote);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanelRemote3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanelButtons, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 514, Short.MAX_VALUE)
                    .addComponent(jLabelConnectTo, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 514, Short.MAX_VALUE)
                    .addComponent(jPanelRemote2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jPanelRemote1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabelProgress, javax.swing.GroupLayout.DEFAULT_SIZE, 248, Short.MAX_VALUE)
                        .addGap(24, 24, 24)
                        .addComponent(defaultsButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
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
                .addComponent(jLabelConnectTo)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanelButtons, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanelRemote1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanelRemote2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanelRemote3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(connectButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(cancelButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(defaultsButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jLabelProgress, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {cancelButton, connectButton, defaultsButton});

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        connected = false;
        dispose();
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void saveSettings() {
        if (getProtocol() == Protocol.WS) {
            settings.setUrl(urlTextField.getText());
            settings.setTruststoreType((String) truststoreTypeComboBox.getSelectedItem());
            settings.setTruststoreFile(truststoreFilePathTextField.getText());
            settings.setTruststorePassword(truststorePasswordField.getPassword());
            settings.setKeystoreType((String) keystoreTypeComboBox.getSelectedItem());
            settings.setKeystoreFile(keystoreFilePathTextField.getText());
        }
        
        OutputStream out = null;
        try {
            out = new FileOutputStream(connectFile);
            Properties properties = new Properties();
            properties.put("protocol", getProtocol().name());
            if (settings.getUrl() != null) {
                properties.put("url", settings.getUrl());
            }
            if (settings.getTruststoreType() != null) {
                properties.put("truststoreType", settings.getTruststoreType());
            }
            if (settings.getTruststoreFile() != null) {
                properties.put("truststoreFile", settings.getTruststoreFile());
            }
            if (settings.getTruststorePassword() != null) {
                properties.put("truststorePassword", new String(settings.getTruststorePassword()));
            }
            if (settings.getKeystoreType() != null) {
                properties.put("keystoreType", settings.getKeystoreType());
            }
            if (settings.getKeystoreFile() != null) {
                properties.put("keystoreFile", settings.getKeystoreFile());
            }
            properties.store(out,
                    "Connect settings");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Could not save configuration:\n"
                    + ex.getMessage(), "Connect", JOptionPane.WARNING_MESSAGE);
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
        // Prepare for connecting
        ws = null;
        enableControls(false);
        jLabelProgress.setText("Connecting...");
        
        // Invoke later so the GUI gets a chance to gray out fields etc
        // XXX: Better would be if parts of this could be done in a background thread but making that work would require some work
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                saveSettings();
                if (jRadioButtonRemote.isSelected()) {
                    // WS connection
                    try {
                        connectOverWS();
                    } catch (Exception ex) {
                        LOG.error("Error connecting", ex);
                        JOptionPane.showMessageDialog(ConnectDialog.this, ExceptionUtils.catCauses(ex, "\n"), "Connect", JOptionPane.ERROR_MESSAGE);
                    }
                } else {
                    // EJB connection
                    try {
                        ws = new AdminLayerEJBImpl();
                        serverHost = "local";
                    } catch (NamingException ex) {
                        LOG.error("Startup error", ex);
                        JOptionPane.showMessageDialog(null,
                            "Startup failed. Is the application server running?\n"
                            + ex.getMessage(),
                            "SignServer Administration GUI startup",
                            JOptionPane.ERROR_MESSAGE);
                    }
                }

                // If we got this far connecting
                if (ws != null) {
                    try {
                        // Try accessing global configuration to see that we have connection and are authorized
                        ws.getGlobalConfiguration();

                        // All is fine
                        connected = true;
                        dispose();
                    } catch(AdminNotAuthorizedException_Exception ex) {
                        // Might still be an auditor so try querying
                        final QueryOrdering order = new QueryOrdering();
                        order.setColumn(AuditRecordData.FIELD_TIMESTAMP);
                        order.setOrder(Order.DESC);
                        
                        try {
                            ws.queryAuditLog(0, 1, Collections.<QueryCondition>emptyList(), Collections.singletonList(order));

                            // All is fine
                            connected = true;
                            dispose();
                        } catch (AdminNotAuthorizedException_Exception ex2) {
                            // Might still be an archive auditor so try querying
                            final QueryOrdering order2 = new QueryOrdering();
                            order2.setColumn(ArchiveMetadata.TIME);
                            order2.setOrder(Order.DESC);

                            try {
                                ws.queryArchive(0, 1, Collections.<QueryCondition>emptyList(), Collections.singletonList(order2), false);

                                // All is fine
                                connected = true;
                                dispose();
                            } catch (Throwable ex3) {
                                LOG.error("Error contacting SignServer", ex3);
                                JOptionPane.showMessageDialog(ConnectDialog.this, ExceptionUtils.catCauses(ex3, "\n"), "Connect", JOptionPane.ERROR_MESSAGE);
                            }
                        } catch (Throwable ex2) {
                            LOG.error("Error contacting SignServer", ex2);
                            JOptionPane.showMessageDialog(ConnectDialog.this, ExceptionUtils.catCauses(ex2, "\n"), "Connect", JOptionPane.ERROR_MESSAGE);
                        }
                    } catch (IllegalStateException ex) {
                        LOG.error("Error contacting SignServer", ex);
                        final StringBuilder message = new StringBuilder();

                        // Check if this is a case of JBoss not running
                        if (ex.getMessage() != null && ex.getMessage().contains("No EJB receiver")) {
                            message.append("SignServer not deployed or application server not running:\n");
                        }

                        message.append(ExceptionUtils.catCauses(ex, "\n"));
                        JOptionPane.showMessageDialog(ConnectDialog.this, message.toString(), "Connect", JOptionPane.ERROR_MESSAGE);
                    } catch (Throwable ex) {
                        LOG.error("Error contacting SignServer", ex);
                        JOptionPane.showMessageDialog(ConnectDialog.this, ExceptionUtils.catCauses(ex, "\n"), "Connect", JOptionPane.ERROR_MESSAGE);
                    }
                }

                // Restore for next retry
                enableControls(true);
                jLabelProgress.setText("");
            }
        });
    }
    
    private void connectOverWS() throws KeyStoreException, IOException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        String url = settings.getUrl();
        // Remove one trailing slash if specified
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        final String urlstr = url + WS_PATH;
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
            List<GUIKeyManager> guiKeyManagers = new LinkedList<>();
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

    private void jRadioButtonLocalRemoteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButtonLocalRemoteActionPerformed
        enableRemote(jRadioButtonRemote.isSelected());
    }//GEN-LAST:event_jRadioButtonLocalRemoteActionPerformed

    private void enableRemote(final boolean enable) {
        for (Component c : jPanelRemote1.getComponents()) {
            c.setEnabled(enable);
        }
        for (Component c : jPanelRemote2.getComponents()) {
            c.setEnabled(enable);
        }
        for (Component c : jPanelRemote3.getComponents()) {
            c.setEnabled(enable);
        }
        if (enable) {
            truststoreTypeComboBoxActionPerformed(null);
            urlTextField.requestFocusInWindow();
        }
    }
    
    private void enableControls(final boolean enable) {
        jRadioButtonLocal.setEnabled(enable);
        jRadioButtonRemote.setEnabled(enable);
        defaultsButton.setEnabled(enable);
        cancelButton.setEnabled(enable);
        connectButton.setEnabled(enable);
        jLabelConnectTo.setEnabled(enable);
        enableRemote(enable && jRadioButtonRemote.isSelected());
    }
    
    private ConnectSettings loadSettingsFromFile(final File file) {
        ConnectSettings sett = new ConnectSettings();
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            final Properties defaults = new Properties();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to load from file " + file.getAbsolutePath());
            }
            defaults.load(in);

            sett.setUrl(defaults.getProperty("url", DEFAULT_URL));
            sett.setTruststoreType(defaults.getProperty("truststoreType"));
            sett.setTruststoreFile(defaults.getProperty("truststoreFile"));
            if (defaults.getProperty("truststorePassword") != null) {
                sett.setTruststorePassword(defaults.getProperty("truststorePassword").toCharArray());
            }
            sett.setKeystoreType(defaults.getProperty("keystoreType"));
            sett.setKeystoreFile(defaults.getProperty("keystoreFile"));
            sett.setProtocol(Protocol.valueOf(defaults.getProperty("protocol", Protocol.EJB.name())));

            loadSettings(sett);
        } catch (IOException ex) {
            LOG.error("Load settings failed", ex);
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Reset defaults", JOptionPane.ERROR_MESSAGE);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
        return sett;
    }

    private void loadSettings(ConnectSettings settings) {
        urlTextField.setText(settings.getUrl());
        truststoreTypeComboBox.setSelectedItem(settings.getTruststoreType());
        truststoreFilePathTextField.setText(settings.getTruststoreFile());
        if (settings.getTruststorePassword() != null) {
            truststorePasswordField.setText(new String(settings.getTruststorePassword()));
        }
        keystoreTypeComboBox.setSelectedItem(settings.getKeystoreType());
        keystoreFilePathTextField.setText(settings.getKeystoreFile());
        if (Protocol.WS == settings.getProtocol()) {
            jRadioButtonRemote.setSelected(true);
        } else {
            jRadioButtonLocal.setSelected(true);
        }
        jRadioButtonLocalRemoteActionPerformed(null);
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
                        .append("library=").append(library.getAbsolutePath()).append("\n")
                        .append("showInfo=true")
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
                throw new KeyStoreException("Could not find constructor for keystore provider", nsme);
            } catch (InstantiationException ie) {
                throw new KeyStoreException("Failed to instantiate keystore provider", ie);
            } catch (ClassNotFoundException ncdfe) {
                throw new KeyStoreException("Unsupported keystore provider", ncdfe);
            } catch (InvocationTargetException ite) {
                throw new KeyStoreException("Could not initialize provider", ite);
            } catch (Exception e) {
                throw new KeyStoreException("Error", e);
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
    private javax.swing.ButtonGroup buttonGroup1;
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
    private javax.swing.JLabel jLabelConnectTo;
    private javax.swing.JLabel jLabelProgress;
    private javax.swing.JPanel jPanelButtons;
    private javax.swing.JPanel jPanelRemote1;
    private javax.swing.JPanel jPanelRemote2;
    private javax.swing.JPanel jPanelRemote3;
    private javax.swing.JRadioButton jRadioButtonLocal;
    private javax.swing.JRadioButton jRadioButtonRemote;
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

    /**
     * @return The selected protocol
     */
    public Protocol getProtocol() {
        final Protocol result;
        if (jRadioButtonLocal.isSelected()) {
            result = Protocol.EJB;
        } else {
            result = Protocol.WS;
        }
        return result;
    }

    /**
     * @return True if connecting went fine
     */
    public boolean isConnected() {
        return connected;
    }

}
