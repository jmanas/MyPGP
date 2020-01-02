package gui;

import bc.*;
import crypto.GetPassword;
import crypto.SecureDeleter;
import exception.MyLogger;
import exception.PasswordCancelled;
import gui.imgs.Icons;
import keys.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;
import java.util.*;
import java.util.prefs.Preferences;

/**
 * @author Jose A. Manas
 * @version 30.12.2016
 */
public class MyPGP {
    private static final DataFlavor FILE_LIST_FLAVOR = DataFlavor.javaFileListFlavor;

    private static MyDirectoryChooser keyFileChooser;
    private static Directory directory;
    private static JButton processButton;
    private static JButton encryptButton;

    private static JFrame frame;
    private static SecureRandom random = new SecureRandom();

    private static DefaultMutableTreeNode secKeyBranch;
    private static DefaultMutableTreeNode listsBranch;
    private static DefaultMutableTreeNode pubKeyBranch;

    private static JTextArea logArea;
    private static JTree keysTree;

    private static MyFileChooser fch;
    private static JPanel keysPanel;

    private static NewDirectoryAction newDirectoryAction;
    private static RefreshAction refreshAction;
    private static SecureDeleteAction secureDeleteAction;

    private static Set<Object> selection = new HashSet<>();

    static {
        logArea = new JTextArea(20, 80);
        logArea.setWrapStyleWord(true);
        logArea.setLineWrap(true);
        log("java home: " + System.getProperty("java.home"));
        log("java version: " + System.getProperty("java.version"));
        log("HOME: " + Info.getHome());
        log("");
    }

    public static void start() {
        Security.addProvider(new BouncyCastleProvider());
        try {
            frame = new JFrame(Version.VERSION);
            frame.setIconImage(Icons.getPgpImage());
            frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

            init();
            frame.setJMenuBar(getMenuBar());
            frame.getContentPane().add(getPanel());
            frame.pack();

            GraphicsEnvironment graphicsEnvironment = GraphicsEnvironment.getLocalGraphicsEnvironment();
            Rectangle total = graphicsEnvironment.getMaximumWindowBounds();
            frame.setSize(total.width / 2, total.height / 2);

            frame.setExtendedState(Frame.MAXIMIZED_BOTH);

            frame.setVisible(true);
        } catch (Exception e) {
            MyLogger.dump(e, Version.VERSION);
        }
    }

    private static void init() {
        directory = Directory.load(Info.getHome());
        Info.loadInfo();
        log("");

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer(selection));
        keysTree.addMouseListener(new MyMouseListener(keysTree, selection));
        keysTree.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    Point point = evt.getLocation();
                    TreePath treePath = keysTree.getPathForLocation(point.x, point.y);
                    if (treePath == null) {
                        evt.rejectDrop();
                        return;
                    }

                    DefaultMutableTreeNode node = (DefaultMutableTreeNode) treePath.getLastPathComponent();
                    File dir = getDirectory(node);
                    if (dir == null) {
                        evt.rejectDrop();
                        return;
                    }
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        for (File srcFile : droppedFiles)
                            copy(dir, srcFile);
                        reloadKeys();
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });
    }

    private static void copy(File dir, File srcFile) {
        File dstFile = new File(dir, srcFile.getName());
        try (InputStream srcIS = new FileInputStream(srcFile);
             OutputStream dstOS = new FileOutputStream(dstFile);
        ) {
            byte[] buffer = new byte[4 * 1024];
            for (; ; ) {
                int n = srcIS.read(buffer);
                if (n < 0)
                    break;
                dstOS.write(buffer, 0, n);
            }
        } catch (IOException e) {
            MyLogger.dump(e, "copy");
        }
    }

    private static File getDirectory(DefaultMutableTreeNode node) {
        boolean publicbranch = false;
        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent()) {
            Object object = n.getUserObject();
            if (object == pubKeyBranch) {
                publicbranch = true;
                break;
            }
            if (object == secKeyBranch)
                return null;
            if (object == listsBranch)
                return null;
        }
        if (!publicbranch)
            return null;
        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent()) {
            try {
                Object object = n.getUserObject();
                if (object == pubKeyBranch)
                    return directory.getFile();
                Directory directory = (Directory) object;
                return directory.getFile();
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    private static void reloadKeys() {
        selection.clear();
        boolean secKeysExpanded = keysTree.isExpanded(new TreePath(secKeyBranch.getPath()));
        boolean listsExpanded = keysTree.isExpanded(new TreePath(listsBranch.getPath()));
        boolean directoryExpanded = keysTree.isExpanded(new TreePath(pubKeyBranch.getPath()));

        Set<Directory> expandedSecretKeys = getExpandedDirectories(secKeyBranch);
        Set<Directory> expandedPublicKeys = getExpandedDirectories(pubKeyBranch);

        KeyDB2.reset();
        KeyListDB.clear();
        directory = Directory.load(Info.getHome());
        Info.loadInfo();
        log("");

        keysTree = new JTree(mkKeysTree(directory));
        keysTree.setCellRenderer(new MyTreeRenderer(selection));
        keysTree.addMouseListener(new MyMouseListener(keysTree, selection));
//            expandAll(keysTree);
        for (Component component : keysPanel.getComponents()) {
            if (component instanceof JScrollPane)
                keysPanel.remove(component);
        }
        keysPanel.add(new JScrollPane(keysTree));
        if (secKeysExpanded)
            keysTree.expandPath(new TreePath(secKeyBranch.getPath()));
        if (listsExpanded)
            keysTree.expandPath(new TreePath(listsBranch.getPath()));
        if (directoryExpanded)
            keysTree.expandPath(new TreePath(pubKeyBranch.getPath()));

        expandKeyDirectories(expandedSecretKeys, secKeyBranch);
        expandKeyDirectories(expandedPublicKeys, pubKeyBranch);

        keysPanel.revalidate();
    }

    private static Set<Directory> getExpandedDirectories(DefaultMutableTreeNode branch) {
        Set<Directory> directorySet = new HashSet<>();
        int nChild = branch.getChildCount();
        for (int ch = 0; ch < nChild; ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) branch.getChildAt(ch);
            readExpandedDirectories(directorySet, child);
        }
        return directorySet;
    }

    private static void readExpandedDirectories(Set<Directory> directories, DefaultMutableTreeNode node) {
        Object object = node.getUserObject();
        if (!(object instanceof Directory))
            return;
        if (keysTree.isExpanded(new TreePath(node.getPath()))) {
            directories.add((Directory) object);
            for (int i = 0; i < node.getChildCount(); i++) {
                DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
                readExpandedDirectories(directories, child);
            }
        }
    }

    private static void expandKeyDirectories(Set<Directory> expandedKeys, DefaultMutableTreeNode branch) {
        int nChild = branch.getChildCount();
        for (int ch = 0; ch < nChild; ch++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) branch.getChildAt(ch);
            expandDirectories(expandedKeys, child);
        }
    }

    private static void expandDirectories(Set<Directory> directories, DefaultMutableTreeNode node) {
        Object object = node.getUserObject();
        if (!(object instanceof Directory))
            return;
        Directory directory = (Directory) object;
        if (!directories.contains(directory))
            return;
        keysTree.expandPath(new TreePath(node.getPath()));
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode child = (DefaultMutableTreeNode) node.getChildAt(i);
            expandDirectories(directories, child);
        }
    }

    private static void expandAll(JTree tree) {
        int row = 0;
        while (row < tree.getRowCount()) {
            tree.expandRow(row);
            row++;
        }
    }

    private static DefaultMutableTreeNode mkKeysTree(Directory directory) {
        DefaultMutableTreeNode keysTreeRoot = new DefaultMutableTreeNode(Text.get("keys"));

        secKeyBranch = new DefaultMutableTreeNode(Text.get("secret_keys"));
        keysTreeRoot.add(secKeyBranch);
        mkKeyTree(secKeyBranch, directory, false);

        listsBranch = new DefaultMutableTreeNode(Text.get("lists"));
        keysTreeRoot.add(listsBranch);
        for (KeyList list : KeyListDB.getListSet())
            listsBranch.add(mkTreeList(list));

        pubKeyBranch = new DefaultMutableTreeNode(directory.toString());
        keysTreeRoot.add(pubKeyBranch);
        mkKeyTree(pubKeyBranch, directory, true);

        return keysTreeRoot;
    }

    private static DefaultMutableTreeNode mkTreeList(KeyList list) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(list);
        for (Key key : list.getMembers(true))
            node.add(mkTreeKey(key));
        return node;
    }

    private static void mkKeyTree(
            DefaultMutableTreeNode root, Directory directory, boolean pub) {
        for (Key key : directory.getKeys()) {
            if (pub || key.isSecret())
                root.add(mkTreeKey(key));
        }
        for (Directory sub : directory.getSubdirs()) {
            DefaultMutableTreeNode newChild = mkKeyTree(sub, pub);
            if (newChild.getChildCount() > 0)
                root.add(newChild);
        }
    }

    private static DefaultMutableTreeNode mkKeyTree(
            Directory directory, boolean pub) {
        DefaultMutableTreeNode node = new DefaultMutableTreeNode(directory);
        for (Key key : directory.getKeys()) {
            if (pub | key.isSecret())
                node.add(mkTreeKey(key));
        }
        for (Directory sub : directory.getSubdirs()) {
            DefaultMutableTreeNode newChild = mkKeyTree(sub, pub);
            if (newChild.getChildCount() > 0)
                node.add(newChild);
        }
        return node;
    }

    private static DefaultMutableTreeNode mkTreeKey(Key key) {
        return mkTreeKey(key, new HashSet<Long>());
    }

    /**
     * Builds a tree for a key.
     * Signers are nested.
     *
     * @param key       key to display.
     * @param hierarchy keys already in the chain to avoid endless loops of mutual certifications.
     * @return tree structure for this key, and signing keys.
     */
    private static DefaultMutableTreeNode mkTreeKey(Key key, Set<Long> hierarchy) {
        DefaultMutableTreeNode keyNode = new DefaultMutableTreeNode(key);
        keyNode.add(new DefaultMutableTreeNode(key.getCorePresentation()));
        DefaultMutableTreeNode detailNode = new DefaultMutableTreeNode(key.getIdFingerprint());
        keyNode.add(detailNode);
        PGPPublicKey publicKey = key.getPublicKey();
        PGPPublicKey encryptingKey = key.getEncryptingKey();
        StringBuilder builder = new StringBuilder();
        builder.append(ToString.publicKey(publicKey.getAlgorithm()))
                .append(" (").append(getBits(publicKey)).append(")");
        if (encryptingKey != null)
            builder.append(" / ")
                    .append(ToString.publicKey(encryptingKey.getAlgorithm()))
                    .append(" (").append(getBits(encryptingKey)).append(")");
        detailNode.add(new DefaultMutableTreeNode(builder.toString()));

        detailNode.add(mkEncryptionAlgorithms(publicKey));

        for (File file : key.getFileList())
            keyNode.add(new DefaultMutableTreeNode(fromHome(file)));

        List<Long> signerList = key.getSigIds();
        if (signerList.size() > 0) {
            Set<Long> extHierarchy = new HashSet<>(hierarchy);
            extHierarchy.addAll(signerList);
            DefaultMutableTreeNode signers = new DefaultMutableTreeNode(Text.get("signers") + " ...");
            keyNode.add(signers);
            for (Long sid : signerList) {
                Key signerKey = KeyDB2.getKey(sid);
                if (signerKey == null)
                    signers.add(new DefaultMutableTreeNode(String.format("[%s]", Key.mkId8(sid))));
                else if (hierarchy.contains(sid))
                    signers.add(new DefaultMutableTreeNode(String.format("[%s] %s", Key.mkId8(sid), signerKey.toString())));
                else
                    signers.add(mkTreeKey(signerKey, extHierarchy));
            }
        }
        return keyNode;
    }

    private static String fromHome(File file) {
        try {
            String path = file.getCanonicalPath();
            String homePath = Info.getHome().getCanonicalPath();
            if (path.startsWith(homePath))
                return path.substring(homePath.length() + 1);
            return path;
        } catch (IOException e) {
            return file.getAbsolutePath();
        }
    }

    private static DefaultMutableTreeNode mkEncryptionAlgorithms(PGPPublicKey publicKey) {
        // encryption algorithms
        int[] algos = AlgorithmSelection.getPreferredEncryptionAlgos(publicKey);
        if (algos == null || algos.length <= 0)
            return null;
        StringBuilder sb = new StringBuilder(Text.get("encrypt"));
        for (int i = 0; i < algos.length; i++) {
            if (i == 0)
                sb.append(": ");
            else
                sb.append(", ");
            sb.append(ToString.symmetricKey(algos[i]));
        }
        return new DefaultMutableTreeNode(sb.toString());
    }

    private static int getBits(PGPPublicKey publicKey) {
        int bitStrength = publicKey.getBitStrength();
        if (bitStrength > 0)
            return bitStrength;
        PublicKeyPacket packet = publicKey.getPublicKeyPacket();
        BCPGKey key = packet.getKey();

        X9ECParameters parameters = getECParameters(key);
        if (parameters != null) {
            ECCurve curve = parameters.getCurve();
            return curve.getFieldSize();
        }
        return 0;
    }

    private static X9ECParameters getECParameters(BCPGKey key) {
        ASN1ObjectIdentifier curveOID = null;
        if (key instanceof ECDSAPublicBCPGKey) {
            ECDSAPublicBCPGKey ecKey = (ECDSAPublicBCPGKey) key;
            curveOID = ecKey.getCurveOID();
        }
        if (key instanceof ECDHPublicBCPGKey) {
            ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey) key;
            curveOID = ecKey.getCurveOID();
        }
        if (curveOID == null)
            return null;
        X9ECParameters parameters;
        parameters = NISTNamedCurves.getByOID(curveOID);
        if (parameters != null)
            return parameters;
        parameters = SECNamedCurves.getByOID(curveOID);
        if (parameters != null)
            return parameters;
        parameters = CustomNamedCurves.getByOID(curveOID);
        if (parameters != null)
            return parameters;
        return null;
    }

    public static Component getPanel() {
        Preferences preferences = Preferences.userRoot().node("mypgp");

        fch = new MyFileChooser();
        fch.setPreferences(preferences);
        String wd = preferences.get("working_dir", null);
        if (wd != null) {
            File wdFile = new File(wd);
            if (wdFile.exists() && wdFile.isDirectory())
                fch.setDirectory(wdFile);
        }

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        processButton = new JButton(Text.get("decrypt_verify"));
        encryptButton = new JButton(Text.get("encrypt_sign"));
        buttons.add(processButton);
        buttons.add(encryptButton);

        processButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                decrypt_verify_Selection(files);
                fch.rescanCurrentDirectory();
                fch.setSelectedFiles(files);
            }
        });
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File[] files = fch.getSelectedFiles();
                if (files == null || files.length == 0)
                    return;
                encrypt_sign_Selection(files);
                fch.rescanCurrentDirectory();
                fch.setSelectedFiles(files);
            }
        });

        processButton.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        decrypt_verify_Selection(droppedFiles.toArray(new File[droppedFiles.size()]));
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });
        encryptButton.setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = evt.getTransferable();
                    if (transferable.isDataFlavorSupported(FILE_LIST_FLAVOR)) {
                        List<File> droppedFiles = (List<File>) transferable.getTransferData(FILE_LIST_FLAVOR);
                        encrypt_sign_Selection(droppedFiles.toArray(new File[droppedFiles.size()]));
                    }
                } catch (Exception ex) {
                    MyLogger.dump(ex, Text.get("drop"));
                }
            }
        });

        keysPanel = new JPanel(new BorderLayout());
        keysPanel.add(new JScrollPane(keysTree));

        JPanel dirPanel = new JPanel(new BorderLayout());
        JToolBar rightToolBar = new JToolBar();
        rightToolBar.setFloatable(false);
        newDirectoryAction = new NewDirectoryAction();
        rightToolBar.add(newDirectoryAction);
        rightToolBar.addSeparator(new Dimension(5, 5));
        refreshAction = new RefreshAction();
        rightToolBar.add(refreshAction);
        rightToolBar.addSeparator(new Dimension(5, 5));
        secureDeleteAction = new SecureDeleteAction();
        rightToolBar.add(secureDeleteAction);
        dirPanel.add(rightToolBar, BorderLayout.NORTH);
        dirPanel.add(fch, BorderLayout.CENTER);
        dirPanel.add(buttons, BorderLayout.SOUTH);

        SpringLayout layout = new SpringLayout();
        JPanel panel = new JPanel(layout);

        panel.add(keysPanel);
        SpringLayout.Constraints keysPanelConstraints = layout.getConstraints(keysPanel);
        keysPanelConstraints.setX(Spring.constant(0));
        keysPanelConstraints.setY(Spring.constant(0));

        panel.add(dirPanel);
        SpringLayout.Constraints dirPanelConstraints = layout.getConstraints(dirPanel);
        dirPanelConstraints.setX(keysPanelConstraints.getConstraint("East"));
        dirPanelConstraints.setY(Spring.constant(0));

        JScrollPane logAreaPane = new JScrollPane(logArea);
        panel.add(logAreaPane);
        SpringLayout.Constraints logAreaConstraints = layout.getConstraints(logAreaPane);
        logAreaConstraints.setX(dirPanelConstraints.getConstraint("West"));
        logAreaConstraints.setY(dirPanelConstraints.getConstraint("South"));
        logAreaConstraints.setWidth(dirPanelConstraints.getWidth());

        Spring totalHeight = Spring.sum(
                dirPanelConstraints.getHeight(),
                logAreaConstraints.getHeight());
        keysPanelConstraints.setHeight(totalHeight);

        SpringLayout.Constraints windowConstraints = layout.getConstraints(panel);
        windowConstraints.setConstraint("East", dirPanelConstraints.getConstraint("East"));
        windowConstraints.setConstraint("South", keysPanelConstraints.getConstraint("South"));

        return panel;
    }

    private static void decrypt_verify_Selection(File[] files) {
        Map<Long, char[]> passwords = new HashMap<>();
        try {
            for (File blackFile : files) {
                try {
                    BcUtilsFiles.process(blackFile, passwords);
                } catch (PasswordCancelled ignored) {
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), Text.get("process"));
                } catch (Exception e) {
                    MyLogger.dump(e, Text.get("process"));
                }
            }
        } finally {
            for (char[] password : passwords.values())
                clearPassword(password);
        }
    }

    private static void encrypt_sign_Selection(File[] files) {
        String action = Text.get("encrypt_sign");
        List<Key> encryptingKeys = getEncryptingKeys();
        List<Key> signingKeys = getSigningKeys();
        if (encryptingKeys.size() + signingKeys.size() == 0)
            return;

        log1(action);
        Map<Key, char[]> passwords = new HashMap<>();
        if (signingKeys.size() > 0) {
            try {
                for (Key signingKey : signingKeys) {
                    char[] password = GetPassword.getInstance().getDecryptionPassword(signingKey.toString());
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }
        }

        try {
            boolean armor = ArmorPanel.getArmor(action, true, ".pgp");
            for (File redFile : files) {
                log(action + " " + redFile.getName());
                try {
                    if (encryptingKeys.size() > 0 && signingKeys.size() > 0)
                        BcUtilsFiles.encrypt_sign(redFile, signingKeys, encryptingKeys, passwords, armor);
                    if (encryptingKeys.size() > 0 && signingKeys.size() == 0)
                        BcUtilsFiles.encrypt(redFile, encryptingKeys, armor);
                    if (encryptingKeys.size() == 0 && signingKeys.size() > 0)
                        BcUtilsFiles.sign(redFile, signingKeys, passwords, armor);
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), action);
                } catch (Exception e) {
                    MyLogger.dump(e, action);
                }
            }
        } catch (PasswordCancelled ignored) {
        }

        for (char[] password : passwords.values())
            clearPassword(password);
    }

    private static JMenuBar getMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu keyMenu = new JMenu(Text.get("keys"));
        menuBar.add(keyMenu);
        keyMenu.add(new GenerateKeyAction());
        keyMenu.add(new AliasKeyAction(true));
        keyMenu.add(new CopyKeyAction(true));
        keyMenu.add(new ExportKeyAction(true));
        keyMenu.add(new ReloadKeysAction());
        keyMenu.add(new FileMapAction());

        JMenu listsMenu = new JMenu(Text.get("lists"));
        menuBar.add(listsMenu);
        listsMenu.add(new AddKeyListAction(true));
        listsMenu.add(new RemoveKeyListAction(true));
        listsMenu.add(new NewListAction());
        listsMenu.add(new RemoveListAction(true));

        JMenu clipMenu = new JMenu(Text.get("clipboard"));
        menuBar.add(clipMenu);
        clipMenu.add(new ViewClipAction());
        clipMenu.add(new EncryptClipAction());
        clipMenu.add(new SignClipAction());
        clipMenu.add(new EncryptSignClipAction());
        clipMenu.add(new DecryptClipAction());

        JMenu fileMenu = new JMenu(Text.get("files"));
        menuBar.add(fileMenu);
        fileMenu.add(new EncryptAction());
        fileMenu.add(new SignAction());
        fileMenu.add(new EncryptSignAction());
        fileMenu.add(new DecryptAction());
        fileMenu.add(new SecureDeleteAction());

        JMenu langMenu = new JMenu(Text.get("language"));
        menuBar.add(langMenu);
        for (final String[] pair : Text.getLanguages()) {
            JMenuItem item = new JMenuItem(pair[1]);
            item.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    Text.setLocale(pair[0]);
                    Info.saveLanguage();
                    reloadKeys();
                    newDirectoryAction.putValue(Action.NAME, Text.get("new_directory"));
                    refreshAction.putValue(Action.NAME, Text.get("refresh"));
                    secureDeleteAction.putValue(Action.NAME, Text.get("delete"));
                    processButton.setText(Text.get("decrypt_verify"));
                    encryptButton.setText(Text.get("encrypt_sign"));
                    frame.setJMenuBar(getMenuBar());
                    frame.validate();
                }
            });
            langMenu.add(item);
        }

        return menuBar;
    }

    private static List<Key> getSecretKeys(boolean checked) {
        List<Key> keys = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths == null || paths.isEmpty())
            return keys;

        for (TreePath path : paths) {
            if (path.getPathComponent(1) != secKeyBranch)
                continue;
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == Key.class)
                keys.add((Key) object);
        }
        return keys;
    }

    private static Collection<TreePath> getSelectionPaths(boolean checked) {
        if (!checked)
            return Arrays.asList(keysTree.getSelectionPaths());

        Collection<TreePath> all = new HashSet<>();
        for (Object x : selection) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) x;
            if (selection.contains(node)) {
                TreePath path = new TreePath(node.getPath());
                all.add(path);
            }
        }
        return all;
    }

    private static List<Key> getSigningKeys() {
        List<Key> keys = new ArrayList<>();
        for (Key key : getSecretKeys(true)) {
            if (key.getSigningKey() != null)
                keys.add(key);
        }
        log(Text.get("sign"));
        for (Key key : keys)
            log2(key.toString());
        return keys;
    }

    private static List<Key> getPublicKeys(boolean checked) {
        List<Key> keys = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths == null || paths.isEmpty())
            return keys;

        for (TreePath path : paths) {
            if (path.getPathComponent(1) == secKeyBranch)
                continue;
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == Key.class) {
                keys.add((Key) object);
            } else if (object.getClass() == KeyList.class) {
                KeyList list = (KeyList) object;
                keys.addAll(list.getMembers(false));

            } else if (object.getClass() == Directory.class) {
                Directory directory = (Directory) object;
                directory.addKeys(keys);

            }
        }
        return keys;
    }

    private static List<KeyList> getKeyLists(boolean checked) {
        List<KeyList> keyLists = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths == null || paths.isEmpty())
            return keyLists;

        for (TreePath path : paths) {
            try {
                if (path.getPathComponent(1) != listsBranch)
                    continue;
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                keyLists.add((KeyList) node.getUserObject());
            } catch (Exception ignored) {
            }
        }
        return keyLists;
    }

    private static List<Key> getEncryptingKeys() {
        List<Key> keys = new ArrayList<>();
        for (Key key : getPublicKeys(true)) {
            if (key.getEncryptingKey() != null)
                keys.add(key);
        }
        log(Text.get("encrypt"));
        for (Key key : keys)
            log2(key.toString());
        return keys;
    }

    private static List<DefaultMutableTreeNode> getLists(boolean checked) {
        List<DefaultMutableTreeNode> lists = new ArrayList<>();
        Collection<TreePath> paths = getSelectionPaths(checked);
        if (paths == null || paths.isEmpty())
            return lists;

        for (TreePath path : paths) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
            Object object = node.getUserObject();
            if (object.getClass() == KeyList.class)
                lists.add(node);
        }
        return lists;
    }

    public static void log1(String msg) {
        log("");
        log(msg);
    }

    public static void log2(String msg) {
        log("  " + msg);
    }

    public static void log(String line) {
        if (line == null)
            return;
        if (line.length() > 0)
            logArea.append(line);
        logArea.append("\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    static Window getWindow() {
        return frame;
    }

    public static void ignore(String absolutePath) {
        if (absolutePath.toLowerCase().endsWith(".jar"))
            return;
        log(Text.get("skip") + " " + absolutePath);
    }

    static DefaultMutableTreeNode getSecKeyBranch() {
        return secKeyBranch;
    }

    private static class EncryptAction
            extends AbstractAction {
        private EncryptAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("encrypt"));
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;
            encrypt_sign_Selection(files);
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private static class SignAction
            extends AbstractAction {
        private SignAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("sign");

            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.isEmpty()) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }

            boolean armor;
            Map<Key, char[]> passwords = new HashMap<>();
            try {
                armor = ArmorPanel.getArmor(action, false, ".sig");
                for (Key signingKey : signingKeys) {
                    char[] password = GetPassword.getInstance().getDecryptionPassword(signingKey.toString());
                    passwords.put(signingKey, password);
                }
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }

            for (File redFile : files) {
                try {
                    log1(action + " " + redFile.getName());
                    BcUtilsFiles.sign(redFile, signingKeys, passwords, armor);
                } catch (PGPException e) {
                    log2(e.toString());
                    if (e.getUnderlyingException() != null)
                        MyLogger.dump(e.getUnderlyingException(), action);
                } catch (Exception e) {
                    MyLogger.dump(e, action);
                }
            }

            for (char[] password : passwords.values())
                clearPassword(password);
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private static class EncryptSignAction
            extends AbstractAction {
        private EncryptSignAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            encrypt_sign_Selection(files);

            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private static class DecryptAction
            extends AbstractAction {
        private DecryptAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("decrypt_verify"));
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;
            decrypt_verify_Selection(files);
            fch.rescanCurrentDirectory();
            fch.setSelectedFiles(files);
        }
    }

    private static class ViewClipAction
            extends AbstractAction {
        private ViewClipAction() {
            super(Text.get("view"));
        }

        public void actionPerformed(ActionEvent event) {
            try {
                String text = MyClipBoard.readString();
                JTextArea area = new JTextArea(text, 40, 80);
                area.setWrapStyleWord(true);
                area.setLineWrap(true);
                JScrollPane pane = new JScrollPane(area);
                JDialog dialog = new JDialog((Window) null, Text.get("clipboard"));
                dialog.add(pane);
                dialog.pack();
                dialog.setVisible(true);
            } catch (Exception e) {
                MyLogger.dump(e, Text.get("view"));
            }
        }
    }

    private static class EncryptClipAction
            extends AbstractAction {
        private EncryptClipAction() {
            super(Text.get("encrypt"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("encrypt");

            List<Key> encryptingKeys = getEncryptingKeys();
            if (encryptingKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            try {
                log(action + " " + Text.get("clipboard"));
                String redText = MyClipBoard.readString();
                String blackText = BcUtilsClipboard.encrypt(redText, encryptingKeys);
                MyClipBoard.write(blackText);
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class SignClipAction
            extends AbstractAction {
        private SignClipAction() {
            super(Text.get("sign"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("sign");

            List<Key> signingKeys = getSigningKeys();
            if (signingKeys.size() != 1) {
                log("%s: %d%n", Text.get("secret_keys"), signingKeys.size());
                return;
            }
            Key signingKey = signingKeys.get(0);
            try {
                log(action + " " + Text.get("clipboard"));
                String redText = MyClipBoard.readString();
                char[] password = GetPassword.getInstance().getDecryptionPassword(action);
                String blackText = BcUtilsClipboard.clearsign(redText, signingKey, password);
                MyClipBoard.write(blackText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class EncryptSignClipAction
            extends AbstractAction {
        private EncryptSignClipAction() {
            super(Text.get("encrypt_sign"));
        }

        public void actionPerformed(ActionEvent event) {
            encrypt_sign_Clipboard(MyClipBoard.readString());
        }
    }

    private static void encrypt_sign_Clipboard(String redText) {
        String action = Text.get("encrypt_sign");
        List<Key> encryptingKeys = getEncryptingKeys();
        List<Key> signingKeys = getSigningKeys();
        if (encryptingKeys.size() + signingKeys.size() == 0)
            return;

        log1(action);
        Key signingKey = null;
        char[] password = new char[0];
        if (signingKeys.size() > 0) {
            try {
                signingKey = signingKeys.get(0);
                password = GetPassword.getInstance().getDecryptionPassword(Text.get("sign"));
            } catch (PasswordCancelled passwordCancelled) {
                return;
            }
        }

        try {
            String blackText = "";
            log(action + " " + Text.get("clipboard"));
            if (encryptingKeys.size() > 0 && signingKeys.size() > 0)
                blackText = BcUtilsClipboard.encrypt_sign(redText, encryptingKeys, signingKey, password);
            if (encryptingKeys.size() > 0 && signingKeys.size() == 0)
                blackText = BcUtilsClipboard.encrypt(redText, encryptingKeys);
            if (encryptingKeys.size() == 0 && signingKeys.size() > 0)
                blackText = BcUtilsClipboard.sign(redText, signingKey, password);
            MyClipBoard.write(blackText);
        } catch (PGPException e) {
            log2(e.toString());
            if (e.getUnderlyingException() != null)
                MyLogger.dump(e.getUnderlyingException(), action);
        } catch (Exception e) {
            MyLogger.dump(e, action);
        }

        clearPassword(password);
    }

    private static class DecryptClipAction
            extends AbstractAction {
        private DecryptClipAction() {
            super(Text.get("decrypt_verify"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("decrypt_verify");
            log1(action + " " + Text.get("clipboard"));
            try {
                String blackText = MyClipBoard.readString();
                String redText = BcUtilsClipboard.process(blackText);
                MyClipBoard.write(redText);
            } catch (PasswordCancelled ignored) {
            } catch (PGPException e) {
                log2(e.toString());
                if (e.getUnderlyingException() != null)
                    MyLogger.dump(e.getUnderlyingException(), action);
            } catch (Exception e) {
                MyLogger.dump(e, action);
            }
        }
    }

    private static class SecureDeleteAction
            extends AbstractAction {
        private SecureDeleteAction() {
            super(Text.get("delete"));
        }

        public void actionPerformed(ActionEvent event) {
            String action = Text.get("delete");
            log1(action);
            File[] files = fch.getSelectedFiles();
            if (files == null || files.length == 0)
                return;

            for (File file : files) {
                try {
                    String msg = String.format(
                            "<html><b>%s</b>:<br>%s</html>",
                            file.getName(), Text.get("delete?")
                    );
                    int result = JOptionPane.showConfirmDialog(null,
                            msg,
                            action,
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            Icons.getPgpIcon());
                    if (result != JOptionPane.OK_OPTION)
                        return;
                    log(action + ": " + file.getName());
                    SecureDeleter.delete(file);
                } catch (Exception e) {
                    MyLogger.dump(e, action);
                }
            }
            fch.rescanCurrentDirectory();
        }
    }

    static void fileDeleted(SecureDeleteWorker worker) {
        try {
            fch.rescanCurrentDirectory();
            Exception executonException = worker.getExecutonException();
            if (executonException != null)
                throw executonException;
        } catch (Exception e) {
            MyLogger.dump(e, Text.get("delete"));
        }
    }

    private static class NewDirectoryAction
            extends AbstractAction {

        private NewDirectoryAction() {
            super(Text.get("new_directory"));
        }

        public void actionPerformed(ActionEvent event) {
            File father = null;
            try {
                father = getDirectory(fch);
            } catch (FileNotFoundException ignored) {
            }
            if (father == null)
                return;
            String label = Text.get("new_directory");
            JTextField textField = new JTextField(20);
            int result = JOptionPane.showConfirmDialog(null,
                    textField, label,
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            String dirname = textField.getText();
            if (dirname == null || dirname.length() == 0)
                return;
            File son = new File(father, dirname);
            son.mkdir();
            fch.setDirectory(son);
        }
    }

    private static class RefreshAction
            extends AbstractAction {
        private RefreshAction() {
            super(Text.get("refresh"));
        }

        public void actionPerformed(ActionEvent event) {
            fch.rescanCurrentDirectory();
        }
    }

    private static class GenerateKeyAction
            extends AbstractAction {
        private GenerateKeyAction() {
            super(Text.get("generate"));
        }

        public void actionPerformed(ActionEvent event) {
            MyDirectoryChooser directoryChooser = new MyDirectoryChooser();
            directoryChooser.setDirectory(Info.getHome());
            Object[] options = {Text.get("accept"), Text.get("cancel")};
            int ret = JOptionPane.showOptionDialog(null,
                    directoryChooser,
                    Text.get("key_directory"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    Icons.getPgpIcon(),
                    options, options[0]);
            if (ret != JFileChooser.APPROVE_OPTION)
                return;
            File where = directoryChooser.getSelectedDirectory();

            final KeyGenPanel panel = new KeyGenPanel();
            for (; ; ) {
                int result = JOptionPane.showConfirmDialog(null,
                        panel, Text.get("generate"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        Icons.getPgpIcon());
                if (result != JOptionPane.OK_OPTION)
                    return;
                if (panel.getName().length() == 0)
                    continue;
                if (panel.getEmail().length() == 0)
                    continue;
                if (panel.getExpireDate() == null)
                    continue;
                char[] password = panel.getPassword();
                if (password == null || password.length == 0)
                    continue;
                break;
            }
            log1(Text.get("generate"));

            KeyGeneratingThread task = new KeyGeneratingThread(
                    where,
                    panel.getSignAlgo(), panel.getEncryptAlgo(),
                    panel.getName(), panel.getEmail(), panel.getComment(),
                    panel.getExpireDate(),
                    panel.getPassword());
            KeyGeneratingWorker worker = new KeyGeneratingWorker(task);
            worker.execute();
        }
    }

    static void keyGenerated(KeyGeneratingThread task) {
        try {
            long delta = task.getDelta();
            log2(String.format("%dm %ds", delta / 60, delta % 60));
            Exception executionException = task.getExecutionException();
            if (executionException != null)
                throw executionException;
            log2(task.getResult());
            reloadKeys();
        } catch (Exception e) {
            if (e instanceof PGPException) {
                PGPException pgpException = (PGPException) e;
                log2(pgpException.toString());
                if (pgpException.getUnderlyingException() != null)
                    MyLogger.dump(pgpException.getUnderlyingException(), Text.get("generate"));
            } else {
                MyLogger.dump(e, Text.get("generate"));
            }
        }
    }

    static class AliasKeyAction
            extends AbstractAction {
        private final boolean checked;

        AliasKeyAction(boolean checked) {
            super(Text.get("alias"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
                return;
            }

            for (Key key : secretKeys)
                setAlias(key);
            for (Key key : publicKeys)
                setAlias(key);
            Info.saveInfo();
            reloadKeys();
        }

        private void setAlias(Key key) {
            JTextField aliasLabel = new JTextField(key.toString());
            int result = JOptionPane.showConfirmDialog(null,
                    aliasLabel, Text.get("alias"),
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            KeyDB2.setAlias(key.getKid(), aliasLabel.getText());
        }
    }

    static class CopyKeyAction
            extends AbstractAction {
        private final boolean checked;

        CopyKeyAction(boolean checked) {
            super(Text.get("copy"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
                return;
            }

            StringBuilder builder = new StringBuilder();
            for (Key key : secretKeys)
                copy(builder, key);
            for (Key key : publicKeys)
                copy(builder, key);
            MyClipBoard.write(builder.toString());
        }

        private void copy(StringBuilder builder, Key key) {
            builder.append(key.toString()).append('\n');
            builder.append(Text.get("fingerprint")).append(": ").append(key.getFingerprintHex4()).append('\n');
        }
    }

    static class ExportKeyAction
            extends AbstractAction {
        private final boolean checked;

        ExportKeyAction(boolean checked) {
            super(Text.get("export"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            log1(Text.get("export"));
            List<Key> secretKeys = getSecretKeys(checked);
            List<Key> publicKeys = getPublicKeys(checked);
            if (secretKeys.size() == 0 && publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                log("%s: 0%n", Text.get("secret_keys"));
                return;
            }
            File where = getFile();
            if (where == null)
                return;

            for (Key key : secretKeys) {
                log2(key.toString());
                KeySaver.exportSecretKey(where, key);
            }
            for (Key key : publicKeys) {
                log2(key.toString());
                KeySaver.exportPublicKey(where, key);
            }
        }

        private File getFile() {
            if (keyFileChooser == null) {
                keyFileChooser = new MyDirectoryChooser();
                keyFileChooser.setDirectory(Info.getHome());
            }
            Object[] options = {Text.get("accept"), Text.get("cancel")};
            int ret = JOptionPane.showOptionDialog(null,
                    keyFileChooser,
                    Text.get("select_directory"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    Icons.getPgpIcon(),
                    options, options[0]);
            if (ret != JFileChooser.APPROVE_OPTION)
                return null;
            return keyFileChooser.getSelectedDirectory();
        }
    }

    private static class ReloadKeysAction
            extends AbstractAction {
        private ReloadKeysAction() {
            super(Text.get("refresh"));
        }

        public void actionPerformed(ActionEvent event) {
            reloadKeys();
        }
    }

    private static class FileMapAction
            extends AbstractAction {
        private FileMapAction() {
            super(String.format("%s & %s", Text.get("files"), Text.get("keys")));
        }

        public void actionPerformed(ActionEvent event) {
            StringBuilder builder = new StringBuilder();
            directory.dumpLog(builder);
            MyTextArea.show(builder.toString(), frame);
        }
    }

    private static class AddKeyListAction
            extends AbstractAction {
        private final boolean checked;

        private AddKeyListAction(boolean checked) {
            super(Text.get("add_key_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<Key> publicKeys = getPublicKeys(checked);
            if (publicKeys.size() == 0) {
                log("%s: 0%n", Text.get("public_keys"));
                return;
            }

            List<DefaultMutableTreeNode> listNodes = getLists(checked);
            if (listNodes.size() == 0) {
                log("%s: 0%n", Text.get("lists"));
                return;
            }

            for (DefaultMutableTreeNode node : listNodes) {
                KeyList list = (KeyList) node.getUserObject();
                for (Key key : publicKeys)
                    list.add(key);
            }
            Info.saveInfo();
            reloadKeys();
        }
    }

    static class RemoveKeyListAction
            extends AbstractAction {
        private final boolean checked;

        RemoveKeyListAction(boolean checked) {
            super(Text.get("remove_key_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            Collection<TreePath> paths = getSelectionPaths(checked);
            if (paths == null || paths.isEmpty())
                return;

            if (checked) {
                List<Key> secretKeys = getSecretKeys(true);
                List<Key> publicKeys = getPublicKeys(true);
                List<KeyList> keyLists = getKeyLists(true);
                for (KeyList keyList : keyLists) {
                    for (Key key : secretKeys)
                        keyList.remove(key);
                    for (Key key : publicKeys)
                        keyList.remove(key);
                }

            } else {
                for (TreePath path : paths) {
                    try {
                        DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                        Key key = (Key) node.getUserObject();
                        KeyList keyList = null;
                        for (DefaultMutableTreeNode n = node; n != null; n = (DefaultMutableTreeNode) n.getParent())
                            keyList = (KeyList) n.getUserObject();
                        keyList.remove(key);
                    } catch (Exception ignored) {
                    }
                }
            }

            for (int i = 0; i < listsBranch.getChildCount(); i++) {
                DefaultMutableTreeNode listNode = (DefaultMutableTreeNode) listsBranch.getChildAt(i);
                removeFrom(listNode);
            }

            Info.saveInfo();
            reloadKeys();
        }

        private void removeFrom(DefaultMutableTreeNode listNode) {
            KeyList list = (KeyList) listNode.getUserObject();
            for (int j = 0; j < listNode.getChildCount(); j++) {
                DefaultMutableTreeNode keyNode = (DefaultMutableTreeNode) listNode.getChildAt(j);
                TreePath keyPath = new TreePath(keyNode.getPath());
                if (keysTree.isPathSelected(keyPath)) {
                    Key key = (Key) keyNode.getUserObject();
                    list.remove(key);
                }
            }
        }
    }

    static class NewListAction
            extends AbstractAction {
        NewListAction() {
            super(Text.get("new_list"));
        }

        public void actionPerformed(ActionEvent event) {
            String label = Text.get("new_list");
            JTextField textField = new JTextField(20);
            int result = JOptionPane.showConfirmDialog(null,
                    textField, label,
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    Icons.getPgpIcon());
            if (result != JOptionPane.OK_OPTION)
                return;
            String listname = textField.getText();
            if (listname == null || listname.length() == 0)
                return;
            if (KeyListDB.get(listname) != null)
                return;
            KeyList list = new KeyList(listname);
            KeyListDB.add(list);
            Info.saveInfo();
            reloadKeys();
        }
    }

    static class RemoveListAction
            extends AbstractAction {
        private final boolean checked;

        RemoveListAction(boolean checked) {
            super(Text.get("remove_list"));
            this.checked = checked;
        }

        public void actionPerformed(ActionEvent event) {
            List<DefaultMutableTreeNode> listNodes = getLists(checked);
            if (listNodes.size() == 0) {
                log("%s: 0%n", Text.get("lists"));
                return;
            }

            for (DefaultMutableTreeNode node : listNodes) {
                KeyList list = (KeyList) node.getUserObject();
                int result = JOptionPane.showConfirmDialog(null,
                        list.getName(),
                        Text.get("remove_list"),
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        Icons.getPgpIcon());
                if (result != JOptionPane.OK_OPTION)
                    return;
                KeyListDB.removeList(list);
            }
            Info.saveInfo();
            reloadKeys();
        }
    }

    private static File getDirectory(MyFileChooser fch)
            throws FileNotFoundException {
        File directory = fch.getSelectedFile();
        if (directory == null || !directory.isDirectory())
            directory = fch.getCurrentDirectory();
        if (directory == null)
            throw new FileNotFoundException("destination");
        if (directory.isDirectory())
            return directory;
        return directory.getParentFile();
    }

    private static void log(String format, String text) {
        logArea.append(String.format(format, text));
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private static void log(String format, String text, int number) {
        logArea.append(String.format(format, text, number));
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private static void clearPassword(char[] password) {
        for (int i = 0; i < password.length; i++)
            password[i] = (char) random.nextInt();
    }
}
