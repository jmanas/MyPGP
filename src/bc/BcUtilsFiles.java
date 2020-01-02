package bc;

import crypto.GetPassword;
import exception.PasswordCancelled;
import gui.FilePanel;
import gui.MyPGP;
import gui.Text;
import gui.Version;
import gui.imgs.Icons;
import keys.Key;
import keys.KeyDB2;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.swing.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author Jose A. Manas
 * @version 1.2.2017
 */
public class BcUtilsFiles {
    private static final int BUFFER_SIZE = 1 << 16;

    /**
     * Encrypt one file.
     *
     * @param redFile    file to encrypt.
     * @param publicKeys destinations.
     * @param armor      true means asc file (text).
     * @throws Exception if anything goes wrong.
     */
    public static void encrypt(File redFile, List<Key> publicKeys, boolean armor)
            throws Exception {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(publicKeys);
        MyPGP.log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(publicKeys);

//        boolean armor = true;
        boolean withIntegrityCheck = true;

        File blackFile = mkFile(Text.get("encrypt"), redFile, armor ? ".asc" : ".pgp");
        if (blackFile == null)
            return;
        try (
                OutputStream os = new BufferedOutputStream(new FileOutputStream(blackFile));
                OutputStream out = getOutputStream(armor, os)
        ) {
            JcePGPDataEncryptorBuilder encryptorBuilder =
                    new JcePGPDataEncryptorBuilder(encryptAlgo)
                            .setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC");
            PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(encryptorBuilder);

            for (Key key : publicKeys) {
                PGPPublicKey encryptingKey = key.getEncryptingKey();
                JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
                        new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
                                .setProvider("BC");
                encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
            }

            encrypt_1(out, redFile, compressionAlgo, encryptedDataGenerator);
            encryptedDataGenerator.close();
        }
    }

    private static void encrypt_1(OutputStream out, File redFile, int compressionAlgo, PGPEncryptedDataGenerator encryptedDataGenerator) throws IOException, PGPException {
        try (OutputStream encryptedData = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE])) {
            PGPCompressedDataGenerator compressedDataGenerator =
                    new PGPCompressedDataGenerator(compressionAlgo);
            try (OutputStream compressedOut = compressedDataGenerator.open(encryptedData)) {
                PGPLiteralDataGenerator literalDataGenerator =
                        new PGPLiteralDataGenerator();
                try (OutputStream literalOut = literalDataGenerator.open(compressedOut,
                        PGPLiteralData.BINARY,
                        redFile.getName(),
                        new Date(redFile.lastModified()),
                        new byte[BUFFER_SIZE])) {
                    {
                        try (InputStream redIs = new BufferedInputStream(new FileInputStream(redFile))) {
                            byte[] buffer = new byte[BUFFER_SIZE];
                            for (; ; ) {
                                int n = redIs.read(buffer);
                                if (n < 0)
                                    break;
                                literalOut.write(buffer, 0, n);
                            }
                        }
                    }
                }
            }
            compressedDataGenerator.close();
        }
    }

    /**
     * Sign one file.
     *
     * @param inFile    file to sign.
     * @param signerKey signer.
     * @param password  password for private key.
     * @param armor     true means asc file (text).
     * @throws Exception if anything goes wrong.
     */
    public static void sign(File inFile, Key signerKey, char[] password, boolean armor)
            throws Exception {
//        boolean armor = false;

        PGPSecretKey secretKey = signerKey.getSigningKey();
        PGPPublicKey publicKey = secretKey.getPublicKey();
        PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
        if (privateKey == null)
            return;

        File outFile = mkFile(Text.get("sign"), inFile, armor ? ".asc" : ".sig");
        if (outFile == null)
            return;
        try (
                OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile));
                OutputStream out = getOutputStream(armor, os)
        ) {
            int signAlgo = publicKey.getAlgorithm();
            int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
            MyPGP.log2(String.format("%s: %s(%s)",
                    Text.get("sign"),
                    ToString.publicKey(signAlgo),
                    ToString.hash(hashAlgo)));

            JcaPGPContentSignerBuilder contentSignerBuilder =
                    new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                            .setProvider("BC");
            PGPSignatureGenerator signatureGenerator =
                    new PGPSignatureGenerator(contentSignerBuilder);
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            try (InputStream is = new BufferedInputStream(new FileInputStream(inFile))) {
                byte[] buffer = new byte[BUFFER_SIZE];
                for (; ; ) {
                    int n = is.read(buffer);
                    if (n < 0)
                        break;
                    signatureGenerator.update(buffer, 0, n);
                }
            }

            try (BCPGOutputStream bOut = new BCPGOutputStream(out)) {
                signatureGenerator.generate().encode(bOut);
            }
        }
    }

    /**
     * Sign one file.
     *
     * @param inFile        file to sign.
     * @param signerKeyList signers.
     * @param passwords     signers' passwords.
     * @param armor         true means asc file (text).
     * @throws Exception if anything goes wrong.
     */
    public static void sign(File inFile,
                            List<Key> signerKeyList,
                            Map<Key, char[]> passwords,
                            boolean armor)
            throws Exception {
//        boolean armor = false;

        PGPPublicKey[] publicKeys = new PGPPublicKey[signerKeyList.size()];
        PGPPrivateKey[] privateKeys = new PGPPrivateKey[signerKeyList.size()];
        for (int i = 0; i < signerKeyList.size(); i++) {
            Key signerKey = signerKeyList.get(i);
            char[] password = passwords.get(signerKey);
            PGPSecretKey secretKey = signerKey.getSigningKey();
            PGPPublicKey publicKey = secretKey.getPublicKey();
            PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
            if (privateKey == null)
                return;
            publicKeys[i] = publicKey;
            privateKeys[i] = privateKey;
        }

        File outFile = mkFile(Text.get("sign"), inFile, armor ? ".asc" : ".sig");
        if (outFile == null)
            return;
        try (
                OutputStream os = new BufferedOutputStream(new FileOutputStream(outFile));
                OutputStream out = getOutputStream(armor, os);
                BCPGOutputStream bOut = new BCPGOutputStream(out)
        ) {
            for (int i = 0; i < signerKeyList.size(); i++) {
                Key signerKey = signerKeyList.get(i);
                PGPPublicKey publicKey = publicKeys[i];
                PGPPrivateKey privateKey = privateKeys[i];

                int signAlgo = publicKey.getAlgorithm();
                int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
                MyPGP.log2(String.format("%s: %s(%s)",
                        Text.get("sign"),
                        ToString.publicKey(signAlgo),
                        ToString.hash(hashAlgo)));

                JcaPGPContentSignerBuilder contentSignerBuilder =
                        new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                                .setProvider("BC");
                PGPSignatureGenerator signatureGenerator =
                        new PGPSignatureGenerator(contentSignerBuilder);
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                try (InputStream is = new BufferedInputStream(new FileInputStream(inFile))) {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    for (; ; ) {
                        int n = is.read(buffer);
                        if (n < 0)
                            break;
                        signatureGenerator.update(buffer, 0, n);
                    }
                }

                signatureGenerator.generate().encode(bOut);
            }
        }
    }

    /**
     * Sign encrypt one file.
     *
     * @param redFile        file to sign & encrypt.
     * @param signerKeyList  signers.
     * @param encryptingKeys destinations.
     * @param passwords      signers' passwords.
     * @param armor          true means asc file (text).
     * @throws Exception if anything goes wrong.
     */
    public static void encrypt_sign(File redFile,
                                    List<Key> signerKeyList,
                                    List<Key> encryptingKeys,
                                    Map<Key, char[]> passwords,
                                    boolean armor)
            throws Exception {
        int encryptAlgo = AlgorithmSelection.getEncryptAlgo(encryptingKeys);
        MyPGP.log2(Text.get("encrypt") + ": " + ToString.symmetricKey(encryptAlgo));
        int compressionAlgo = AlgorithmSelection.getCompressionAlgo(encryptingKeys);

//        boolean armor = true;
        boolean withIntegrityCheck = true;


        File blackFile = mkFile(Text.get("encrypt"), redFile, armor ? ".asc" : ".pgp");
        if (blackFile == null)
            return;
        try (
                OutputStream os = new BufferedOutputStream(new FileOutputStream(blackFile));
                OutputStream out = getOutputStream(armor, os)
        ) {
            JcePGPDataEncryptorBuilder encryptorBuilder =
                    new JcePGPDataEncryptorBuilder(encryptAlgo)
                            .setWithIntegrityPacket(withIntegrityCheck)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC");
            PGPEncryptedDataGenerator encryptedDataGenerator =
                    new PGPEncryptedDataGenerator(encryptorBuilder);

            for (Key key : encryptingKeys) {
                PGPPublicKey encryptingKey = key.getEncryptingKey();
                JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator =
                        new JcePublicKeyKeyEncryptionMethodGenerator(encryptingKey)
                                .setProvider("BC");
                encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
            }

            encrypt_sign_1(blackFile, redFile, out, signerKeyList, compressionAlgo, passwords, encryptedDataGenerator);
            encryptedDataGenerator.close();
        }
    }

    private static void encrypt_sign_1(File blackFile, File redFile, OutputStream out, List<Key> signerKeyList,
                                       int compressionAlgo, Map<Key, char[]> passwords,
                                       PGPEncryptedDataGenerator encryptedDataGenerator)
            throws IOException, PGPException {
        PGPPublicKey[] publicKeys = new PGPPublicKey[signerKeyList.size()];
        PGPPrivateKey[] privateKeys = new PGPPrivateKey[signerKeyList.size()];
        for (int i = 0; i < signerKeyList.size(); i++) {
            Key signerKey = signerKeyList.get(i);
            char[] password = passwords.get(signerKey);
            PGPSecretKey secretKey = signerKey.getSigningKey();
            PGPPublicKey publicKey = secretKey.getPublicKey();
            PGPPrivateKey privateKey = BcUtils.getPrivateKey(secretKey, password);
            if (privateKey == null)
                return;     // at least, one signer fails
            publicKeys[i] = publicKey;
            privateKeys[i] = privateKey;
        }

        try (OutputStream encryptedData = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE])) {
            PGPCompressedDataGenerator compressedDataGenerator =
                    new PGPCompressedDataGenerator(compressionAlgo);
            try (OutputStream compressedOut = compressedDataGenerator.open(encryptedData)) {
                for (int i = 0; i < signerKeyList.size(); i++) {
                    Key signerKey = signerKeyList.get(i);
                    PGPPublicKey publicKey = publicKeys[i];
                    PGPPrivateKey privateKey = privateKeys[i];

                    int signAlgo = publicKey.getAlgorithm();
                    int hashAlgo = AlgorithmSelection.getHashAlgo(signerKey);
                    MyPGP.log2(String.format("%s: %s(%s)",
                            Text.get("sign"),
                            ToString.publicKey(signAlgo),
                            ToString.hash(hashAlgo)));

                    JcaPGPContentSignerBuilder contentSignerBuilder =
                            new JcaPGPContentSignerBuilder(signAlgo, hashAlgo)
                                    .setProvider("BC");
                    PGPSignatureGenerator signatureGenerator =
                            new PGPSignatureGenerator(contentSignerBuilder);
                    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                    Iterator it = publicKey.getUserIDs();
                    if (it.hasNext()) {
                        String userId = (String) it.next();
                        PGPSignatureSubpacketGenerator signatureSubpacketGenerator =
                                new PGPSignatureSubpacketGenerator();
                        signatureSubpacketGenerator.setSignerUserID(false, userId);
                        signatureGenerator.setHashedSubpackets(signatureSubpacketGenerator.generate());
                    }
                    signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

                    PGPLiteralDataGenerator literalDataGenerator =
                            new PGPLiteralDataGenerator();
                    try (OutputStream literalOut = literalDataGenerator.open(compressedOut,
                            PGPLiteralData.BINARY,
                            redFile.getName(),
                            new Date(blackFile.lastModified()),
                            new byte[BUFFER_SIZE])) {
                        try (InputStream redIs = new BufferedInputStream(new FileInputStream(redFile))) {
                            byte[] buffer = new byte[BUFFER_SIZE];
                            for (; ; ) {
                                int n = redIs.read(buffer);
                                if (n < 0)
                                    break;
                                literalOut.write(buffer, 0, n);
                                signatureGenerator.update(buffer, 0, n);
                            }
                        }
                    }
                    literalDataGenerator.close();
                    signatureGenerator.generate().encode(compressedOut);
                }
            }
            compressedDataGenerator.close();
        }
    }

    private static void decrypt(File redFile, File blackFile, Map<Long, char[]> passwords)
            throws IOException, PasswordCancelled, PGPException {
        BcUtils.log1(String.format("%s(%s) --> %s",
                Text.get("decrypt"), blackFile.getName(), redFile.getName()));
        if (blackFile.length() == 0)
            return;
        try (InputStream is = CRLF.sanitize(blackFile)) {
            PGPEncryptedDataList encryptedDataList = BcUtils.getEncryptedDataList(is, blackFile.getName());
            if (encryptedDataList == null)
                return;

            List<PGPPublicKeyEncryptedData> list = BcUtils.getKnownKeyEncryptedData(encryptedDataList);
            if (list.size() == 0) {
                BcUtils.log2(Text.get("no_known_key"));
                return;
            }

            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            for (PGPPublicKeyEncryptedData item : list) {
                pbe = item;
                long id = pbe.getKeyID();
                Key key = KeyDB2.getKey(id);
                if (key == null)
                    continue;
                char[] password = passwords.get(id);
                if (password == null)
                    password = GetPassword.getInstance().getDecryptionPassword(Text.get("decrypt") + ": " + key);
                if (password == null || password.length == 0)
                    continue;
                passwords.put(id, password);
                PGPSecretKey pgpSecretKey = KeyDB2.getSecretKey(id);
                sKey = BcUtils.getPrivateKey(pgpSecretKey, password);
                if (sKey != null)
                    break;
            }
            if (sKey == null) {
                BcUtils.log2(Text.get("no_known_key"));
                return;
            }

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;

            PublicKeyDataDecryptorFactory factory =
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(sKey);
            int encryptAlgo = pbe.getSymmetricAlgorithm(factory);
            MyPGP.log2(Text.get("decrypt") + ": " + ToString.symmetricKey(encryptAlgo));
            try (InputStream clear = pbe.getDataStream(factory)) {
                PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(clear);

                byte[] redBytes;
                try (ByteArrayOutputStream redData = new ByteArrayOutputStream()) {
                    for (; ; ) {
                        Object message = pgpObjectFactory.nextObject();
                        if (message == null)
                            break;
                        if (message instanceof PGPCompressedData) {
                            PGPCompressedData compressedData = (PGPCompressedData) message;
                            pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                        } else if (message instanceof PGPLiteralData) {
                            PGPLiteralData literalData = (PGPLiteralData) message;
                            pipeAll(literalData.getInputStream(), redData);
                        } else if (message instanceof PGPOnePassSignatureList) {
                            onePassSignatureList = (PGPOnePassSignatureList) message;
                        } else if (message instanceof PGPSignatureList) {
                            signatureList = (PGPSignatureList) message;
                        } else {
                            throw new PGPException("message unknown message type.");
                        }
                    }
                    redBytes = redData.toByteArray();
                }

                if (pbe.isIntegrityProtected() && !pbe.verify())
                    BcUtils.log2("integrity check fails");

                try (OutputStream redOs = new BufferedOutputStream(new FileOutputStream(redFile))) {
                    redOs.write(redBytes);
                }

                BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);
            }
        }
    }

    /**
     * Verify file signature.
     *
     * @param signatureFile detached signature.
     * @param redFile       signed file.
     * @throws IOException  errors.
     * @throws PGPException errors.
     */
    public static void verify(File signatureFile, File redFile)
            throws IOException, PGPException {
        try (
                InputStream sigIs = new FileInputStream(signatureFile);
                InputStream decoderStream = PGPUtil.getDecoderStream(sigIs)
        ) {
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);

            PGPSignatureList signatureList;
            Object object = pgpObjectFactory.nextObject();
            if (object instanceof PGPCompressedData) {
                PGPCompressedData compressedData = (PGPCompressedData) object;
                pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                signatureList = (PGPSignatureList) pgpObjectFactory.nextObject();
            } else {
                signatureList = (PGPSignatureList) object;
            }

            for (int i = 0; i < signatureList.size(); i++) {
                PGPSignature signature = signatureList.get(i);
                verify(redFile, signature);
            }
        }
    }

    private static void verify(PGPSignatureList signatureList, File redFile)
            throws IOException, PGPException {
        for (int i = 0; i < signatureList.size(); i++) {
            PGPSignature signature = signatureList.get(i);
            verify(redFile, signature);
        }
    }

    private static void verify(File redFile, PGPSignature signature)
            throws PGPException, IOException {
        int hashAlgo = signature.getHashAlgorithm();
        int signAlgo = signature.getKeyAlgorithm();
        BcUtils.log2(String.format("%s: %s(%s)", Text.get("signature"), ToString.publicKey(signAlgo), ToString.hash(hashAlgo)));
        BcUtils.logSignTime(signature);

        Key key = KeyDB2.getKey(signature.getKeyID());
        if (key == null) {
            BcUtils.log2(String.format("%s: %s", Text.get("signer"), Key.mkId8(signature.getKeyID())));
            return;
        }
        BcUtils.log2(String.format("%s: %s", Text.get("signer"), key));

        PGPPublicKey publicKey = key.getPublicKey();
        signature.init(
                new JcaPGPContentVerifierBuilderProvider()
                        .setProvider("BC"),
                publicKey);
        try (InputStream redIs = new BufferedInputStream(new FileInputStream(redFile))) {
            byte[] buffer = new byte[BUFFER_SIZE];
            for (; ; ) {
                int n = redIs.read(buffer);
                if (n < 0)
                    break;
                signature.update(buffer, 0, n);
            }
        }
        if (signature.verify())
            BcUtils.log2(Text.get("signature_ok"));
        else
            BcUtils.log2(Text.get("signature_bad"));
    }

    /**
     * Discover crypto operations to perform.
     *
     * @param blackFile entry file.
     * @param passwords known destinations' passwords.
     * @throws IOException        errors.
     * @throws PasswordCancelled  user cancels.
     * @throws PGPException       errors.
     */
    public static void process(File blackFile, Map<Long, char[]> passwords)
            throws IOException, PasswordCancelled, PGPException {
        if (blackFile.length() == 0)
            return;
        try (
                InputStream is = CRLF.sanitize(blackFile);
                InputStream decoderStream = PGPUtil.getDecoderStream(is)
        ) {
            PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);
            Object x;
            do {
                try {
                    x = pgpObjectFactory.nextObject();
                } catch (Exception e) {
                    x = null;
                }
                if (x == null) {
                    BcUtils.log1(String.format("%s(%s) :",
                            Text.get("process"), blackFile.getName()));
                    BcUtils.log2(String.format("%s: %s", blackFile.getName(), Text.get("exception.bad_format")));
                    return;
                }
                if (x instanceof PGPCompressedData) {
                    PGPCompressedData compressedData = (PGPCompressedData) x;
                    pgpObjectFactory = new BcPGPObjectFactory(compressedData.getDataStream());
                    x = pgpObjectFactory.nextObject();
                }
            } while (x instanceof PGPMarker);

            if (x instanceof PGPEncryptedDataList) {
                File redFile = mkRedFile(Text.get("process"), blackFile);
                if (redFile == null)
                    redFile = new File(blackFile.getParent(), "mypgp.out");
                decrypt(redFile, blackFile, passwords);
                return;
            }

            if (x instanceof PGPSignatureList) {
                File redFile = getRedFile(Text.get("process"), blackFile);
                String filenameString = redFile == null ? "no" : redFile.getName();
                BcUtils.log1(String.format("%s == %s(%s) :",
                        blackFile.getName(), Text.get("signature"), filenameString));
                if (redFile == null)
                    BcUtils.log2(String.format("%s: %s", blackFile.getName(), Text.get("no_signed_file")));
                else
                    verify((PGPSignatureList) x, redFile);
                return;
            }

            if (x instanceof PGPOnePassSignatureList) {
                BcUtils.log1(String.format("%s(%s) :",
                        Text.get("signature"), blackFile.getName()));
                PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList) x;

                PGPLiteralData literalData = (PGPLiteralData) pgpObjectFactory.nextObject();
                String filename = literalData.getFileName();
                Date date = literalData.getModificationTime();
                byte[] redBytes = getBytes(literalData);

                if (filename != null) {
                    if (date == null || date.getTime() == 0)
                        BcUtils.log2("-> " + filename);
                    else
                        BcUtils.log2(String.format("-> %s (%tF)", filename, date));
                    File redFile = new File(blackFile.getParent(), filename);
                    if (redFile.exists())
                        redFile = new File(blackFile.getParent(), "mypgp.out");
                    try (OutputStream os = new FileOutputStream(redFile)) {
                        os.write(redBytes);
                    }
                }

                PGPSignatureList signatureList = (PGPSignatureList) pgpObjectFactory.nextObject();
                BcUtils.verifySignature(onePassSignatureList, signatureList, redBytes);
                return;
            }

            if (x instanceof PGPPublicKey)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPPublicKeyRing)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPPublicKeyRingCollection)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));

            else if (x instanceof PGPSecretKey)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPSecretKeyRing)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
            else if (x instanceof PGPSecretKeyRingCollection)
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));

            else
                BcUtils.log2(String.format("%s: %s", blackFile.getName(), x.getClass().getSimpleName()));
        }
    }

    private static byte[] getBytes(PGPLiteralData literalData)
            throws IOException {
        try (ByteArrayOutputStream redData = new ByteArrayOutputStream()) {
            pipeAll(literalData.getInputStream(), redData);
            return redData.toByteArray();
        }
    }

    /**
     * Prepares a new file with a given extension.
     *
     * @param base base name.
     * @param ext  extension (with starting dot).
     * @return file with cooked name.
     */
    private static File mkFile(String op, File base, String ext) {
        FilePanel panel = new FilePanel(base, ext);
        File file = panel.getOvwFile();
        if (!file.exists())
            return file;

        int ret = JOptionPane.showConfirmDialog(null,
                panel, op,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (ret != JOptionPane.OK_OPTION)
            return null;
        return panel.getSelectedFile();
    }

    private static File mkRedFile(String op, File blackFile) {
        String redFilename;
        String blackFilename = blackFile.getName();
        if (blackFilename.endsWith(".asc"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".sig"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".pgp"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".gpg"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else
            return null;

        File file = new File(blackFile.getParent(), redFilename);
        if (!file.exists())
            return file;

        FilePanel panel = new FilePanel(file);
        int ret = JOptionPane.showConfirmDialog(null,
                panel, op,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                Icons.getPgpIcon());
        if (ret != JOptionPane.OK_OPTION)
            return null;
        return panel.getSelectedFile();
    }

    private static File getRedFile(String op, File blackFile) {
        String redFilename;
        String blackFilename = blackFile.getName();
        if (blackFilename.endsWith(".asc"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".sig"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".pgp"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else if (blackFilename.endsWith(".gpg"))
            redFilename = blackFilename.substring(0, blackFilename.length() - 4);
        else
            return null;

        File file = new File(blackFile.getParent(), redFilename);
        if (file.exists())
            return file;

        JFileChooser fileChooser = new JFileChooser(blackFile.getParentFile());
        fileChooser.setDialogTitle(op);
        int ret = fileChooser.showOpenDialog(null);
        if (ret != JFileChooser.APPROVE_OPTION)
            return null;
        return fileChooser.getSelectedFile();
    }

    private static void pipeAll(InputStream is, OutputStream os)
            throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        for (; ; ) {
            int n = is.read(buffer);
            if (n < 0)
                break;
            os.write(buffer, 0, n);
        }
    }

    private static OutputStream getOutputStream(boolean armor, OutputStream os) {
        if (armor) {
            ArmoredOutputStream aos = new ArmoredOutputStream(os);
            aos.setHeader("Comment", Version.VERSION);
            return aos;
        }
        return os;
    }
}
