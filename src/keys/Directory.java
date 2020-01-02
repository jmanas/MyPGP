package keys;

import bc.PemSplitter;
import gui.MyPGP;
import gui.Text;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.Collator;
import java.util.*;

/**
 * @author Jose A. Manas
 * @version 25.5.2013
 */
public class Directory {
    private static final Comparator<Directory> DIR_COMPARATOR = new Comparator<Directory>() {
        public int compare(Directory dir1, Directory dir2) {
            String name1 = dir1.toString();
            String name2 = dir2.toString();
            return name1.compareToIgnoreCase(name2);
        }
    };
    private final File file;
    private final String name;

    private List<File> children = new ArrayList<>();
    private Collection<Directory> subdirs = new TreeSet<>(DIR_COMPARATOR);
    private Collection<Key> keys = new HashSet<>();
    private Map<File, Collection<Key>> keyloadlog = new HashMap<>();

    public static Directory load(File file) {
        Directory directory = new Directory(file);
        File[] files = file.listFiles();
        if (files == null || files.length == 0)
            return directory;

        for (File child : files) {
            if (skip(child)) {
                MyPGP.ignore(child.getAbsolutePath());
            } else if (child.isFile()) {
                directory.children.add(child);
                loadRings(directory, child);
            }
        }

        for (File child : files) {
            if (skip(child))
                continue;
            if (child.isDirectory()) {
                Directory subdir = load(child);
                if (subdir != null && !subdir.isEmpty())
                    directory.subdirs.add(subdir);
            }
        }
        return directory;
    }

    private static void loadRings(Directory directory, File child) {
        PemSplitter splitter = null;
        try {
            splitter = new PemSplitter(child);
            while (splitter.hasNext()) {
                InputStream decoderStream = PGPUtil.getDecoderStream(splitter.next());
                PGPObjectFactory pgpObjectFactory = new BcPGPObjectFactory(decoderStream);
                for (; ; ) {
                    Object object = pgpObjectFactory.nextObject();
                    if (object == null)
                        break;
                    if (object instanceof PGPPublicKeyRing)
                        loadPublicRing(directory, child, (PGPPublicKeyRing) object);
                    else if (object instanceof PGPSecretKeyRing)
                        loadSecretRing(directory, child, (PGPSecretKeyRing) object);
//                    else
//                        System.out.println(object.getClass().getSimpleName());
                }
            }
        } catch (Exception e) {
            MyPGP.ignore(child.getAbsolutePath());
        } finally {
            if (splitter != null)
                splitter.close();
        }
    }

    private static void loadPublicRing(Directory directory, File child, PGPPublicKeyRing ring) {
        PGPPublicKey masterKey = null;
        Iterator keyIterator = ring.getPublicKeys();
        while (keyIterator.hasNext()) {
            PGPPublicKey pgpPublicKey = (PGPPublicKey) keyIterator.next();
            if (pgpPublicKey.isMasterKey())
                masterKey = pgpPublicKey;
            Key key = KeyDB2.store(masterKey, pgpPublicKey);
            directory.add(child, key);
        }
    }

    private static void loadSecretRing(Directory directory, File child, PGPSecretKeyRing ring) {
        PGPSecretKey masterKey = null;
        Iterator keyIterator = ring.getSecretKeys();
        while (keyIterator.hasNext()) {
            PGPSecretKey pgpSecretKey = (PGPSecretKey) keyIterator.next();
            if (pgpSecretKey.isMasterKey())
                masterKey = pgpSecretKey;
            Key key = KeyDB2.store(masterKey, pgpSecretKey);
            directory.add(child, key);
        }
    }

    private void add(File file, Key key) {
        if (key == null)
            return;
        key.setFile(file);
        if (!key.isMasterKey())
            return;
        for (Key k : keys) {
            if (k.getId() == key.getId())
                return;
        }
        keys.add(key);
        Collection<Key> kc = keyloadlog.get(file);
        if (kc == null) {
            kc = new ArrayList<>();
            keyloadlog.put(file, kc);
        }
        kc.add(key);
    }

    private static boolean skip(File child) {
        String childname = child.getName().toLowerCase();
        if (childname.startsWith("_"))
            return true;
        if (childname.endsWith(".skip"))
            return true;
        if (childname.endsWith(".mypgp"))
            return true;
        if (childname.endsWith(".mygpg"))
            return true;
        if (childname.endsWith(".exe"))
            return true;
        if (childname.endsWith(".jar"))
            return true;
        if (childname.endsWith(".app"))
            return true;
//        if (childname.endsWith(".pgp"))
//            return true;
//        if (childname.endsWith(".gpg"))
//            return true;
//        if (childname.endsWith(".bak"))
//            return true;
//        if (childname.endsWith(".lock"))
//            return true;
        return false;
    }

    private boolean isEmpty() {
        return children.isEmpty() && subdirs.isEmpty();
    }

    public Directory(File file) {
        this.file = file;
        this.name = file.getName();
    }

    @Override
    public String toString() {
        return name;
    }

    public Collection<Directory> getSubdirs() {
        return subdirs;
    }

    public Collection<Key> getKeys() {
        Set<Key> sorted = new TreeSet<>(new Comparator<Key>() {
            Collator collator = Collator.getInstance(Text.getLocale());

            public int compare(Key key1, Key key2) {
                int compare = collator.compare(key1.toString(), key2.toString());
                if (compare == 0)
                    return key1.getKid().compareTo(key2.getKid());
                return compare;
            }
        });
        sorted.addAll(keys);
        return sorted;
    }

    public void addKeys(List<Key> keyList) {
        keyList.addAll(keys);
        for (Directory child : subdirs)
            child.addKeys(keyList);
    }

    public void dumpLog(StringBuilder builder) {
        for (Map.Entry<File, Collection<Key>> es : keyloadlog.entrySet()) {
            try {
                File file = es.getKey();
                builder.append(String.format("%s%n", file.getCanonicalPath()));
                Collection<Key> list = es.getValue();
                for (Key key : list)
                    builder.append(String.format("        [%s] %s%n", key.getKid8(), key));
                builder.append('\n');
            } catch (IOException ignored) {
            }
        }
        for (Directory directory : getSubdirs())
            directory.dumpLog(builder);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        Directory directory = (Directory) o;
        return file.equals(directory.file);
    }

    @Override
    public int hashCode() {
        return file.hashCode();
    }

    public File getFile() {
        return file;
    }
}
