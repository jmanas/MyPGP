package keys;

import gui.Text;

import java.io.PrintWriter;
import java.text.Collator;
import java.util.*;

// 28.6.2011 delay ordering to prevent alias changes

/**
 * @author Jose A. Manas
 * @version 2.6.2011
 */
public class KeyList
        implements Comparable {
    private static int nextUid = 1;

    private int uid;
    private String name;
    //    private Collection<Key> members = new TreeSet<Key>(Key.KEY_COMPARATOR);
    private Collection<Key> members = new HashSet<>();

    public KeyList(int uid, String name) {
        this.uid = uid;
        this.name = name;
        if (nextUid < uid + 1)
            nextUid = uid + 1;
    }

    public KeyList(String name) {
        uid = nextUid++;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Collection<Key> getMembers(boolean sort) {
        if (!sort)
            return members;

        Set<Key> sorted = new TreeSet<>(new Comparator<Key>() {
            Collator collator = Collator.getInstance(Text.getLocale());

            public int compare(Key key1, Key key2) {
                return collator.compare(key1.toString(), key2.toString());
            }
        });
        sorted.addAll(members);
        return sorted;
    }

    public void add(Key key) {
        members.add(key);
    }

    public void add(Collection<Key> keys) {
        members.addAll(keys);
    }

    public void remove(Key key) {
        members.remove(key);
    }

    public void remove(Collection<Key> keys) {
        members.removeAll(keys);
    }

    @Override
    public String toString() {
        return name;
    }

    public int compareTo(Object o) {
        KeyList she = (KeyList) o;
        String myText = name;
        String herText = she.name;
        return myText.compareToIgnoreCase(herText);
    }

    public void load(String body) {
        String[] kids = body.split("[ ,]");
        for (String s : kids) {
            if (s == null || s.trim().length() == 0)
                continue;
            String kid = s.trim();
            setMember(kid);
        }
    }

    private void setMember(String kid) {
        Key key = KeyDB2.getKey(kid);
        if (key != null)
            members.add(key);
    }

    public void save(PrintWriter writer) {
        writer.write(String.format("list.%d.name= %s%n", uid, name));
        writer.write(String.format("list.%d.members=", uid));
        for (Key key : members) {
            writer.write(' ');
            writer.write(key.getKid());
        }
        writer.println();
    }

    int getUid() {
        return uid;
    }
}
