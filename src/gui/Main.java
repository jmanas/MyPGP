package gui;

import exception.MyLogger;
import gui.imgs.Icons;
import keys.Info;

import javax.swing.*;
import java.io.File;
import java.util.prefs.Preferences;

/**
 * Application launcher.
 *
 * @author Jose A. Manas
 * @version 27.4.2011
 */
public class Main {

    public static void main(String[] args) {
        try {
            Preferences preferences = Preferences.userRoot().node("mypgp");

            String langPreference = preferences.get("language", "en");
            Text.setLocale(langPreference);

            MyDirectoryChooser chooser = new MyDirectoryChooser();
            String last = preferences.get("root", null);
            if (last != null)
                chooser.setDirectory(last);
            Object[] options = {Text.get("accept"), Text.get("cancel")};
            int ret = JOptionPane.showOptionDialog(null,
                    chooser,
                    Text.get("key_directory"),
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    Icons.getPgpIcon(),
                    options, options[0]);
            if (ret != JFileChooser.APPROVE_OPTION)
                throw new NoHomeException();
            File home = chooser.getSelectedDirectory();
            if (home == null)
                throw new NoHomeException();
            if (!home.isDirectory())
                throw new NoHomeException();
            preferences.put("root", home.getCanonicalPath());
            Info.setHome(home);

            MyPGP.start();
        } catch (NoHomeException nhe) {
//            MyLogger.record(nhe);
            String message = "no HOME directory";
            String title = Version.VERSION;
            JOptionPane.showMessageDialog(null,
                    message, title,
                    JOptionPane.ERROR_MESSAGE,
                    Icons.getPgpIcon());
            System.exit(1);
        } catch (Throwable e) {
            e.printStackTrace();
            MyLogger.record(e);
            String message = Text.get("no_libraries");
            String title = "https://www.bouncycastle.org/";
            JOptionPane.showMessageDialog(null,
                    message, title,
                    JOptionPane.ERROR_MESSAGE,
                    Icons.getPgpIcon());
            System.exit(1);
        }
    }

    private static class NoHomeException
            extends Exception {
    }
}
