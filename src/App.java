import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.Arrays;

public class App {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE_BITS = 128;
    private static final int KEY_SIZE_BYTES = 32;

    private static final int ARGON2_ITERATIONS = 4;
    private static final int ARGON2_MEMORY_KB = 1_048_576;
    private static final int ARGON2_PARALLELISM = 2;

    private static final int SECURE_DELETE_PASSES = 3;

    private static byte[] deriveKey(char[] password, byte[] salt) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(ARGON2_ITERATIONS)
                .withMemoryAsKB(ARGON2_MEMORY_KB)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt)
                .build();

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);

        byte[] passwordBytes = PasswordConverter.UTF8.convert(password);
        byte[] key = new byte[KEY_SIZE_BYTES];
        try {
            generator.generateBytes(passwordBytes, key, 0, key.length);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
        return key;
    }

    public static void encryptFile(String inputPath, String outputPath, char[] password) throws Exception {
        byte[] fileData = Files.readAllBytes(new File(inputPath).toPath());
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(salt);
        random.nextBytes(iv);

        byte[] aesKey = deriveKey(password, salt);
        byte[] finalPackage;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] encryptedDataAndTag = cipher.doFinal(fileData);
            finalPackage = new byte[salt.length + iv.length + encryptedDataAndTag.length];
            System.arraycopy(salt, 0, finalPackage, 0, salt.length);
            System.arraycopy(iv, 0, finalPackage, salt.length, iv.length);
            System.arraycopy(encryptedDataAndTag, 0, finalPackage, salt.length + iv.length, encryptedDataAndTag.length);
        } finally {
            Arrays.fill(aesKey, (byte) 0);
            Arrays.fill(fileData, (byte) 0);
        }
        Files.write(new File(outputPath).toPath(), finalPackage);
    }

    public static void decryptFile(String encryptedPath, String outputPath, char[] password) throws Exception {
        byte[] completePackage = Files.readAllBytes(new File(encryptedPath).toPath());
        int minLength = SALT_SIZE + IV_SIZE;
        if (completePackage.length < minLength) {
            throw new IllegalArgumentException("Dosya çok kısa, geçerli bir şifrelenmiş dosya değil.");
        }

        byte[] salt = Arrays.copyOfRange(completePackage, 0, SALT_SIZE);
        byte[] iv = Arrays.copyOfRange(completePackage, SALT_SIZE, SALT_SIZE + IV_SIZE);
        byte[] encryptedDataAndTag = Arrays.copyOfRange(completePackage, SALT_SIZE + IV_SIZE, completePackage.length);

        byte[] aesKey = deriveKey(password, salt);
        byte[] decryptedData;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_SIZE_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            decryptedData = cipher.doFinal(encryptedDataAndTag);
        } catch (AEADBadTagException e) {
            AEADBadTagException wrapped = new AEADBadTagException("Yanlış şifre veya bozuk dosya!");
            wrapped.initCause(e);
            throw wrapped;
        } finally {
            Arrays.fill(aesKey, (byte) 0);
        }

        try {
            Files.write(new File(outputPath).toPath(), decryptedData);
        } finally {
            Arrays.fill(decryptedData, (byte) 0);
        }
    }

    private static void secureDelete(File file) throws IOException {
        if (!file.exists()) return;

        long length = file.length();
        SecureRandom random = new SecureRandom();

        try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
            byte[] buffer = new byte[4096];
            for (int pass = 0; pass < SECURE_DELETE_PASSES; pass++) {
                raf.seek(0);
                long written = 0;
                while (written < length) {
                    random.nextBytes(buffer);
                    int toWrite = (int) Math.min(buffer.length, length - written);
                    raf.write(buffer, 0, toWrite);
                    written += toWrite;
                }
                raf.getFD().sync();
            }
        }

        File shredded = new File(file.getParentFile(), "._del_" + System.nanoTime());
        boolean renamed = file.renameTo(shredded);
        File toDelete = renamed ? shredded : file;
        if (!toDelete.delete()) {
            toDelete.deleteOnExit();
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(App::showMainDialog);
    }

    private static void showMainDialog() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        panel.add(new JLabel("Mode:"), gbc);
        JComboBox<String> modeBox = new JComboBox<>(new String[]{"Encrypt", "Decrypt"});
        gbc.gridx = 1; gbc.gridwidth = 2;
        panel.add(modeBox, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        panel.add(new JLabel("File:"), gbc);
        JTextField filePathField = new JTextField();
        filePathField.setEditable(false);
        gbc.gridx = 1; gbc.gridwidth = 1;
        panel.add(filePathField, gbc);
        JButton browseButton = new JButton("Browse...");
        gbc.gridx = 2; gbc.gridwidth = 1;
        panel.add(browseButton, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
        panel.add(new JLabel("Password:"), gbc);
        JPasswordField passwordField = new JPasswordField();
        gbc.gridx = 1; gbc.gridwidth = 2;
        panel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        JCheckBox secureDeleteCheck = new JCheckBox("Delete original securely (overwrite with random data before delete)");
        panel.add(secureDeleteCheck, gbc);

        final File[] selectedFile = new File[1];

        browseButton.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int result = chooser.showOpenDialog(panel);
            if (result == JFileChooser.APPROVE_OPTION) {
                selectedFile[0] = chooser.getSelectedFile();
                filePathField.setText(selectedFile[0].getAbsolutePath());
            }
        });

        int result = JOptionPane.showConfirmDialog(
                null, panel, "File Encryptor",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        );

        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        if (selectedFile[0] == null) {
            JOptionPane.showMessageDialog(null, "No file selected.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (selectedFile[0].isDirectory()) {
            JOptionPane.showMessageDialog(null,
                    "Folders cannot be encrypted directly. Please convert to ZIP (archive) format first.",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = passwordField.getPassword();
        if (password.length == 0) {
            JOptionPane.showMessageDialog(null, "Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        boolean isEncrypt = modeBox.getSelectedItem().equals("Encrypt");
        boolean secureDeleteRequested = secureDeleteCheck.isSelected();

        File inputFile = selectedFile[0];
        String inputPath = inputFile.getAbsolutePath();

        String outputPath;
        if (isEncrypt) {
            outputPath = inputPath + ".enc";
        } else {
            if (!inputPath.toLowerCase().endsWith(".enc")) {
                JOptionPane.showMessageDialog(null,
                        "Selected file does not have a .enc extension. Cannot decrypt.",
                        "Error", JOptionPane.ERROR_MESSAGE);
                Arrays.fill(password, '\0');
                return;
            }
            outputPath = inputPath.substring(0, inputPath.length() - 4);
        }

        File outputFile = new File(outputPath);
        if (outputFile.exists()) {
            int overwrite = JOptionPane.showConfirmDialog(null,
                    "Target file already exists:\n" + outputPath + "\nOverwrite?",
                    "File exists", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (overwrite != JOptionPane.YES_OPTION) {
                Arrays.fill(password, '\0');
                return;
            }
        }

        try {
            if (isEncrypt) {
                encryptFile(inputPath, outputPath, password);
            } else {
                decryptFile(inputPath, outputPath, password);
            }

            if (secureDeleteRequested) {
                try {
                    secureDelete(inputFile);
                } catch (IOException ioEx) {
                    JOptionPane.showMessageDialog(null,
                            "File processed successfully, but secure delete of the original failed:\n" + ioEx.getMessage(),
                            "Warning", JOptionPane.WARNING_MESSAGE);
                }
            }

            JOptionPane.showMessageDialog(null,
                    (isEncrypt ? "File successfully encrypted!\n" : "File successfully decrypted!\n") + outputPath,
                    "Success", JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(null,
                    "Operation failed:\n" + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
