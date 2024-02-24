import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class SignFile {

  public static void main(String[] args) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream("protego_keystore.jks"), "changeit".toCharArray());
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("protegoKeyPair", "keyPass".toCharArray());
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] fileContent = getFileContent();
    byte[] messageHash = md.digest(fileContent);

    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(messageHash);
    byte[] digitalSignature = signature.sign();

    String base64DigitalSignature = Base64.getEncoder().encodeToString(digitalSignature);
    writeFile(fileContent, base64DigitalSignature);

  }

  public static byte[] getFileContent() throws Exception {
    byte[] fileContent = Files.lines(Paths.get("app.narvi.authz.rules.PolicyRuleClasses"), StandardCharsets.UTF_8)
        .map(line -> line.trim())
        .filter(line -> !line.startsWith("Signature:"))
        .collect(Collectors.joining("\n"))
        .getBytes(StandardCharsets.UTF_8);
    System.out.println("File content: \n" + new String(fileContent, StandardCharsets.UTF_8));
    return fileContent;
  }

  public static void writeFile(byte[] fileContent, String signature) throws Exception {
    Path newFile = Paths.get("app.narvi.authz.rules.PolicyRuleClasses");
    if( ! Files.exists(newFile)) {
      Files.write(newFile, fileContent, StandardOpenOption.CREATE);
    } else {
      Files.write(newFile, fileContent, StandardOpenOption.TRUNCATE_EXISTING);
    }
    Path rulesFile = Paths.get("app.narvi.authz.rules.PolicyRuleClasses");
    Files.writeString(rulesFile, "\nSignature: " + signature, StandardOpenOption.APPEND);
  }

}