import java.io.FileInputStream;
import java.nio.charset.Charset;
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

  private static final String FILE_TO_SIGN = "app.narvi.authz.rules.PolicyRuleClasses";

  public static void main(String[] args) throws Exception {

    System.out.println("TODO: write how to use");

    byte[] fileContent;
    if (args.length == 0) {
      System.out.println("No arguments. Signing file " + FILE_TO_SIGN);
      fileContent = getFileContent();
    } else if(args.length == 1) {
      System.out.println("Signing argument " + args[0]);
      fileContent = args[0].getBytes(StandardCharsets.UTF_8);
    } else {
      System.out.println("Invalid number of arguments");
      System.exit(2);
      return;
    }

    KeyStore keyStore = KeyStore.getInstance("JKS");
    keyStore.load(new FileInputStream("protego_keystore.jks"), "changeit".toCharArray());
    PrivateKey privateKey = (PrivateKey) keyStore.getKey("protegoKeyPair", "keyPass".toCharArray());
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] messageHash = md.digest(fileContent);
    System.out.println("Digest: " + messageHash);
    Signature signature = Signature.getInstance("SHA1withRSA");
    signature.initSign(privateKey);
    signature.update(messageHash);
    byte[] digitalSignature = signature.sign();

    String base64DigitalSignature = Base64.getEncoder().encodeToString(digitalSignature);

    if(args.length == 0) {
      writeFile(fileContent, base64DigitalSignature);
    } else {
      System.out.println(base64DigitalSignature);
    }

  }

  public static byte[] getFileContent() throws Exception {
    byte[] fileContent = Files.lines(Paths.get(FILE_TO_SIGN), StandardCharsets.UTF_8)
        .map(line -> line.trim())
        .filter(line -> !line.isBlank())
        .filter(line -> !line.startsWith("Signature:"))
        .collect(Collectors.joining("\n"))
        .getBytes(StandardCharsets.UTF_8);
    System.out.println("File content: \n" + new String(fileContent, StandardCharsets.UTF_8));
    return fileContent;
  }

  public static void writeFile(byte[] fileContent, String signature) throws Exception {
    Path newFile = Paths.get(FILE_TO_SIGN);
    if( ! Files.exists(newFile)) {
      Files.write(newFile, fileContent, StandardOpenOption.CREATE);
    } else {
      Files.write(newFile, fileContent, StandardOpenOption.TRUNCATE_EXISTING);
    }
    Path rulesFile = Paths.get(FILE_TO_SIGN);
    Files.writeString(rulesFile, "\nSignature: " + signature, StandardOpenOption.APPEND);
  }

}