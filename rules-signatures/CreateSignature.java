import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CreateSignature {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";

  public static void main(String[] args) throws Exception {

    String stringToHashAndEncrypt;
    if(args.length == 1) {
      stringToHashAndEncrypt = args[0];
    } else {
      System.out.println("Invalid usage. Pass oly one parameter: the fully classified class name." );
      System.exit(1);
      return;
    }

    //gen sha-1
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(stringToHashAndEncrypt.getBytes(StandardCharsets.UTF_8));

    String hashString = Base64.getEncoder().encodeToString(sha1.digest());

    System.out.println("string to hash = " + stringToHashAndEncrypt);
    System.out.println("sha1 = " + hashString);

    //crypt sha-1
    byte[] privateKeyBytes = Files.readAllBytes(Paths.get("key.pkcs8"));

    //for using in sources
    //byte[] privateKeyBytes = CreateSignature.class.getResourceAsStream("/key.pkcs8").readAllBytes();

    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);

    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
    byte[] encryptedMessageHash = cipher.doFinal(hashString.getBytes(StandardCharsets.UTF_8));

    //decrypt
    byte[] pubKeyBytes = Files.readAllBytes(Paths.get("publicKey.pub"));
    //for use in sources
    //byte[] pubKeyBytes = CreateSignature.class.getResourceAsStream("/publicKey.pub").readAllBytes();
    String publicKeyString = new String(pubKeyBytes, StandardCharsets.UTF_8);
    publicKeyString = publicKeyString.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
        .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
        .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

    System.out.println("pubkey=" + publicKeyString);

    byte[] decoded = Base64
        .getDecoder()
        .decode(publicKeyString);

    KeySpec keySpec = new X509EncodedKeySpec(decoded);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKey);

    
    byte[] decrypted = cipher2.doFinal(encryptedMessageHash);

    System.out.println("decrypt = " + new String(decrypted, StandardCharsets.UTF_8));
    System.out.println("*******\nencrypted signature (copy this):\n" + Base64.getEncoder().encodeToString(encryptedMessageHash) + "\n*******");
  }
}
