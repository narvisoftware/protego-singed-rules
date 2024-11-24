package app.narvi.protego.signatures.rules.conf;

import java.lang.invoke.MethodHandles;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;

import javassist.ClassPool;
import javassist.CtClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PolicyRuleCofiguration {

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  private static final String ALGORITHM = "RSA";

  private String className;
  private String signature;

  public PolicyRuleCofiguration() {
  }

  public PolicyRuleCofiguration(String className) {
    this.className = className;
  }

  public PolicyRuleCofiguration(String className, String signature) {
    this.className = className;
    this.signature = signature;
  }

  public String getClassName() {
    return className;
  }

  public void setClassName(String className) {
    this.className = className;
  }

  public String getSignature() {
    return signature;
  }

  public void setSignature(String signature) {
    this.signature = signature;
  }

  public void verifySignature(String publicKeyAsString) {
    try {

      String unencryptedHash = getClassHash();
      LOG.debug("Class bytecode hash: "+ unencryptedHash);

      byte[] decryptedAsBytes = decrypt(publicKeyAsString, signature);
      String decryptedSignature =  Base64.getEncoder().encodeToString(decryptedAsBytes);
      LOG.debug("Decrypted signature: " + decryptedSignature);

      if (!decryptedSignature.equals(unencryptedHash)) {
        throw new SignatureUnmatchException("signature does not match!");
      } else {
        LOG.debug("Signature match: " + decryptedSignature + " = " + unencryptedHash);
      }
    } catch (Exception e) {
      throw new SignatureUnmatchException("Something went wrong while verifying signature.", e);
    }
  }

  public byte[] decrypt(String publicKeyAsString, String input) throws Exception {
    byte[] decodedPubKeyBytes = Base64.getDecoder().decode(publicKeyAsString);
    KeySpec keySpec = new X509EncodedKeySpec(decodedPubKeyBytes);

    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    PublicKey publicKey = keyFactory.generatePublic(keySpec);

    final Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher2.init(Cipher.DECRYPT_MODE, publicKey);

    LOG.debug("Signature: " + input);
    byte[] encryptedMessageHash = Base64.getDecoder().decode(input);

    return cipher2.doFinal(encryptedMessageHash);
  }

  public String getClassHash() throws Exception {
    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
    sha1.reset();
    sha1.update(getClassFingerprint());

    return Base64.getEncoder().encodeToString(sha1.digest());
  }

  public byte[] getClassFingerprint() throws Exception {
    ClassPool cp = ClassPool.getDefault();
    CtClass cc = cp.get(className);
    byte[] bytecode = cc.toBytecode();
    /*
        class file contains:
        ClassFile {
            u4   magic;
            u2   minor_version;
            u2   major_version;
            .....
        }
        magic u4 is Hex: "CAFE BABE"
        version (4bytes) for java 22 is version 66.0 (HEX: "0000 0042")
     */
    byte[] bytecodeWithoutVersion = Arrays.copyOfRange(bytecode, 4 + 2 + 2, bytecode.length);
    return bytecodeWithoutVersion;
  }
}
