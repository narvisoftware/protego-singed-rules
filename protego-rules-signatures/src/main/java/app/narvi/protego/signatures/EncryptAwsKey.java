package app.narvi.protego.signatures;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptAwsKey {

  public static void main(String[] args) throws Exception {
    encryptAWSKey();
  }

  public static void encryptAWSKey() throws Exception {
    String awsKey = "bpARtKZG6OEV3D+L/dVHAwIULA4qCd2nW4cyI5H/";
    CreateSignature signatureClass = new CreateSignature();
    signatureClass.loadPublicKey();
    signatureClass.encryptAndDecrypt(awsKey);
  }

}
