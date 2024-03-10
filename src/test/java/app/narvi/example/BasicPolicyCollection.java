package app.narvi.example;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;

import app.narvi.authz.PolicyEvaluator;
import app.narvi.authz.PolicyRulesProvider;
import app.narvi.authz.RulesCollection;

public class BasicPolicyCollection implements RulesCollection {

  public static final String NEW_LINE_CHARACTER = "\n";
  public static final String PUBLIC_KEY_START_KEY_STRING = "-----BEGIN PUBLIC KEY-----";
  public static final String PUBLIC_KEY_END_KEY_STRING = "-----END PUBLIC KEY-----";
  public static final String EMPTY_STRING = "";
  public static final String NEW_CR_CHARACTER = "\r";
  private static final String ALGORITHM = "RSA";
  public static String  secretMessage  = "Some random words in no particular order.";


  private static String publicKey = """
      -----BEGIN CERTIFICATE-----
      MIIBPjCB6aADAgECAgRqidUjMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCU5h
      cnZpLmFwcDAgFw0yNDAyMjUxNzE1MzhaGA8zMDIzMDYyODE3MTUzOFowFDESMBAG
      A1UEAxMJTmFydmkuYXBwMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK7HEGB5v/rS
      rFIGc4cgPcLutv8QscSEsf2AZnlEGyKWFZraXV0+LmR4QdFdhXUGY0bTR7YQ0YkZ
      QVes6rR8KZsCAwEAAaMhMB8wHQYDVR0OBBYEFNdwFXr+PNvrG+3jjRjUXUtJQJmP
      MA0GCSqGSIb3DQEBCwUAA0EAZLTA1awMTmwkLvkpPA7BDvPqCxjBnB3iuiOs8Foo
      4gb07hYoX0WaF8+F6SHSFCYvBxjp13Jbe0KgMK/tF4PS+w==
      -----END CERTIFICATE-----
      """;

  private final List<PolicyRulesProvider> rulesProviders = List.of(
      () -> Arrays.asList(
          new AllowOwnTenantAccess(),
          new EveryoneCanReadPublicCatalogs()
      )
  );

  public BasicPolicyCollection() {
    PolicyEvaluator.registerRulesCollection(this);
    String publicKeyPEM = publicKey
        .replace("-----BEGIN CERTIFICATE-----\n", "")
        .replaceAll("\n", "")
        .replace("-----END CERTIFICATE-----", "");

    byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);


      System.out.println("\"" + publicKeyPEM + "\"");
//      X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encoded);
//      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//      PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
      try {

//        String signature = new AllowOwnTenantAccess().getSignature();
//
        byte[] inStream = publicKeyPEM.getBytes(StandardCharsets.UTF_8);
//
//        InputStream inputStream = new ByteArrayInputStream(inStream);
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
//        PublicKey pubKey = cert.getPublicKey();
//
//        Cipher encryptCipher = Cipher.getInstance("RSA");
//        encryptCipher.init(Cipher.DECRYPT_MODE, pubKey);
//
//        byte[] cipherText = encryptCipher.doFinal(signature.getBytes(StandardCharsets.UTF_8));
//
//        inputStream.close();
//        System.out.println(Base64.getEncoder().encodeToString(cipherText));

//        InputStream inputStream = new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8));
//        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//        X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(inputStream);
//        PublicKey pk = certificate.getPublicKey();
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
//        cipher.init(Cipher.ENCRYPT_MODE, pk);
//        System.out.println(Base64.getEncoder().encodeToString(cipher.doFinal(new AllowOwnTenantAccess().getSignature().getBytes(StandardCharsets.UTF_8))));

        String pubData = publicKey
            .replaceAll("\\n", "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .trim();

        String pub_Key= """
            -----BEGIN PUBLIC KEY-----
            MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANBDvIXw1CBTvwHprFeSeAzVIQ7RoqDr
            rHNr7BBrmtzLO/Rxc1Rvnu99G4z8wAPe3nAJeQLtHjmHwJWsheFh2bcCAwEAAQ==
            -----END PUBLIC KEY-----
            """;
        pub_Key=pub_Key.replaceAll(NEW_LINE_CHARACTER, EMPTY_STRING)
            .replaceAll(PUBLIC_KEY_START_KEY_STRING, EMPTY_STRING)
            .replaceAll(PUBLIC_KEY_END_KEY_STRING, EMPTY_STRING)
            .replaceAll(NEW_CR_CHARACTER, EMPTY_STRING);

        byte[] publicKey = Base64.getDecoder().decode(pub_Key.getBytes());
        try {
          byte[] encryptedData = encrypt(publicKey,
              "plm".getBytes());

          String encryptedString = Base64.getEncoder().encodeToString(encryptedData);

          System.out.println("Output encryptedString: " + encryptedString);
        } catch (Exception e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }


      } catch (Exception e) {
        throw new RuntimeException("Unavailable RSA algorithm.", e);
      }
    }

  public static byte[] encrypt(byte[] publicKey, byte[] inputData)
      throws Exception {

    PublicKey key = KeyFactory.getInstance(ALGORITHM)
        .generatePublic(new X509EncodedKeySpec(publicKey));

    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, key);

    byte[] encryptedBytes = cipher.doFinal(inputData);

    return encryptedBytes;
  }

  @Override
  public Iterable<PolicyRulesProvider> getRulesProviders() {
    return rulesProviders;
  }


}
