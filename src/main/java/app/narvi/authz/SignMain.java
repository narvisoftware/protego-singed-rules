package app.narvi.authz;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SignMain {

  private static final long MAX_KEY_SIZE_BYTES = 8192L;

  private static final String UTF_8 = "UTF-8";

  private static final String SHA1_WITH_RSA = "SHA1withRSA";
  private static final String SUN_JSSE = "SunJSSE";
  private static final String RSA = "RSA";

  private static File pkcsKeyFile_;

  private static final char HEX_DIGIT [] = {
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  private static byte [] keyFileBytes_;
  private static Signature dsa_;
  private static KeyFactory keyFactory_;
  private static PrivateKey privateKey_;

  public static void main(String[] args) {
    try {
      pkcsKeyFile_ = new File("key.pkcs8");
      FileInputStream is = new FileInputStream(pkcsKeyFile_);

      final long length = pkcsKeyFile_.length();

      if ( length > MAX_KEY_SIZE_BYTES ) {
        throw new IOException( "Key file is too big!" );
      }

      int offset = 0;
      int read = 0;
      keyFileBytes_ = new byte[(int)length];
      while ( offset < keyFileBytes_.length
          && (read=is.read(keyFileBytes_, offset,
          keyFileBytes_.length-offset)) >= 0 ) {
        offset += read;
      }

//      byte[] publicKey = Base64.getDecoder().decode(pub_Key.getBytes());

      dsa_ = Signature.getInstance(SHA1_WITH_RSA);
      keyFactory_ = KeyFactory.getInstance(RSA);

      init();

//      System.out.println(
//          toHex(getSignature(
//              "app.narvi.example.AllowOwnTenantAccess".getBytes( UTF_8 ) )
//          ).toUpperCase()
//      );
      System.out.println("--;"+
          Base64.getEncoder().encodeToString(getSignature(
              "app.narvi.example.AllowOwnTenantAccess".getBytes( UTF_8 )))
      );

    } catch ( Exception e ) {
      // Wrap it, so every where that you use PKCS8RSASigner
      // you don't have to wrap the constructor in a try/catch.
      // But the caller should catch Error's though.
      throw new Error(e);
    }
  }

  public static byte [] getSignature ( byte [] message ) throws Exception {

    dsa_.update( message );
    return dsa_.sign();

  }

  private static void init ( ) throws Exception {

    InputStream is = null;
//
//    if ( !this.pkcsKeyFile_.exists() ) {
//      throw new FileNotFoundException( "RSA key file not found!" );
//    }

    // Get the size, in bytes, of the key file.
    final long length = pkcsKeyFile_.length();

    if ( length > MAX_KEY_SIZE_BYTES ) {
      throw new IOException( "Key file is too big!" );
    }

    try {
      pkcsKeyFile_ = new File("key.pkcs8");

      is = new FileInputStream(pkcsKeyFile_);

      int offset = 0;
      int read = 0;
      keyFileBytes_ = new byte[(int)length];
      while ( offset < keyFileBytes_.length
          && (read=is.read(keyFileBytes_, offset,
          keyFileBytes_.length-offset)) >= 0 ) {
        offset += read;
      }

    } catch ( IOException ioe ) {
      throw ioe;
    } finally {
      try {
        if ( is != null ) {
          is.close();
        }
      } catch ( IOException ioe ) {
        throw new Exception("Error, couldn't close FileInputStream", ioe);
      }
    }

    PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(
        keyFileBytes_ );

    // Get the private key from the key factory.
    privateKey_ = keyFactory_.generatePrivate( privKeySpec );

    // Init the signature from the private key.
    dsa_.initSign( privateKey_ );

  }
  public static String toHex ( byte [] bytes ) {

    if ( bytes == null ) {
      return null;
    }

    StringBuilder buffer = new StringBuilder(bytes.length*2);
    for ( byte thisByte : bytes ) {
      buffer.append(byteToHex(thisByte));
    }

    return buffer.toString();

  }

  private static String byteToHex ( byte b ) {
    char [] array = { HEX_DIGIT[(b >> 4) & 0x0f], HEX_DIGIT[b & 0x0f] };
    return new String(array);
  }

}
