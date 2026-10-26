import java.security.MessageDigest;
import javax.crypto.Cipher;

public class LegacyAuth {
    public void encryptData() throws Exception {
        // Triggers DES rule
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        
        // Triggers SHA1 rule
        MessageDigest md = MessageDigest.getInstance("SHA-1");
    }
}