import java.io.ByteArrayOutputStream;
import java.security.*;
import javax.crypto.Cipher;

public class RsaUtil {

    private static final int keySize = 512;

    // 生成密钥对 KeyPair (公钥与私钥)
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    // 使用指定的密钥 key 对 data 进行加密
    public static byte[] encrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // 使用指定的密钥 key 对 数据量较大的 data 进行分段加密
    public static byte[] encryptWithSegment(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int inputLen = data.length;
        int maxBlockSize = keySize / 8 - 11; // 减去PKCS#1填充的大小
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int offset = 0; // 数据起始位置
        while (inputLen - offset > 0) {
            byte[] buffer;
            if (inputLen - offset > maxBlockSize) {
                buffer = cipher.doFinal(data, offset, maxBlockSize);
            } else {
                buffer = cipher.doFinal(data, offset, inputLen - offset);
            }
            out.write(buffer, 0, buffer.length);
            offset += maxBlockSize;
        }

        return out.toByteArray();
    }

    //  使用指定的密钥 key 对 数据量较大的 data 进行分段解密
    public static byte[] decryptWithSegment(byte[] encryptedData, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        int inputLen = encryptedData.length;
        int maxBlockSize = keySize / 8; // RSA解密的块大小
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int offset = 0; // 数据起始位置
        while (inputLen - offset > 0) {
            byte[] buffer;
            if (inputLen - offset > maxBlockSize) {
                buffer = cipher.doFinal(encryptedData, offset, maxBlockSize);
            } else {
                buffer = cipher.doFinal(encryptedData, offset, inputLen - offset);
            }
            out.write(buffer, 0, buffer.length);
            offset += maxBlockSize;
        }

        return out.toByteArray();
    }

    // 使用指定的密钥 key 对 data 进行解密
    public static byte[] decrypt(byte[] data, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

}
