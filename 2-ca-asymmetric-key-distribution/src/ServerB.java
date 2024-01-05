import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ServerB {
    private static final String HOST = "127.0.0.1"; // CA 端的 IP 地址
    private static final int PORT = 12345; // 监听的端口
    private static final int CA_PORT = 17788; // CA 端监听的端口
    private static final String IDB = "36920231153244"; // B 的身份标识
    private static KeyPair keyPair; // RSA 密钥对

    public static void main(String[] args) throws Exception {

        PublicKey caPublicKey;    // CA 的公钥
        X509Certificate userCert; // CA 为 B 端生成的公钥证书

        // 生成密钥对
        keyPair = RsaUtil.generateKeyPair();

        try (Socket socket = new Socket(HOST, CA_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            oos.writeObject(keyPair.getPublic());
            oos.writeObject(IDB);
            oos.flush();

            caPublicKey = (PublicKey) ois.readObject();
            userCert = (X509Certificate) ois.readObject();
            if (!verifyCertificate(caPublicKey, userCert)) {
                throw new Exception("CA 生成的公钥证书存在问题");
            }
            else {
                System.out.println("CA 生成的公钥证书有效");
            }

        }

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("B 端启动，等待客户端的连接...");

            try (Socket socket = serverSocket.accept();
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

                // 获取 A 端的公钥证书
                X509Certificate userCertA = (X509Certificate) ois.readObject();
                if (!verifyCertificate(caPublicKey, userCert)) {
                    throw new Exception("A 端的公钥证书存在问题");
                }
                else {
                    System.out.println("A 端的公钥证书有效");
                }

                // 向 A 端发送公钥证书
                oos.writeObject(userCert);
                oos.flush();

                // 接收 A 端使用 B 的公钥加密的测试样例数据
                byte[] encryptedData = (byte[]) ois.readObject();
                byte[] decryptedData = RsaUtil.decrypt(encryptedData, keyPair.getPrivate());
                ByteBuffer testBuffer = ByteBuffer.wrap(decryptedData);
                int testVal = testBuffer.getInt();

                // 对样例数据进行计算，再使用 A 端的公钥加密，然后发送
                testVal *= 2;
                testBuffer = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
                testBuffer.putInt(testVal);
                encryptedData = RsaUtil.encrypt(testBuffer.array(), userCertA.getPublicKey());
                oos.writeObject(encryptedData);
                oos.flush();

                encryptedData = (byte[]) ois.readObject();
                decryptedData = RsaUtil.decryptWithSegment(encryptedData, keyPair.getPrivate());
                System.out.println("解密结束时间戳:" + System.currentTimeMillis());
                byte[] testFileData = readFile(new File("src/test_pic.bmp"));
                if (Arrays.equals(testFileData, decryptedData)) {
                    System.out.println("两个图像文件相同，加密和解密过程正确。");
                } else {
                    System.out.println("两个图像文件相同，存在问题。");
                    throw new Exception();
                }

                File outputFile = new File("src/output_pic.bmp");
                writeFile(decryptedData, outputFile);


            }
        }
    }

    private static void writeFile(byte[] data, File file) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }

    public static boolean verifyCertificate(PublicKey caPublicKey, X509Certificate certificate) {
        try {
            // 用CA的公钥验证证书签名
            certificate.verify(caPublicKey);
            return true;
        } catch (CertificateException | NoSuchAlgorithmException |
                 InvalidKeyException | NoSuchProviderException |
                 SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }


}
