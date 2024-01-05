import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class ClientA {
    private static final String HOST = "127.0.0.1"; // B 端的 IP 地址
    private static final int PORT = 12345; // B 端监听的端口

    private static final int CA_PORT = 17788; // CA 端监听的端口
    private static final String IDA = "23020231154265"; // A 的身份标识

    private static KeyPair keyPair; // RSA 密钥对


    public static void main(String[] args) throws Exception {

        PublicKey caPublicKey;    // CA 的公钥
        X509Certificate userCert; // CA 为 A 端生成的公钥证书

        // 生成密钥对
        keyPair = RsaUtil.generateKeyPair();

        try (Socket socket = new Socket(HOST, CA_PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            // 向 CA 发送公钥及 IDA
            oos.writeObject(keyPair.getPublic());
            oos.writeObject(IDA);
            oos.flush();

            // 得到 CA 的公钥以及为 A 端生成的公钥证书
            caPublicKey = (PublicKey) ois.readObject();
            userCert = (X509Certificate) ois.readObject();
            if (!verifyCertificate(caPublicKey, userCert)) {
                throw new Exception("CA 生成的公钥证书存在问题");
            }
            else {
                System.out.println("CA 生成的公钥证书有效");
            }
        }

        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            // 向 B 端发送公钥证书
            oos.writeObject(userCert);
            oos.flush();

            // 获取 B 端的公钥证书
            X509Certificate userCertB = (X509Certificate) ois.readObject();
            if (!verifyCertificate(caPublicKey, userCert)) {
                throw new Exception("B 端的公钥证书存在问题");
            }
            else {
                System.out.println("B 端的公钥证书有效");
            }

            // 使用 B 端的公钥加密一个测试样例数据，然后发送
            int testVal = 100;
            ByteBuffer testBuffer = ByteBuffer.allocate(Integer.SIZE / Byte.SIZE);
            testBuffer.putInt(testVal);
            byte[] encryptedData = RsaUtil.encrypt(testBuffer.array(), userCertB.getPublicKey());
            oos.writeObject(encryptedData);
            oos.flush();

            // 接收 B 端使用 A 的公钥加密的样例数据计算结果，验证
            encryptedData = (byte[]) ois.readObject();
            encryptedData = RsaUtil.decrypt(encryptedData, keyPair.getPrivate());
            testBuffer = ByteBuffer.wrap(encryptedData);
            int outputVal = testBuffer.getInt();
            if (!verifyKeyDistribution(testVal, outputVal)) {
                throw new Exception("公钥分配失败");
            }
            else {
                System.out.println("公钥分配工作成功\n");
            }



            // 使用 B 端的公钥，对图像文件进行加密，然后发送
            File file = new File("src/test_pic.bmp");
            byte[] fileData = readFile(file);
            System.out.println("加密开始时间戳:" + System.currentTimeMillis());
            encryptedData = RsaUtil.encryptWithSegment(fileData, userCertB.getPublicKey());
            oos.writeObject(encryptedData);
            oos.flush();


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

    public static boolean verifyKeyDistribution(int testVal, int outputVal) {
        int res = testVal * 2;
        System.out.println("本地测试样例数据:" + testVal + ", 本地计算结果:" + res + ", 远端计算结果:" + outputVal);
        return res == outputVal;
    }



}
