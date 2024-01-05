import sun.security.x509.*;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class CertificateAuthority {
    private static final int PORT = 17788; // 监听的端口

    private static final long VALIDITY_PERIOD = 365L * 24 * 60 * 60 * 1000; // 有效期为1年

    private static KeyPair caKeyPair;

    public static void main(String[] args) throws Exception {
        caKeyPair = RsaUtil.generateKeyPair();

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("CA 端启动，等待连接...");

            // 循环监听一个连接
            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("接收到新的用户连接");

                // 为每个连接创建一个新的线程
                new Thread(new ClientHandler(socket)).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                // 获取输入和输出流
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

                // 读取用户的公钥和主题DN
                PublicKey userPublicKey = (PublicKey) input.readObject();
                String subjectDN = (String) input.readObject();

                // 生成证书
                X509Certificate certificate = generateCertificate(userPublicKey, subjectDN);

                // 将证书和CA的公钥发送给客户端
                output.writeObject(caKeyPair.getPublic());
                output.writeObject(certificate);
                System.out.println("向该用户颁发证书");

                // 关闭连接
                socket.close();
                System.out.println("用户连接关闭\n");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static X509Certificate generateCertificate(PublicKey publicKey, String userID) throws Exception {
        // 创建证书有效期
        Date from = new Date();
        Date to = new Date(from.getTime() + VALIDITY_PERIOD);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // 使用CA的私钥和用户公钥创建证书
        String subjectDN = "CN=" + userID;
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(from, to));
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, new X500Name(subjectDN));
        info.set(X509CertInfo.ISSUER, new X500Name("CN=CertificateAuthority"));
        info.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // 创建未签名的证书
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(caKeyPair.getPrivate(), "SHA256withRSA");

        // 更新算法字段
        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(caKeyPair.getPrivate(), "SHA256withRSA");

        return cert;
    }
}