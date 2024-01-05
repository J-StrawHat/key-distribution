import sun.security.krb5.internal.crypto.Des;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Date;
import java.util.Base64;

public class ClientA {
    private static final String HOST = "127.0.0.1"; // B 端的 IP 地址
    private static final int PORT = 12345; // B 端监听的端口
    private static final String IDA = "23020231154265"; // A 的身份标识

    private static KeyPair keyPair; // RSA 密钥对

    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            // 生成密钥对，并发送公钥到 B 端
            keyPair = RsaUtil.generateKeyPair();
            oos.writeObject(keyPair.getPublic());
            oos.flush();

            // 接收来自 B 端的公钥
            PublicKey publicKeyB = (PublicKey) ois.readObject();

            System.out.println("完成公钥的分发工作\n");

            // 使用 B 的公钥对 N1 + IDA 进行加密，然后发送
            String N1 = String.valueOf(new Date().getTime());
            byte[] encryptedData = RsaUtil.encrypt((N1 + ";" + IDA).getBytes(), publicKeyB);
            oos.writeObject(encryptedData);
            oos.flush();

            // 接收来自 B 使用 PKA 加密的 N1 + N2，验证 B 是否接收正确的 N1
            encryptedData = (byte[]) ois.readObject();
            byte[] decryptedData = RsaUtil.decrypt(encryptedData, keyPair.getPrivate());
            String response = new String(decryptedData);
            System.out.println("接收到来自 B 的 PKA 加密响应：" + response);
            String[] responseParts = response.split(";");
            String receivedN1 = responseParts[0];
            if (!N1.equals(receivedN1)) {
                System.out.println("B 无效接收 N1");
                throw new Exception();
            }
            System.out.println("B 正确地接收 N1");

            // 使用 B 的公钥对 N2 进行加密，然后发送
            String N2 = responseParts[1];
            encryptedData = RsaUtil.encrypt(N2.getBytes(), publicKeyB);
            oos.writeObject(encryptedData);
            oos.flush();

            // 使用私钥对 ks 加密后，再使用 B 的公钥进行二次加密，然后发送
            SecretKey ks = DesUtil.generateSessionKey();
            System.out.println("Ks (Base64): " + Base64.getEncoder().encodeToString(ks.getEncoded()));
            byte[] encryptedKs = RsaUtil.encrypt(ks.getEncoded(), keyPair.getPrivate());
            encryptedKs = RsaUtil.encryptWithSegment(encryptedKs, publicKeyB); // 第一次加密得到的数据量较大
            oos.writeObject(encryptedKs);
            oos.flush();
            System.out.println("完成密钥分配工作\n");

            // 使用 ks 对图像文件进行加密，然后发送
            File file = new File("src/test_pic.bmp");
            byte[] fileData = readFile(file);
            System.out.println("加密开始时间戳:" + System.currentTimeMillis());
            encryptedData = DesUtil.encrypt(fileData, ks);
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

}
