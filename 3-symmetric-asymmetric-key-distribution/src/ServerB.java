import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ServerB {
    private static final int PORT = 12345; // 监听的端口
    private static final String IDB = "36920231153244"; // B 的身份标识

    private static KeyPair keyPair; // RSA 密钥对

    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("B 端启动，等待连接...");

            try (Socket socket = serverSocket.accept();
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

                // 接收来自 A 端的公钥
                PublicKey publicKeyA = (PublicKey) ois.readObject();

                // 生成密钥对，并发送公钥到 A 端
                keyPair = RsaUtil.generateKeyPair();
                oos.writeObject(keyPair.getPublic());
                oos.flush();

                System.out.println("完成公钥的分发工作\n");

                // 接收来自 A 使用 PKB 加密的 N1 + IDA
                byte[] encryptedData = (byte[]) ois.readObject();
                byte[] decryptedData = RsaUtil.decrypt(encryptedData, keyPair.getPrivate());
                String response = new String(decryptedData);
                System.out.println("接收到来自 A 的 PKB 加密响应：" + response);
                String[] responseParts = response.split(";");
                String N1 = responseParts[0];

                // 使用 A 的公钥对 N1 + N2 进行加密，然后发送
                String N2 = String.valueOf(new Date().getTime());
                encryptedData = RsaUtil.encrypt((N1 + ";" + N2).getBytes(), publicKeyA);
                oos.writeObject(encryptedData);
                oos.flush();

                // 接收来自 A 使用 PKB 加密的 N2，验证 A 是否接收正确的 N2
                encryptedData = (byte[]) ois.readObject();
                decryptedData = RsaUtil.decrypt(encryptedData, keyPair.getPrivate());
                String receivedN2 = new String(decryptedData);
                if (!N2.equals(receivedN2)) {
                    System.out.println("A 无效接收 N2");
                    throw new Exception();
                }
                System.out.println("A 正确地接收 N2");

                // 接收来自 A 经过二次加密的 ks ，先使用 B 的私钥进行解密，再使用 A 的公钥进行再解密
                encryptedData = (byte[]) ois.readObject();
                encryptedData = RsaUtil.decryptWithSegment(encryptedData, keyPair.getPrivate());
                byte[] ksbytes = RsaUtil.decrypt(encryptedData, publicKeyA);
                System.out.println("Ks (Base64): " + Base64.getEncoder().encodeToString(ksbytes));
                SecretKey ks = new SecretKeySpec(ksbytes, "DES");
                System.out.println("完成密钥分配工作\n");

                encryptedData = (byte[]) ois.readObject();
                decryptedData = DesUtil.decrypt(encryptedData, ks);
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


}
