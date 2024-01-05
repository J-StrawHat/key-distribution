import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Date;

public class ServerB {
    private static final int PORT = 12345; // 监听的端口
    private static final String IDB = "36920231153244"; // B 的身份标识
    private static KeyPair keyPair; // RSA 密钥对

    private static final byte[] sharedKm = new byte[] {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef }; // A 与 B 共享的 Km

    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("B 端启动，等待连接...");

            try (Socket socket = serverSocket.accept();
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                 ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream())) {

                // 接收来自 A 的 IDA 和 N1
                String request = (String) ois.readObject();
                System.out.println("接收到来自 A 的信息: " + request);
                String[] parts = request.split(";");
                String IDAReceived = parts[0];
                String N1 = parts[1];

                // 生成会话密钥 Ks、N2，对 N1 进行一定规则的变换
                SecretKey ks = KeyUtil.generateSessionKey();
                String N2 = String.valueOf(new Date().getTime());
                String transformedN1 = transformN(N1);

                // 构建响应信息：Ks + IDA + IDB + N1 + N2
                String encodedKs = bytesToHex(ks.getEncoded());
                String combinedResponse = encodedKs + ";" + IDAReceived + ";" + IDB + ";" + N1 + ";" + N2;
                SecretKey keySpecKm = new SecretKeySpec(sharedKm, "DES");
                byte[] encryptedResponse = DesUtil.encrypt(combinedResponse.getBytes(), keySpecKm);
                oos.writeObject(encryptedResponse);
                oos.flush();

                // 接收来自 A 的 Ks 加密后 N2
                byte[] encryptedN2 = (byte[]) ois.readObject();
                byte[] decryptedN2 = DesUtil.decrypt(encryptedN2, ks);
                String decryptedN2String = new String(decryptedN2);
                if (decryptedN2String.equals(transformN(N2))) {
                    System.out.println("N2 验证成功，A 端已正确接收 Ks\n");
                    combinedResponse = "OK";
                } else {
                    System.out.println("N2 验证失败\n");
                    combinedResponse = "FAILED";
                }
                encryptedResponse = DesUtil.encrypt(combinedResponse.getBytes(), keySpecKm);
                oos.writeObject(encryptedResponse);
                oos.flush();


                // 接收加密的文件数据，并进行解密
                byte[] encryptedData = (byte[]) ois.readObject();
                byte[] decryptedData = DesUtil.decrypt(encryptedData, ks);
                String decryptedContent = new String(decryptedData);
                System.out.println("解密后的文件内容: \n" + decryptedContent);
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String transformN(String N1) {
        // 将 N1 的每个字符转换为对应的 ASCII 值，并以 '-' 分隔
        StringBuilder transformed = new StringBuilder();
        for (char c : N1.toCharArray()) {
            if (transformed.length() > 0) {
                transformed.append("-");
            }
            transformed.append((int) c);
        }
        return transformed.toString();
    }
}
