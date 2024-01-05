import java.io.*;
import java.net.Socket;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.math.BigInteger;

public class ClientA {
    private static final String HOST = "127.0.0.1"; // B 端的 IP 地址
    private static final int PORT = 12345; // B 端监听的端口
    private static final String IDA = "23020231154265"; // A 的身份标识

    private static final byte[] sharedKm = new byte[] {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef }; // A 与 B 共享的 Km

    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            // 生成 N1（可以是时间戳），接着发送 IDA 和 N1 给 B
            String N1 = String.valueOf(new Date().getTime());
            oos.writeObject(IDA + ";" + N1);
            oos.flush();

            // 接收来自 B 的加密响应，并使用 Km 解密响应
            byte[] encryptedResponse = (byte[]) ois.readObject();
            SecretKey keySpecKm = new SecretKeySpec(sharedKm, "DES");
            byte[] decryptedResponse = DesUtil.decrypt(encryptedResponse, keySpecKm);
            String response = new String(decryptedResponse);
            System.out.println("接收到来自 B 的 Km 加密响应：" + response);
            String[] responseParts = response.split(";");

            // 提取 Ks 和 N2
            byte[] ksBytes = hexStringToByteArray(responseParts[0]);
            SecretKey ks = new SecretKeySpec(ksBytes, "DES");
            String N2 = responseParts[4];

            // 对 N2 进行变换并使用 Ks 加密，接着发送给 B
            String transformedN2 = transformN(N2);
            byte[] encryptedN2 = DesUtil.encrypt(transformedN2.getBytes(), ks);
            oos.writeObject(encryptedN2);
            oos.flush();

            // 接收 B 的应答，确认 B 对 Ks 的验证
            encryptedResponse = (byte[]) ois.readObject();
            decryptedResponse = DesUtil.decrypt(encryptedResponse, keySpecKm);
            response = new String(decryptedResponse);
            System.out.println("接收 B 的应答：" + response);
            if ("OK".equals(response)) {
                // 使用 Ks 加密文件，接着发送给 B
                File file = new File("src/test-1.txt");
                byte[] fileData = readFile(file);
                byte[] encryptedData = DesUtil.encrypt(fileData, ks);
                oos.writeObject(encryptedData);
                oos.flush();
            }
            else {
                System.out.println("B 拒绝接收新的消息");
            }

        }
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return data;
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        // 将十六进制字符串转换为字节数组
        if ((s.length() % 2) != 0) { // 确保十六进制字符串长度为偶数
            s = "0" + s;
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static String transformN(String N2) {
        // 将 N2 的每个字符转换为对应的 ASCII 值，并以 '-' 分隔
        StringBuilder transformed = new StringBuilder();
        for (char c : N2.toCharArray()) {
            if (transformed.length() > 0) {
                transformed.append("-");
            }
            transformed.append((int) c);
        }
        return transformed.toString();
    }
}