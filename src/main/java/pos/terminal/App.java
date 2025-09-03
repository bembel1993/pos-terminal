package pos.terminal;

import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class App {
	
    private static final String SERVER_HOST = "127.0.0.1";
    private static final int SERVER_PORT = 12345;
	
	// Предположим, ключ из конфигурации
    private static final String HMAC_KEY = "31101993";
    
    public static void main(String[] args) throws Exception {
    
    	String cardNumber = "4242424242424242";
        int amountCents = 33450; // например, 123.45
        int merchantId = 9876;

        byte[] transactionBytes = createTransaction(cardNumber, amountCents, merchantId);

        // Выводим в шестнадцатеричном виде для проверки
        System.out.println(bytesToHex(transactionBytes));
        decodeTransaction(transactionBytes);
        
        TransactionData data = decodeTransaction(transactionBytes);
        String card = data.getCardNumber();
        int amount = data.getAmount();
        String transId = data.getTransId();
        int merchtId = data.getMerchantId();
        // Подписываем данные HMAC-SHA-256
        String signature = generateHMACSHA256(transactionBytes, HMAC_KEY);
        System.out.println("HMAC-SHA-256 Signature: " + signature);
        System.out.println("--------------------------------------------------------/n");
     // Ваш payload (например, сериализованные данные транзакции)
//        byte[] payload = transactionBytes;
//        System.out.println(payload);
//        // 1. Генерация сессионного ключа
//        SecretKey sessionKey = generateAESKey();
//        System.out.println(sessionKey);
//        // 2. Шифрование payload
//        byte[] encryptedPayload = encryptAESGCM(payload, sessionKey);
//        System.out.println(encryptedPayload);
//        // 3. RSA публичный ключ сервера (загрузить из файла или строки в формате PEM)
//        PublicKey serverPublicKey = loadPublicKey(); // Реализуйте этот метод
//        System.out.println(serverPublicKey);
//        // 4. Шифрование сессионного ключа RSA-OAEP
//        byte[] encryptedSessionKey = encryptSessionKeyRSA(sessionKey, serverPublicKey);
//        System.out.println(encryptedSessionKey);
        // Передача:
        // - encryptedPayload
        // - encryptedSessionKey
        
     // 6) Отправляем данные на сервер
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            // Отправляем длину зашифрованного RSA-ключ
//            dos.writeInt(encryptedSessionKey.length);
            // Отправляем зашифрованный RSA-ключ
//            dos.write(encryptedSessionKey);
//        	dos.writeInt(transactionBytes.length);
            dos.writeInt(bytesToHex(transactionBytes).length());
            dos.writeBytes(bytesToHex(transactionBytes));
            
            // Запись строки
            dos.writeUTF(card);

            // Запись суммы
            dos.writeInt(amount);

            // Запись транзакционного ID
            dos.writeUTF(transId);

            // Запись merchantId
            dos.writeInt(merchtId);
            
            dos.writeUTF(signature);
//            dos.writeChars(signature);
//            // Отправляем длину зашифрованных данных
//            dos.writeInt(encryptedPayload.length);
//            // Отправляем зашифрованные данные
//            dos.write(encryptedPayload);
            System.out.println("Encrypted data sent to server.");
        } catch (Exception e) {
        	System.out.println("Server is not launched, exception:" + e);
        }
    }
    
    public static byte[] createTransaction(String cardNumber, int amountCents, int merchantId) {
        // Маскируем номер карты
        String maskedCard = maskCardNumber(cardNumber);

        // Генерируем уникальный transaction_id
        String transactionId = generateTransactionId();

        // Фиксированные длины полей
        final int CARD_LEN = 20;     // длина маскированного номера карты
        final int TRAN_ID_LEN = 50;  // длина transaction_id

        // Кодируем строки в байты с фиксированной длиной
        byte[] cardBytes = fixedLengthBytes(maskedCard, CARD_LEN);
        byte[] transIdBytes = fixedLengthBytes(transactionId, TRAN_ID_LEN);

        // Кодируем числовые поля
        ByteBuffer buffer = ByteBuffer.allocate(CARD_LEN + 4 + TRAN_ID_LEN + 4);

        buffer.put(cardBytes);
        buffer.putInt(amountCents);
        buffer.put(transIdBytes);
        buffer.putInt(merchantId);

        return buffer.array();
    }

    private static String maskCardNumber(String cardNumber) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cardNumber.length(); i++) {
            if (i < 4 || i >= cardNumber.length() - 4) {
                sb.append(cardNumber.charAt(i));
            } else {
                sb.append('*');
            }
        }
        return sb.toString();
    }

    private static String generateTransactionId() {
        UUID uuid = UUID.randomUUID();
        long timestamp = System.currentTimeMillis();
        return uuid.toString() + "_" + timestamp;
    }

    private static byte[] fixedLengthBytes(String str, int length) {
        byte[] bytes = new byte[length];
        byte[] strBytes = str.getBytes(StandardCharsets.UTF_8);
        int copyLength = Math.min(strBytes.length, length);
        System.arraycopy(strBytes, 0, bytes, 0, copyLength);
        // остальное заполняется нулями
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    public static TransactionData decodeTransaction(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);

        byte[] cardBytes = new byte[20];
        buffer.get(cardBytes);
        String card = new String(cardBytes, StandardCharsets.UTF_8).trim();

        int amount = buffer.getInt();

        byte[] transIdBytes = new byte[50];
        buffer.get(transIdBytes);
        String transId = new String(transIdBytes, StandardCharsets.UTF_8).trim();

        int merchantId = buffer.getInt();

        System.out.println("Card PAN: " + card);
        System.out.println("Amount: " + amount);
        System.out.println("Transaction ID: " + transId);
        System.out.println("Merchant ID: " + merchantId);
        
        TransactionData trData = new TransactionData(card, amount, transId, merchantId);
        
        return trData;
    }
    
    public static String generateHMACSHA256(byte[] data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hmacBytes = mac.doFinal(data);
            // Можно возвращать как hex или base64
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error while generating HMAC", e);
        }
    }
    
    
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }
    
    
    public static byte[] encryptAESGCM(byte[] payload, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // 12 байт для GCM
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedData = cipher.doFinal(payload);
        // Можно вернуть вместе IV и зашифрованные данные
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        return byteBuffer.array();
    }
    
    
    public static byte[] encryptSessionKeyRSA(SecretKey sessionKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(sessionKey.getEncoded());
    }
    
    
    public static PublicKey loadPublicKey() throws Exception {
        // Ваш публичный ключ в формате PEM (замените на свой ключ)
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArwLr1vO2EOGQb+wl1n7n\n" +
                "s0zL0sBc0XKcX7n7zFZ4XK7X6J4eQ6Xf4sG7W0lP0m1Zq9vV0O1zK3T7kF5fO7zE\n" +
                "Xk4x3QIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        // Удаляем строки с BEGIN и END, убираем переносы и пробелы
        String publicKeyPEMStr = publicKeyPEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        // Декодируем Base64
        byte[] decoded = Base64.getDecoder().decode(publicKeyPEMStr);

        // Создаем спецификацию ключа
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Возвращаем публичный ключ
        return keyFactory.generatePublic(keySpec);
    }
}
