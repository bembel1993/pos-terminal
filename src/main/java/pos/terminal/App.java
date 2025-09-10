package pos.terminal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
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
	
    private static final String HMAC_KEY = "31101993";
    
    public static void main(String[] args) throws Exception {
    
    	String cardNumber = "4242424242424242";
        int amountCents = 33450;
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
        // payload (например, сериализованные данные транзакции)
        byte[] payload = transactionBytes;
        System.out.println("Payload: " + bytesToHex(payload));
        // 1. Генерация сессионного ключа
        SecretKey sessionKey = generateAESKey();
        System.out.println("Session key (hex): " + bytesToHex(sessionKey.getEncoded()));
        // 2. Шифрование payload
        byte[] encryptedPayload = encryptAESGCM(payload, sessionKey);
        System.out.println("Encrypted Payload: " + bytesToHex(encryptedPayload));
        // 3. RSA публичный ключ сервера (формат PEM)
        try {
            PublicKey serverPublicKey = loadPublicKey("C:/My Disc/app/1-JAVA APP/PEM/public_key.pem");
            System.out.println("Public Key: " + serverPublicKey);
        
            // 4. Шифрование сессионного ключа RSA-OAEP
            byte[] encryptedSessionKey = encryptSessionKeyRSA(sessionKey, serverPublicKey);
            System.out.println("Cypher session key: " + java.util.Base64.getEncoder().encodeToString(encryptedSessionKey));
        
            // 5. IV для AES-GCM
            byte[] iv = generateIV();

	        // 6. HMAC подпись данных (encryptedPayload)
	        String hmacSignature = generateHMACSHA256(encryptedPayload, HMAC_KEY);
	        byte[] hmacBytes = hmacSignature.getBytes(StandardCharsets.UTF_8);
	
	        // 7. Пакет
	        byte[] packet = buildPacket(encryptedSessionKey, iv, hmacBytes, encryptedPayload);
	
	        System.out.println("Final Packet (hex): " + bytesToHex(packet));
	        
	        parsePacket(packet);


     // 8) Отправляем данные на сервер
	        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
	             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {
	
	            // Отправляем зашифрованный RSA-ключ
	        	dos.writeInt(bytesToHex(encryptedSessionKey).length());
	            dos.writeBytes(bytesToHex(encryptedSessionKey));
	//        	Отправляем размер транзакции 
	            dos.writeInt(bytesToHex(transactionBytes).length());
	            dos.writeBytes(bytesToHex(transactionBytes));
	            
	            // Отправляем строки
	            dos.writeUTF(card);
	
	            // Отправляем сумму
	            dos.writeInt(amount);
	
	            // Отправляем транзакционную ID
	            dos.writeUTF(transId);
	
	            // Отправляем merchantId
	            dos.writeInt(merchtId);
	            
	            // Отправляем подпись	            
	            dos.writeUTF(signature);
	            
	            System.out.println("Encrypted data sent to server.");
	        } catch (Exception e) {
	        	System.out.println("Server is not launched, exception:" + e);
	        }
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
    }
    
    public static byte[] createTransaction(String cardNumber, int amountCents, int merchantId) {
        
        String maskedCard = maskCardNumber(cardNumber);

        String transactionId = generateTransactionId();

        // Фиксированные длины полей
        final int CARD_LEN = 20;     
        final int TRAN_ID_LEN = 50;  

        byte[] cardBytes = fixedLengthBytes(maskedCard, CARD_LEN);
        byte[] transIdBytes = fixedLengthBytes(transactionId, TRAN_ID_LEN);

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
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] encryptedData = cipher.doFinal(payload);
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        return byteBuffer.array();
    }
    
    
    public static byte[] encryptSessionKeyRSA(SecretKey sessionKey, PublicKey serverPublicKey) throws Exception {
        // Инициализация Cipher для RSA с OAEP
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        
        return cipher.doFinal(sessionKey.getEncoded());
    }
    
    
    public static PublicKey loadPublicKey(String filename) throws Exception {
    	String keyPem = new String(Files.readAllBytes(Paths.get(filename)), StandardCharsets.UTF_8);
        return getPublicKeyFromPem(keyPem);
    }
    
    private static PublicKey getPublicKeyFromPem(String pem) throws Exception {
        String publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                                  .replace("-----END PUBLIC KEY-----", "")
                                  .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    
    public static byte[] generateIV() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
    
    
    public static byte[] buildPacket(byte[] encryptedSessionKey, byte[] iv, byte[] hmac, byte[] encryptedTLVData) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Расчет общей длины
        int totalLength = 4 + encryptedSessionKey.length + iv.length + hmac.length + encryptedTLVData.length;

        // HEADER: 4 байта
        baos.write(0x01);
        baos.write(0x01);
        baos.write(ByteBuffer.allocate(2).putShort((short) totalLength).array()); // длина всего пакета

        // Остальные компоненты
        baos.write(encryptedSessionKey);
        baos.write(iv);
        baos.write(hmac);
        baos.write(encryptedTLVData);

        return baos.toByteArray();
    }
    
    
    public static void parsePacket(byte[] packetBytes) {
        if (packetBytes.length < 4) {
            System.out.println("Пакет слишком короткий для парсинга HEADER");
            return;
        }

        // Распарсить HEADER
        byte version = packetBytes[0];
        byte msgType = packetBytes[1];
        int totalLength = ByteBuffer.wrap(packetBytes, 2, 2).getShort() & 0xFFFF; // без знака

//        System.out.println("Версия: " + String.format("0x%02X", version));
//        System.out.println("Тип сообщения: " + String.format("0x%02X", msgType));
//        System.out.println("Общая длина (из HEADER): " + totalLength);
//        System.out.println("Фактическая длина байтов: " + packetBytes.length);

        if (packetBytes.length != totalLength) {
            System.out.println("Внимание: длина пакета не совпадает с длиной в HEADER!");
        }

        // Размеры компонентов
        int encSessionKeySize = 256;
        int ivSize = 12;
        int hmacSize = 32;

        int pos = 4;

        if (packetBytes.length < pos + encSessionKeySize + ivSize + hmacSize) {
            System.out.println("Пакет слишком короткий для ожидаемых компонентов");
            return;
        }

        byte[] encSessionKey = Arrays.copyOfRange(packetBytes, pos, pos + encSessionKeySize);
        pos += encSessionKeySize;

        byte[] iv = Arrays.copyOfRange(packetBytes, pos, pos + ivSize);
        pos += ivSize;

        byte[] hmac = Arrays.copyOfRange(packetBytes, pos, pos + hmacSize);
        pos += hmacSize;

        byte[] encryptedTLVData = Arrays.copyOfRange(packetBytes, pos, packetBytes.length);
        System.out.println("--------------------------------------------------------------");
        // Вывод компонентов в hex
        byte protocolVersion = packetBytes[0];
        byte messageType = packetBytes[1];

        System.out.println("=== HEADER ===");
        System.out.println("Версия протокола: " + String.format("0x%02X", protocolVersion));
        System.out.println("Тип сообщения: " + String.format("0x%02X", messageType));
        System.out.println("Общая длина пакета (из HEADER): " + totalLength);
        System.out.println("Фактическая длина байтов: " + packetBytes.length);
        System.out.println();
        System.out.println("ENCRYPTED_SESSION_KEY (hex): " + bytesToHex(encSessionKey));
        System.out.println("IV (hex): " + bytesToHex(iv));
        System.out.println("HMAC (hex): " + bytesToHex(hmac));
        System.out.println("ENCRYPTED_TLV_DATA (hex): " + bytesToHex(encryptedTLVData));
        
        System.out.println("--------------------------------------------------------------");
    }
}