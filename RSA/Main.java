import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Map;
import java.util.Scanner;

public class Main {
    public static void outputCiphertext(byte[] ciphertext, String subject){
        StringBuilder sb = new StringBuilder(subject);
        for (byte b : ciphertext){
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb);
    }
    static private void testEM(RSA rsa, Map<Character, BigInteger> keys, Charset charset, String message){
        try {
            byte[] ciphertext;
            byte[] decryptedMessage;

            // RSAES-PSCS1-V1_5:
            ciphertext = rsa.RSAES_PKCS1_V1_5_ENCRYPT(keys.get('e'), keys.get('n'), message);
            outputCiphertext(ciphertext, "RSAES-PSCS1-V1_5 ciphertext: ");
            decryptedMessage = rsa.RSAES_PKCS1_V1_5_DECRYPT(keys.get('d'), keys.get('n'), ciphertext);
            System.out.println(new String(decryptedMessage, charset));

            // NO LABEL TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message);
            outputCiphertext(ciphertext, "RSAES-OAEP-ENCRYPT no label ciphertext: ");
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext);
            System.out.println(new String(decryptedMessage, charset));

            // CORRESPONDING LABELS TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, "Average label fun");
            outputCiphertext(ciphertext, "RSAES-OAEP-ENCRYPT corresponding labels ciphertext: ");
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, "Average label fun");
            System.out.println(new String(decryptedMessage, charset));

            //DIVERGENT LABELS TEST:
            ciphertext = rsa.RSAES_OAEP_ENCRYPT(keys.get('e'), keys.get('n'), message, "Average label fun");
            outputCiphertext(ciphertext, "RSAES-OAEP-ENCRYPT divergent labels ciphertext: ");
            decryptedMessage = rsa.RSAES_OAEP_DECRYPT(keys.get('d'), keys.get('n'), ciphertext, "Average label enjoyer");
            System.out.println(new String(decryptedMessage, charset));
        }
        catch (RuntimeException | NoSuchAlgorithmException ex){
            System.out.println(ex);
        }
    }
    static private void testDS(RSA rsa, Map<Character, BigInteger> keys, Charset charset, String message){
        try {
            byte[] DS;
            boolean res;
            int sLen = rsa.enterSaltLength();

            // VALID SIGNATURE TEST:
            DS = rsa.RSASSA_PSS_SIGN(keys.get('d'), keys.get('n'), message, sLen);
            outputCiphertext(DS, "RSASSA-PSS-SIGN digital signature: ");
            res = rsa.RSASSA_PSS_VERIFY(keys.get('e'), keys.get('n'), message, sLen, DS);
            System.out.println(res);

            // INVALID SIGNATURE TEST:
            DS = rsa.RSASSA_PSS_SIGN(keys.get('d'), keys.get('n'), message, sLen);
            outputCiphertext(DS, "RSASSA-PSS-SIGN digital signature: ");
            res = rsa.RSASSA_PSS_VERIFY(keys.get('e'), keys.get('n'), message + "divergent message", sLen, DS);
            System.out.println(res);
        }
        catch (RuntimeException | NoSuchAlgorithmException ex){
            System.out.println(ex);
        }

    }
    public static void main(String[] args) throws NoSuchAlgorithmException {
        RSA rsa = new RSA();
        // WARNING: INSECURE STORAGE. MADE IN EDUCATIONAL PURPOSES:
        Map<Character, BigInteger> keys = rsa.generateKeys();

        System.out.println("Enter message to be encrypted: ");
        Scanner scanner = new Scanner(System.in);
        String message = scanner.nextLine();
        Charset charset = StandardCharsets.UTF_8;

        testEM(rsa, keys, charset, message);
        testDS(rsa, keys, charset, message);
    }
}
