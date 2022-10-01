import java.math.BigInteger;
import java.security.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class RSA {
    private String hashAlgorithm; // Type of the hash algorithm
    private int k; // Length in octets of the modulus n
    private int hLen; // Length in octets of the specified hash algorithm

    /**
     * Generates private (d), public (e) exponents and modulus (n).
     * @return BigInteger map of 3 values with d, e and n accordingly as char keys.
     */
    Map<Character, BigInteger> generateKeys() throws NoSuchAlgorithmException {
        Map<Character, BigInteger> kS = new HashMap<>();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(k * 8); // in bits
        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        kS.put('d', ((RSAPrivateKey) privateKey).getPrivateExponent());
        kS.put('e', ((RSAPublicKey) publicKey).getPublicExponent());
        kS.put('n', ((RSAPrivateKey) privateKey).getModulus());

        return kS;
    }
    /**
     * Requests salt length for the RSASSA_PSS via console.
     * @return desired salt length as integer value.
     */
    int enterSaltLength(){
        int sLen;
        System.out.println("Enter desired length of the salt: ");
        Scanner scanner = new Scanner(System.in);
        try{
            sLen = Integer.parseInt(scanner.nextLine());
            if (sLen > k - hLen - 2)
                throw  new RuntimeException("Salt length is too large!");

        }
        catch (Exception ex){
            System.out.println("Something went wrong: " + ex);
            sLen = enterSaltLength();
        }
        return sLen;
    }
    /**
     * Requests key length in bits via console.
     * Sets length in octets of the modulus n.
     */
    void enterKeyLength() {
        System.out.println("Enter key length in bits: ");
        Scanner scanner = new Scanner(System.in);
        try{
            int keyLength = Integer.parseInt(scanner.nextLine());
            if (keyLength % 512 != 0) {
                System.out.println("Invalid key length!");
                enterKeyLength();
            }else {
                k = keyLength / 8;
            }
        }
        catch (Exception ex){
            System.out.println("Something went wrong: " + ex);
            enterKeyLength();
        }
    }
    /**
     * Calculates message digest length for a specified hashing algorithm.
     * @param hashAlgorithm intended hashing algorithm.
     * @return hash length.
     */
    private static int calculateHashLength(String hashAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return md.digest("".getBytes(StandardCharsets.UTF_8)).length;
    }
    /**
     * Requests hashing algorithm type via console until it is not valid.
     * Sets hash length in octets for specified algorithm.
     */
    void enterHashAlgorithm(){
        System.out.println("Enter hashing algorithm: ");
        Scanner scanner = new Scanner(System.in);
        String hAlg = scanner.nextLine();
        try{
            hLen = calculateHashLength(hAlg);
            hashAlgorithm = hAlg;
        }
        catch (NoSuchAlgorithmException e){
            System.out.println("Invalid hashing algorithm: " + e);
            enterHashAlgorithm();
        }
    }
    /**
     * Constructor for the RSA class.
     * Calls enterKeyLength() and enterHashAlgorithm() functions.
     */
    RSA(){
        enterKeyLength();
        enterHashAlgorithm();
    }
    /**
     * Encryption primitive.
     * @param e public exponent.
     * @param n public modulus.
     * @param m message representative, an integer between 0 and n - 1.
     * @return ciphertext representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSAEP(BigInteger e, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) < 0) || (m.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Message representative out of range!");
        }
        return m.modPow(e, n);
    }

    /**
     * Decryption primitive.
     * @param d private exponent.
     * @param n public modulus.
     * @param c ciphertext representative, an integer between 0 and n - 1.
     * @return message representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSADP(BigInteger d, BigInteger n, BigInteger c){
        if ((c.compareTo(BigInteger.ZERO) < 0) || (c.compareTo(n.subtract(BigInteger.ONE)) > -1)){
            throw new RuntimeException("Ciphertext representative out of range!");
        }
        return c.modPow(d, n);
    }
    /**
     * Digital signature primitive.
     * @param d private exponent.
     * @param n public modulus.
     * @param m message representative, an integer between 0 and n - 1.
     * @return signature representative, an integer between 0 and n - 1.
     */
    private static BigInteger RSASP1(BigInteger d, BigInteger n, BigInteger m){
        if ((m.compareTo(BigInteger.ZERO) < 0) || (m.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Message representative out of range!");
        }
        return m.modPow(d, n);
    }
    /**
     * Verification signature function primitive
     * @param e public exponent
     * @param n public modulus
     * @param s signature representative, an integer between 0 and n - 1
     * @return message representative, an integer between 0 and n - 1
     */
    private static BigInteger RSAVP1(BigInteger e, BigInteger n, BigInteger s){
        if ((s.compareTo(BigInteger.ZERO) < 0) || (s.compareTo(n.subtract(BigInteger.ONE)) > 0)){
            throw new RuntimeException("Signature representative out of range!");
        }
        return s.modPow(e, n);
    }
    /**
     * I2OSP converts a nonnegative integer into an octet string of a specified length.
     * @params x nonnegative integer to be converted.
     * @params xLen intended length of the resulting octet string.
     * @return octet string of length xLen.
     */
    private static byte[] I2OSP(BigInteger x, int xLen){
        if (x.compareTo(BigInteger.valueOf(256).pow(xLen)) > -1)
            throw new RuntimeException("Integer too large!");

        byte[] res = new byte[xLen];
        for(int i = 0; i != xLen; ++i){
            res[i] = (x.divide(BigInteger.valueOf(256).pow(xLen - i - 1)).byteValue());
        }
        return res;
    }
    /**
     * OS2IP converts an octet string into a nonnegative integer.
     * @params x octet string to be converted.
     * @return corresponding nonnegative integer.
     */
    private static BigInteger OS2IP(byte[] x){
        BigInteger res = BigInteger.ZERO;
        for (int i = 0; i != x.length; ++i){
            res = res.add(BigInteger.valueOf(x[i] & 0xFF).multiply(BigInteger.valueOf(256).pow(x.length - i - 1)));
        }
        return res;
    }
    /**
     * Hashing function.
     * @param str input message as an octet string.
     * @param hashAlgorithm intended type of the hash algorithm.
     * @return message digest as an octet string.
     */
    private static byte[] hashString(byte[] str, String hashAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        return md.digest(str);
    }
    /**
     * Mask generation function.
     * @param Z seed from which mask is generated, an octet string.
     * @param l intended length in octets of the mask.
     * @param hashAlgorithm intended type of the hash algorithm.
     * @return mask of l octets length.
     */
    private static byte[] MGF1(byte[] Z, int l, String hashAlgorithm) throws NoSuchAlgorithmException {

        int hLen = calculateHashLength(hashAlgorithm);
        if (l > Math.pow(2,hLen)) throw new RuntimeException("Mask too long!");
        byte[] T = new byte[l];

        byte[] tmp = new byte[Z.length + 4];
        System.arraycopy(Z, 0, tmp, 0, Z.length);
        int i = 0;
        for (int counter = 0; counter != Math.ceilDiv(l,hLen) - 1; ++ counter){
            byte[] C = I2OSP(BigInteger.valueOf(counter), 4);
            System.arraycopy(C, 0, tmp, Z.length, 4);
            byte[] tmp2 = hashString(tmp, hashAlgorithm);
            int k = 0;
            while(i < l && k < hLen) {
                T[i] = tmp2[k];
                k++; i++;
            }
        }
        return T;
    }
    /**
     * Generates random octet string.
     * @param len intended length in octets of the seed.
     * @return seed string of size len.
     */
    private static byte[] seedRandom(int len) throws NoSuchAlgorithmException {
        byte[] res = new byte[len];
        SecureRandom.getInstanceStrong().nextBytes(res);
        return res;
    }
    /**
     * Applies xor operation to the corresponding characters of string a and b.
     * @param a denotes first term.
     * @param b denotes second term.
     * @return string of \xor result.
     */
    private static byte[] XORStrings(byte[] a, byte[] b){
        if (a.length != b.length)
            throw new RuntimeException("Lengths of strings diverges!");
        byte[] res = new byte[a.length];
        for (int i = 0; i != a.length; ++i){
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }
    /**
     * Encryption operation.
     * Using specified hashing algorithm.
     * @param e public exponent.
     * @param n public modulus.
     * @param msg message to be encrypted, an octet string of length mLen.
     * @param l optional label to be associated with the message, by default, empty string.
     * @return ciphertext, an octet string of length k.
     */
    public byte[] RSAES_OAEP_ENCRYPT(BigInteger e, BigInteger n, String msg, String l)
            throws NoSuchAlgorithmException {

        // EME-OAEP Encoding:
        int mLen = msg.length();
        if (mLen > k - 2*hLen - 2) throw new RuntimeException("Message too long!");

        byte[] message = msg.getBytes(StandardCharsets.UTF_8);
        byte[] L = l.getBytes(StandardCharsets.UTF_8);

        byte[] lHash = hashString(L, hashAlgorithm);

        byte[] DB = new byte[k - hLen - 1];
        System.arraycopy(lHash, 0, DB, 0, hLen);
        for (int i = hLen; i != DB.length - 1 - mLen; ++i){
            DB[i] = 0x00;
        }
        DB[DB.length-1-mLen] = 0x01;
        System.arraycopy(message, 0, DB, DB.length - mLen, mLen);

        byte[] seed = seedRandom(hLen);
        byte[] dbMask = MGF1(seed, k - hLen - 1, hashAlgorithm);
        byte[] maskedDB = XORStrings(DB, dbMask);
        byte[] seedMask = MGF1(maskedDB, hLen, hashAlgorithm);
        byte[] maskedSeed = XORStrings(seed, seedMask);

        byte[] EM = new byte[k];
        EM[0] = 0x00;
        System.arraycopy(maskedSeed, 0, EM, 1, hLen);
        System.arraycopy(maskedDB, 0, EM, hLen + 1, k - hLen - 1);

        //RSA encryption:
        BigInteger m = OS2IP(EM);
        BigInteger c = RSAEP(e, n, m);
        return I2OSP(c, k);
    }
    // piece of overloading to achieve default associated label L
    public byte[] RSAES_OAEP_ENCRYPT(BigInteger e, BigInteger n, String msg)
            throws NoSuchAlgorithmException {
            return RSAES_OAEP_ENCRYPT(e ,n, msg,"");
    }
    /**
     * Decryption operation.
     * Using specified hashing algorithm.
     * @param d private exponent.
     * @param n public modulus.
     * @param ciphertext ciphertext to be decrypted, an octet string of length k.
     * @param l optional label associated with the message.
     * @return message, an octet string of length mLen, where mLen <= k - 2hLen - 2.
     */
    public byte[] RSAES_OAEP_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext, String l)
            throws NoSuchAlgorithmException {

        if (ciphertext.length != k || k < (2*hLen + 2))
            throw new RuntimeException("Decryption error!");
        //RSA Decryption:
        BigInteger c = OS2IP(ciphertext);
        BigInteger m = RSADP(d, n, c);
        byte[] EM = I2OSP(m, k);

        // EME-OAEP Decoding:
        if (l == null) l = "";
        byte[] lHash = hashString(l.getBytes(StandardCharsets.UTF_8), hashAlgorithm);
        byte Y = EM[0];

        byte[] maskedSeed = Arrays.copyOfRange(EM, 1, hLen+1);
        byte[] maskedDB = Arrays.copyOfRange(EM, hLen+1, k);
        byte[] seedMask = MGF1(maskedDB, hLen, hashAlgorithm);
        byte[] seed = XORStrings(maskedSeed, seedMask);
        byte[] dbMask = MGF1(seed, k - hLen - 1, hashAlgorithm);
        byte[] DB = XORStrings(maskedDB, dbMask);
        byte[] lHash1 = Arrays.copyOfRange(DB, 0, hLen);

        int index = hLen;
        while(index < DB.length && DB[index] != 0x01 ){
            index++;
        }
        byte[] M = Arrays.copyOfRange(DB,index+1, DB.length);
        if(DB[index] != 0x01 || !Arrays.equals(lHash, lHash1) || Y != 0)
            throw new RuntimeException();
        return M;
    }
    // Overloading to achieve default empty associated label:
    public byte[] RSAES_OAEP_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext)
            throws NoSuchAlgorithmException {
        return RSAES_OAEP_DECRYPT(d,n,ciphertext, "");
    }
    /**
     * Encryption operation.
     * @param e public exponent.
     * @param n public modulus.
     * @param msg message to be encrypted, an octet string of length mLen.
     * @return ciphertext, an octet string of length k.
     */
    public byte[] RSAES_PKCS1_V1_5_ENCRYPT(BigInteger e, BigInteger n, String msg)
            throws NoSuchAlgorithmException {

        int mLen = msg.length();
        if (mLen > k - 11) throw new RuntimeException("Message too long!");
        byte[] message = msg.getBytes(StandardCharsets.UTF_8);

        // EME-PKCS1-v1_5 encoding:
        byte[] PS = seedRandom(k-mLen-3);

        byte[] EM = new byte[k];
        EM[0] = 0x00; EM[1] = 0x02;
        System.arraycopy(PS, 0, EM, 2, PS.length);
        EM[PS.length+2] = 0x00;
        System.arraycopy(message, 0, EM, PS.length+3, mLen);

        //RSA encryption:
        BigInteger m = OS2IP(EM);
        BigInteger c = RSAEP(e, n, m);
        return I2OSP(c, k);
    }
    /**
     * Decryption operation.
     * @param d private exponent.
     * @param n public modulus.
     * @param ciphertext ciphertext to be decrypted, an octet string of length k.
     * @return message, an octet string of length mLen, where mLen <= k - 2hLen - 2.
     */
    public byte[] RSAES_PKCS1_V1_5_DECRYPT(BigInteger d, BigInteger n, byte[] ciphertext){

        if (ciphertext.length != k || k < 11)
            throw new RuntimeException("Decryption error!");
        //RSA Decryption:
        BigInteger c = OS2IP(ciphertext);
        BigInteger m = RSADP(d, n, c);
        byte[] EM = I2OSP(m, k);

        // EME-PKCS1-v1_5 decoding:

        int index = EM.length-1;
        while(index > 2 && EM[index] != 0x00 ){
            index--;
        }
        if(EM[0] != 0x00 || EM[1] != 0x02 || EM[index] != 0x00 || index-2 < 8)
            throw new RuntimeException();

        byte[] M = new byte[EM.length - index - 1];
        System.arraycopy(EM, index+1, M, 0, EM.length-index-1);

        return M;
    }

    /**
     * Sets leftmost bits to 0.
     * @param amount number of bits need to be set.
     * @param element conducted byte value.
     * @return byte element with amount bits equal 0.
     */
    public static byte calculateByte(int amount, byte element){
        for (int pos = 0; pos != amount+1; ++pos)
            element &= ~(1 << (8-pos));
        return element;
    }
    /**
     * Digital signature encoding operation.
     * @param M represents octet message string.
     * @param emBits length of the encoded message
     * @param sLen intended length of the salt.
     * @param hashAlgorithm desired hashing algorithm.
     * @return encoded message as an octet string of length emBits.
     */
    private byte[] EMSA_PSS_ENCODE(byte[] M, int emBits, int sLen, String hashAlgorithm) throws NoSuchAlgorithmException {
        int emLen = (int) Math.ceil(((double) (emBits)) / 8);
        int hLen = calculateHashLength(hashAlgorithm);
        if (emLen < hLen + sLen + 2)
            throw new RuntimeException("Encoding error!");

        byte[] mHash = hashString(M, hashAlgorithm);
        byte[] salt = seedRandom(sLen);

        byte[] M1 = new byte[8 + hLen + sLen];
        for(int i = 0; i != 8; ++i) M1[i] = 0x00;
        System.arraycopy(mHash, 0, M1, 8, hLen);
        System.arraycopy(salt, 0, M1, 8+hLen, sLen);

        byte[] H = hashString(M1, hashAlgorithm);
        byte[] PS = new byte[emLen - sLen - hLen - 2]; // 0x00 for all elements by default

        byte[] DB = new byte[emLen - hLen - 1];
        System.arraycopy(PS, 0, DB,0, PS.length);
        DB[PS.length] = 0x01;
        System.arraycopy(salt, 0, DB, PS.length + 1, sLen);

        byte[] dbMask = MGF1(H, emLen - hLen - 1, hashAlgorithm);
        byte[] maskedDB = XORStrings(DB, dbMask);
        maskedDB[0] = calculateByte(8*emLen - emBits, maskedDB[0]);

        byte[] EM = new byte[emLen];
        System.arraycopy(maskedDB, 0, EM,0, maskedDB.length);
        System.arraycopy(H, 0, EM, maskedDB.length, H.length);
        EM[emLen-1] = (byte) 0xbc;

        return EM;
    }
    /**
     * Digital signature verification function.
     * @param M intended message as octet string to be verified.
     * @param EM encrypted message of M
     * @param emBits maximal bit length of the integer OS2IP (EM)
     * @param sLen intended length of the salt.
     * @param hashAlgorithm intended hashing algorithm
     * @return boolean true if signature valid and false - otherwise.
     */
    private boolean EMSA_PSS_VERIFY(byte[] M, byte[] EM, int emBits, int sLen, String hashAlgorithm) throws NoSuchAlgorithmException {
        int emLen = EM.length;
        int hLen = calculateHashLength(hashAlgorithm);
        if ((emLen < hLen + sLen + 2) || (EM[emLen-1] != (byte) 0xbc))
            throw new RuntimeException("Inconsistent!");

        byte[] mHash = hashString(M, hashAlgorithm);

        byte[] maskedDB = new byte[emLen - hLen - 1];
        System.arraycopy(EM, 0, maskedDB, 0, maskedDB.length);

        byte[] H = new byte[hLen];
        System.arraycopy(EM, maskedDB.length, H, 0, hLen);

        if (maskedDB[0] != calculateByte(8*emLen - emBits, maskedDB[0]))
            throw new RuntimeException("Inconsistent!");

        byte[] dbMask = MGF1(H, emLen - hLen - 1, hashAlgorithm);
        byte[] DB = XORStrings(maskedDB, dbMask);

        if (DB[emLen - hLen - sLen - 2] != (byte) 0x01)
            throw new RuntimeException("Inconsistent!");

        // check from the first due to modified maskedDB[0]
        for (int i = 1; i != emLen - hLen - sLen - 2; ++i){
            if (DB[i] != (byte)(0x00))
                throw new RuntimeException("Inconsistent!");
        }

        byte[] M1 = new byte[8 + hLen + sLen];
        for(int i = 0; i != 8; ++i) M1[i] = 0x00;
        System.arraycopy(mHash, 0, M1, 8, hLen);
        System.arraycopy(DB, DB.length - sLen, M1, 8+hLen, sLen);
        byte[] H1 = hashString(M1, hashAlgorithm);

        return Arrays.equals(H1,H);
    }
    /**
     * Signature generation function.
     * @param d represents private key exponent.
     * @param n represents modulus.
     * @param msg intended message.
     * @param sLen intended length of the salt.
     * @return octet string of digital signature.
     */
    public byte[] RSASSA_PSS_SIGN (BigInteger d, BigInteger n, String msg, int sLen) throws NoSuchAlgorithmException {
        byte[] EM = EMSA_PSS_ENCODE(msg.getBytes(StandardCharsets.UTF_8), k*8 - 1, sLen, hashAlgorithm);
        BigInteger m = OS2IP(EM);
        BigInteger s = RSASP1 (d, n, m);
        return I2OSP(s, k);
    }
    /**
     * Signature verification function.
     * @param e represents public key exponent.
     * @param n represents modulus.
     * @param msg intended message.
     * @param sLen intended length of the salt.
     * @param S signature of msg.
     * @return boolean true if signature valid and false - otherwise.
     */
    public boolean RSASSA_PSS_VERIFY(BigInteger e, BigInteger n, String msg, int sLen, byte[] S) throws NoSuchAlgorithmException {
       try {
           if (S.length != k)
               throw new RuntimeException("Invalid signature!");
           BigInteger s = OS2IP(S);
           BigInteger m = RSAVP1(e, n, s);
           int emLen = (int) Math.ceil(((double) (k*8 - 1)) / 8);
           byte[] EM = I2OSP(m, emLen);
           return EMSA_PSS_VERIFY(msg.getBytes(StandardCharsets.UTF_8), EM, k*8 - 1, sLen, hashAlgorithm);
       }
       catch (RuntimeException ex){
           throw new RuntimeException("Invalid signature!");
       }
    }
}
