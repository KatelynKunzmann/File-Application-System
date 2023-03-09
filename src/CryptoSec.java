import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**Implement helper method to create RSA Signature given private key  working on it (Taha)
Implement helper method to verify RSA Signature given signature and public key 
 */

public class CryptoSec {
    CryptoSec() {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    public KeyPair genRSAKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            SecureRandom randSrc = new SecureRandom();
            gen.initialize(2048, randSrc);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("There was error generating RSA keypair");
            e.printStackTrace();
        }
        return null;
    }

    public RSAPublicKey readRSAPublicKey(String fileName) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(fileName + ".public"));
            byte[] pubBytes = pemReader.readPemObject().getContent();
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA");
        } catch (FileNotFoundException e) {
            System.out.println("Could not find " + fileName + ".public");
        } catch (IOException e) {
            System.out.println("Error reading in public key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The public key encoding was improperly configured so turning it back into a" +
                    " RSAPublicKey key failed");
        }
        return null;
    }

    public RSAPrivateKey readRSAPrivateKey(String fileName) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PemReader pemReader = new PemReader(new FileReader(fileName + ".private"));
            byte[] privBytes = pemReader.readPemObject().getContent();
            return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error finding RSA algorithm");
        } catch (FileNotFoundException e) {
            System.out.println("Unable to find RSA private key for " + fileName);
        } catch (IOException e) {
            System.out.println("Error reading in private key");
        } catch (InvalidKeySpecException e) {
            System.out.println("The private key encoding was improperly configured so turning it back into a" +
                    " RSAPrivateKey key failed");
            e.printStackTrace();
        }

        return null;
    }

    public boolean writeKeyPair(String username, KeyPair keypair) {
        try {
            // Write public key to file
            String pubFilename = username + ".public";
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename)));
            pemWriter.writeObject(new PemObject("RSA PUBLIC KEY", keypair.getPublic().getEncoded()));
            pemWriter.close();

            // Write private key to file
            String privFilename = username + ".private";
            pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(privFilename)));
            pemWriter.writeObject(new PemObject("RSA PRIVATE KEY", keypair.getPrivate().getEncoded()));
            pemWriter.close();

            return true;
        } catch (IOException e) {
            System.out.println("Error writing key to file.");
        }
        return false;
    }

    public boolean writePubKey(String filename, RSAPublicKey pubKey) {
        try {
            // Write public key to file
            String pubFilename = filename + ".public";
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(pubFilename)));
            pemWriter.writeObject(new PemObject("RSA PUBLIC KEY", pubKey.getEncoded()));
            pemWriter.close();
            return true;
        } catch (IOException e) {
            System.out.println("Error writing public key to file.");
            e.printStackTrace();
        }
        return false;
    }

    public String byteArrToHexStr(byte [] byteArr) {
        StringBuilder hexStr = new StringBuilder();
        for (byte b: byteArr) {
            hexStr.append(String.format("%02x", b));
        }
        return hexStr.toString();
    }

    public boolean writeStrToFile(String filename, String str) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(filename + ".txt"));
            bw.write(str);
            bw.close();
            return true;
        } catch (IOException e) {
            System.out.println("There was an issue writing string to " + filename + ".txt");
        }
        return false;
    }

    public KeyPair genECDHKeyPair() {
       try {
           ECGenParameterSpec ecAlgoSpec = new ECGenParameterSpec("secp256r1");
           KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
           keyGen.initialize(ecAlgoSpec);
           return keyGen.generateKeyPair();
       } catch (NoSuchAlgorithmException e) {
           System.out.println("Invalid algorithm specified for ECDH keygen");
           e.printStackTrace();
       } catch (InvalidAlgorithmParameterException e) {
           System.out.println("Invalid algorithm parameters specified for ECDH keygen");
           e.printStackTrace();
       }
       return null;
    }


    public byte[] rsaSign(RSAPrivateKey privateKey, byte[] msg) {
        try {
            Signature rsaSig = Signature.getInstance("SHA256withRSA", "BC");
            rsaSig.initSign(privateKey);
            rsaSig.update(msg);
            return rsaSig.sign();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Signature algorithm specified not found");
            e.printStackTrace();
        } catch (SignatureException e) {
            System.out.println("Issue signing RSA");
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("Invalid security provider provided for RSA signature");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key specified for RSA signature");
            e.printStackTrace();
        }
        return null;
    }

    /** Generate shared secret Kab
    * @param privateKey - ECDH private key of party calling this function
    * @param publicKey - ECDH public key of other party provided by party calling this function
    * return - byte[] of shared secret
    */
    public byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH", "BC");
            keyAgree.init(privateKey);
            keyAgree.doPhase(publicKey, true);
            return keyAgree.generateSecret();
        } catch(IllegalStateException e) {
            System.err.println("Error: Illegal state");
            e.printStackTrace();        
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: No algorithm exists");
            e.printStackTrace();
        } catch(InvalidKeyException e) {
            System.err.println("Error: Invlid Key");
            e.printStackTrace();
        } catch(NoSuchProviderException e) {
            System.err.println("Error: No such provider exists");
            e.printStackTrace();
        }
        return null;
    }


    /**
     * Given an object that implements Serializable, serializes it
     * into a byte array which it returns
     * @param obj this is any object that implements Serializable
     * @return byte[] containing the serialized object
     * **/
    public byte[] serializeObject(Object obj) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream serialize = new ObjectOutputStream(bos);
            serialize.writeObject(obj);
            serialize.flush();
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * Given shared secret Kab and a message with encrypted contents,
     * verifies the HMAC, decrypts the contents, deserializes contents
     * back into an envelope and returns it.
     * Returns null if HMAC verification fails
     * @param msg  encrypted Message containing encrypted envelope & HMAC
     * @param Kab shared secret
     * @return Envelope
     **/
    public Envelope decryptEnvelopeMessage(Message msg, byte[] Kab, int seq) {
        byte[] orgBytes = decryptString(msg, Kab, seq, true); // get decrypted envelope bytes
        if (orgBytes != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(orgBytes);
            try {
                ObjectInput in = new ObjectInputStream(bis);
                return (Envelope) in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        return null;
    }

    /**
     * Given an envelope, serializes, encrypts, generates HMAC,
     * and returns a Message with the encrypted envelope and
     * a HMAC of the envelope
     * @param env Envelope to be encrypted
     * @param Kab shared secret used to derive ki and ke
     * @return Message (containing enc and hmac)
     **/
    public Message encryptEnvelope(Envelope env, byte[] Kab, int seqNum) {
        byte[] serializedEnv = serializeObject(env);
        if (serializedEnv != null) {
            return encryptByteArr(serializedEnv, Kab, seqNum, true);
        } else {
            System.out.println("Error serializing");
        }
        return null;
    }

//    public UserToken decryptTokenMessage(Message msg, byte[] Kab, RSAPublicKey gsPubKey) {
//        byte[] orgBytes = decryptString(msg, Kab); // get decrypted token package bytes & verify HMAC
//        if (orgBytes != null) {
//            ByteArrayInputStream bis = new ByteArrayInputStream(orgBytes);
//            try {
//                ObjectInput in = new ObjectInputStream(bis);
//                SignedToken signedToken = (SignedToken) in.readObject();
//                Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
//                verifySig.initVerify(gsPubKey);
////                System.out.println("token crypto sec decryption: ");
////                System.out.println(byteArrToHexStr(signedToken.getTokenBytes()));
//                verifySig.update(signedToken.getTokenBytes());
//                if(!verifySig.verify(signedToken.getTokenSignature())) {
//                    System.out.println("Token could not be verified as signature did not match.");
//                    return null;
//                }
//                bis = new ByteArrayInputStream(signedToken.getTokenBytes());
//                in = new ObjectInputStream(bis);
//                return (UserToken) in.readObject();
//            } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | SignatureException |
//                     NoSuchProviderException | InvalidKeyException e) {
//                e.printStackTrace();
//            }
//        }
//        return null;
//    }


    public Message encryptToken(UserToken token, byte[] Kab, int seq) {
        try {
            RSAPrivateKey privateKey = readRSAPrivateKey("gs");
            if (privateKey != null) {
                byte[] tokenBytes = serializeObject(token);
                byte[] tokenSigned = rsaSign(privateKey, tokenBytes);
                if (tokenSigned != null) {
                    SignedToken tokenPackage = new SignedToken(tokenBytes, tokenSigned);
                    byte[] tokenPackageBytes = serializeObject(tokenPackage);
                    if (tokenPackageBytes != null) {
                        return encryptByteArr(tokenPackageBytes, Kab, seq, false);
                    } else {
                        System.out.println("Could not serialize token while encrypting it.");
                    }
                } else {
                    System.out.println("Could not sign token in encrypt token.");
                }
            } else {
                System.out.println("Private key for the group server could not be found while encrypting token");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * Returns a 16 byte IV given key by deriving a new key using SHA-256 hash
     * with a constant.
     * @param Kab shared secret
     * @return byte[] iv
    **/
    private byte[] genIV(byte[] Kab) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String toHash = new String(Kab);
            toHash += "IV Generator";
            byte[] hash = digest.digest(toHash.getBytes(StandardCharsets.UTF_8));
            int ivLength = 16;
            byte[] iv = new byte[ivLength];
            System.arraycopy(hash, 0, iv, 0, ivLength);
            return iv;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Returns ki, a 256-bit key, derived from Kab (shared secret)
     * to be used as an integrity key
     * @param Kab shared secret used to derive ki
     * @return SecretKey ki
     * **/
    private SecretKey getKi(byte[] Kab) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteIConst = "AES Integrity".getBytes();
            byte[] toHash = new byte[Kab.length + byteIConst.length];
            System.arraycopy(Kab, 0, toHash, 0, Kab.length);
            System.arraycopy(byteIConst, 0, toHash, Kab.length, byteIConst.length);
            byte[] hash = digest.digest(toHash);

            return new SecretKeySpec(hash, 0, hash.length, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * Returns ke, a 256 bit encryption key, derived from Kab (shared secret)
     * @param Kab shared secret used to derive ke
     * @return SecretKey ke
     * **/
    private SecretKey getKe(byte[] Kab) {
        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteIConst = "AES Encryption".getBytes();
            byte[] toHash = new byte[Kab.length + byteIConst.length];
            System.arraycopy(Kab, 0, toHash, 0, Kab.length);
            System.arraycopy(byteIConst, 0, toHash, Kab.length, byteIConst.length);
            byte[] hash = digest.digest(toHash);
            return new SecretKeySpec(hash, 0, hash.length, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Given a byte[] message and a shared secret Kab, encrypts
     * the message and generates a HMAC for it, returning both
     * as a Message
     * @param msg The message in byte[] form to be encrypted
     * @return k shared secret Kab used to derive keys to encrypt
     *         and generate the HMAC
     * **/
    public Message encryptByteArr(byte[] msg,  byte[] k, int seq, boolean seqHMAC){
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKey ki = getKi(k);
            SecretKey ke = getKe(k);
            sha256_HMAC.init(ki);
            byte[] hmac;
            if (seqHMAC) {
                byte[] seqByteArr = ByteBuffer.allocate(4).putInt(seq).array();
                // Concatenate byte arrays then encrypt as one
                byte[] seqEnv = new byte[msg.length + seqByteArr.length];
                System.arraycopy(msg, 0, seqEnv, 0, msg.length);
                System.arraycopy(seqByteArr, 0, seqEnv, msg.length, seqByteArr.length);
                hmac =  sha256_HMAC.doFinal(seqEnv);
            } else {
                hmac = sha256_HMAC.doFinal(msg);
            }

            Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] ivBytes = genIV(k);
            if (ivBytes != null) {
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                c.init(Cipher.ENCRYPT_MODE, ke, iv);
                byte[] enc = c.doFinal(msg);
                return new Message(hmac, enc);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
    public byte[] genKabHMAC(byte[] Kab, String name) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            sha256_HMAC.init(getKi(Kab));
            byte[] nameBytes = name.getBytes();
            byte[] toHash = new byte[Kab.length + nameBytes.length];
            System.arraycopy(Kab, 0, toHash, 0, Kab.length);
            System.arraycopy(nameBytes, 0, toHash, Kab.length, nameBytes.length);
            return sha256_HMAC.doFinal(toHash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] decryptString(Message m, byte[] k, int seq, boolean seqHMAC){
        try {
            SecretKey ki = getKi(k);
            SecretKey ke = getKe(k);

            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            sha256_HMAC.init(ki);
            Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] ivBytes = genIV(k); // generate an iv based on Kab
            if (ivBytes != null) {
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                c.init(Cipher.DECRYPT_MODE,ke, iv);
                byte[] s = c.doFinal(m.enc);

                byte[] hmac;
                if (seqHMAC) {
                    byte[] seqByteArr = ByteBuffer.allocate(4).putInt(seq).array();
                    // Concatenate byte arrays then encrypt as one
                    byte[] seqEnv = new byte[s.length + seqByteArr.length];
                    System.arraycopy(s, 0, seqEnv, 0, s.length);
                    System.arraycopy(seqByteArr, 0, seqEnv, s.length, seqByteArr.length);
                    hmac =  sha256_HMAC.doFinal(seqEnv);
                } else {
                    hmac = sha256_HMAC.doFinal(s);
                }
                if (Arrays.equals(hmac, m.hmac)){
                    return s;
                } else {
                    System.out.println("INTEGRITY VIOLATION: Error with HMAC");
                    return null;
                }
            }

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public String serializeToken(UserToken t){
        StringBuilder s  = new StringBuilder(t.getIssuer() + "|" + t.getSubject());
        for(String m: t.getGroups()){
            s.append("|").append(m);
        }
        return s.toString();
    }

//    public Token deserializeToken(String s){
//        String[] arr = s.split("|");
//        String issuer = arr[0];
//        String subject = arr[1];
//        String recipientPubKey = arr[2];
////        List<String> groups = new List<String>();
//        List<String> groups = new ArrayList<>();
//        for (int i=2;i<arr.length;i++){
//            groups.add(arr[i]);
//        }
//        return new Token(issuer,subject,groups, recipientPubKey);
//    }

    public String serializeList(List<String> arr){
        String s = "";
        for(String i : arr){
            s+= i+"|";
        }
        return s.substring(0,s.length()-1);
    }

    public List<String> deserializeString(String s){
        return  Arrays.asList(s.split("|"));
    }

    public SignedToken decryptMessageToSignedToken(Message msg, byte[] Kab, int seq) {
        byte[] orgBytes = decryptString(msg, Kab, seq, false); // get decrypted token package bytes & verify HMAC
        if (orgBytes != null) {
            ByteArrayInputStream bis = new ByteArrayInputStream(orgBytes);
            try {
                ObjectInput in = new ObjectInputStream(bis);
                return (SignedToken) in.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
    
    public UserToken decryptSignedToken(SignedToken signedToken, RSAPublicKey gsPubKey) {
        try{
            Signature verifySig = Signature.getInstance("SHA256withRSA", "BC");
            verifySig.initVerify(gsPubKey);
            verifySig.update(signedToken.getTokenBytes());
            if(!verifySig.verify(signedToken.getTokenSignature())) {
                System.out.println("Token could not be verified as signature did not match.");
                return null;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(signedToken.getTokenBytes());
            ObjectInputStream in = new ObjectInputStream(bis);
            return (UserToken) in.readObject();
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | SignatureException |
                NoSuchProviderException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public ArrayList<SecretKey> readGroupKey(String groupname) {
        try {
            PemReader pemReader = new PemReader(new FileReader(groupname + "_keyring" + ".txt"));
            ArrayList<SecretKey> keyring = new ArrayList<SecretKey>();
            while(pemReader.ready()){
                byte[] keyBytes = pemReader.readPemObject().getContent();
                SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
                keyring.add(secretKeySpec);
            }
            return keyring;
        } catch (FileNotFoundException e) {
            System.out.println("Could not find " + groupname + "_keyring" + ".txt");
        } catch (IOException e) {
            System.out.println("Error reading in public key");
        }
        return null;
    }

    public boolean writeGroupKey(String groupname, ArrayList<SecretKey> keyring) {
        try {
            String fileName = groupname+"_keyring" + ".txt";
            PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(fileName)));
            for(int i = 0; i < keyring.size(); i++){
                pemWriter.writeObject(new PemObject(groupname+" "+i, keyring.get(i).getEncoded()));
            }
            pemWriter.close();

            return true;
        } catch (IOException e) {
            System.out.println("Error writing key to file.");
        }
        return false;
    }

    public SecretKey generateGroupKey(){
        try{
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        }
        
    }

    public byte[] decryptByteArr(byte[] msg,  byte[] k){
        try {
            SecretKey ke = getKe(k);

            Cipher c = Cipher.getInstance("AES/CBC/PKCS7Padding");
            byte[] ivBytes = genIV(k);
            if (ivBytes != null) {
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                c.init(Cipher.DECRYPT_MODE, ke, iv);
                return c.doFinal(msg);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
