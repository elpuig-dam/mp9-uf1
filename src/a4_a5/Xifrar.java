package a4_a5;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.security.cert.Certificate;

public class Xifrar {
    //codi 1.1.1 IOC: Generació d'una clau simètrica
    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    //codi 1.1.2 IOC: Generació de clau simpetrica a partir d'una contrasenya
    public static SecretKey passwordKeyGeneration(String text, int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize/8);
                sKey = new SecretKeySpec(key, "AES");
            } catch (Exception ex) {
                System.err.println("Error generant la clau:" + ex);
            }
        }
        return sKey;
    }

    //Xifrar amb clau simpetrica
    public static byte[] encryptData(SecretKey sKey, byte[] data) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    //Desxifrar amb clau simpètrica
    public static byte[] decryptData(SecretKey sKey, byte[] encrypteddata) throws BadPaddingException {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            decryptedData =  cipher.doFinal(encrypteddata);
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return decryptedData;
    }

    //Xifrar amb clau pública
    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    //Desxifrar amb clau privada
    public static byte[] decryptData(byte[] data, PrivateKey sec) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, sec);
            decryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptedData;
    }

    //Generar parell de claus
    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    //Llegir un keystore del sistema
    public static KeyStore loadKeyStore(String ksFile, String ksPwd, String ksType) throws Exception {
        KeyStore ks = KeyStore.getInstance(ksType);
        File f = new File(ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    //Xifrar amb clau embolcallada
    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            //Generem clau amb AES
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();

            //Xifrem dades amb AES a partir de la clau anterior
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);

            //Embolcallem la clau amb RSA
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    //desxifrar amb clau embolcallada
    public static byte[] decryptWrappedData(byte[][] data, PrivateKey sec) {
        byte[] msgDes = null;
        try {
            //desenbolcallem la clau UNWRAP
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.UNWRAP_MODE, sec);
            SecretKey clauDes = (SecretKey) cipher.unwrap(data[1],"AES",Cipher.SECRET_KEY);


            //Desxifrem les dades
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, clauDes);
            msgDes = cipher.doFinal(data[0]);

        } catch (Exception ex) {
            System.err.println("Ha succeït un error desxifrant: " + ex);
        }
        return msgDes;
    }

    /***
     *
     * @param ks //keystore
     * @param alias //alies de la clau del keystore
     * @param pwMyKey //password de clau pública desada al keystore
     * @return PublicKey
     */
    public static PublicKey getPublicKey(KeyStore ks, String alias, String pwMyKey) {
        PublicKey pub = null;
        Key key = null;
        try {
            key = ks.getKey(alias, pwMyKey.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        if(key instanceof PrivateKey) {
            try {
                Certificate cert = ks.getCertificate(alias);
                pub = cert.getPublicKey();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        return pub;

    }

    /***
     *
     * @param filename //Certificat de clau pública per exemple .cer
     * @return PublicKey
     */
    public static PublicKey getPublicKey(String filename) {
        Certificate cert = null;
        FileInputStream fis;
        PublicKey pub=null;
        try {
            fis = new FileInputStream(filename);
            BufferedInputStream bis = new BufferedInputStream(fis);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            while (bis.available() > 0) {
                cert = cf.generateCertificate(bis);
                //System.out.println(cert.toString());
            }
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }

        pub = cert.getPublicKey();

        return pub;

    }

    //Signa unes dades amb la private key
    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;
        try {
            Signature signer = Signature.getInstance("SHA256withDSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    //valida les dades d'una signatura
    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA256withDSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

}
