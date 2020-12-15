package a4_a5;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

public class A5 {

    public static void main(String[] args) {
        String msg = "hello world!!!";
        byte[] encriptedData = null;
        byte[] dencriptedData = null;

        //exerici 1.1
        System.out.println("Exercici 1.1");
        KeyPair parelldeclaus = Xifrar.randomGenerate(1024);
        encriptedData = Xifrar.encryptData(msg.getBytes(),parelldeclaus.getPublic());
        System.out.println(new String(encriptedData));

        dencriptedData = Xifrar.decryptData(encriptedData,parelldeclaus.getPrivate());
        System.out.println(new String(dencriptedData));

        System.out.println("pública:\n" + parelldeclaus.getPublic());
        System.out.println("privada:\n" + parelldeclaus.getPrivate());

        //Exercici 1.2 Keystore

        //Carreguem el keystore
        System.out.println("Exercici 1.2");
        String pathKeystore = "/home/jordi/MP9/UF1/A2/";
        KeyStore ks = null;
        try {
            ks = Xifrar.loadKeyStore(pathKeystore + "/keystore_jherna76.ks","kankusho","PKCS12");
            System.out.println("Keystore tipus " + ks.getType() + " carregat");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Generem una SecretKey i una SecretKeyEntrey que necessita el Keystore
        SecretKey secretKey = Xifrar.keygenKeyGeneration(128);
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        System.out.println("SecretKay creada...");
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("kankusho".toCharArray());
        try {
            ks.setEntry("a5key2",skEntry,protParam);
            System.out.println("SecretKey desada all keystore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        // desem el keystore amb un altre nom per no sobreescriure l'original
        try (FileOutputStream fos = new FileOutputStream(pathKeystore + "/ks_jherna.ks")) {
            ks.store(fos, "kankusho".toCharArray());
            System.out.println("Keystore desat a " + pathKeystore);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Exercici 1.2.i
        SecretKey sk = null;
        try {
            sk = (SecretKey) ks.getKey("a5key2","kankusho".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        //Comprovem quin és l'algoritme
        System.out.println("Algoritmde la SecretKey " + sk.getEncoded() + " : " + sk.getAlgorithm());


        //Exercici 1.3
        System.out.println("1.3 carregar certificat");
        PublicKey publicKey13 = Xifrar.getPublicKey(pathKeystore + "/elmeucertificat.cer");
        System.out.println(publicKey13.getAlgorithm());

        //Exercici 1.4
        System.out.println("1.4 carregar certificat de publickey del keystore");
        PublicKey publicKey14 = Xifrar.getPublicKey(ks,"mykey","kankusho");
        System.out.println(publicKey14.toString());

        //Exercici 1.5
        System.out.println("Exercici 1.5");
        Path path = Paths.get(pathKeystore + "/read.txt");
        byte[] f = null;
        try {
            f = Files.readAllBytes(path);
        } catch (IOException e) {
            e.printStackTrace();
        }

        //Agafem la PrivateKey
        PrivateKey pk = null;
        try {
            pk = (PrivateKey) ks.getKey("mykey","kankusho".toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        //Signem el fitxer llegit en bytes
        byte[] signatura = Xifrar.signData(f, pk);
        System.out.println("Signatura: " + new String(signatura, StandardCharsets.UTF_8));

        //Exercici 1.6 Verifiquem
        System.out.println("Exercici 1.6");
        boolean ok = false;
        ok = Xifrar.validateSignature(f,signatura,publicKey14);
        System.out.println("Les dades són: " + new String(ok?"Correctes":"Incorrectes"));

        // Exercici 2
        byte[][] testwrap = Xifrar.encryptWrappedData(msg.getBytes(),parelldeclaus.getPublic());
        System.out.println("key wrapped: " + new String(testwrap[1]));
        System.out.println("data encripted: " + new String(testwrap[0]));

        byte[] testunwrap = Xifrar.decryptWrappedData(testwrap,parelldeclaus.getPrivate());
        System.out.println("text desxifrat: " + new String(testunwrap));




    }
}
