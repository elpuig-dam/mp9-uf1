package a4_a5;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;

public class A4 {


    public static void main(String[] args) {

        String msg = "Distància, mans, mscareta";
        String pwd = "covid19";
        String pwd2 = "GripComuna";
        SecretKey sk,sk2;
        //generem la clau a partir del password pwd
        sk = Xifrar.passwordKeyGeneration(pwd,128);
        sk2 = Xifrar.passwordKeyGeneration(pwd2,128);
        //Xifrem
        byte[] msgXifrat = Xifrar.encryptData(sk,msg.getBytes());

        //Desxifrem
        byte[] msgDesxifrat = new byte[0];
        try {
            msgDesxifrat = Xifrar.decryptData(sk2,msgXifrat);
            System.out.println("Password correcte");
        } catch (BadPaddingException e) {
            System.out.println("password incorrecte");;
        }
        System.out.println(new String(msgDesxifrat));


    }
}
