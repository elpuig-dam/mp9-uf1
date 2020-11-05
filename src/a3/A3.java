package a3;

import java.io.File;
import java.io.FileOutputStream;

public class A3 {
    public static void main(String[] args) throws Exception {

        //Consultem les propietats del sistema
        String userhome = System.getProperty("user.home");
        String javahome = System.getProperty("java.home");
        String osname = System.getProperty("os.name");

        String msg = new String("Directori home: " + userhome + "\n");
        msg += "Directori java = " + javahome + "\n";
        msg += "S.O = " + osname + "\n";
        System.out.println(msg);


        //Guardem les propietats del sistema en un fitxer
        File fs = new File(userhome + "/MP9/UF1/A3/props.txt");
        try {
            FileOutputStream out = new FileOutputStream(fs);
            out.write(msg.getBytes("UTF-8"));
            out.close();
            System.out.println("Informació desada a: " + fs.getAbsolutePath());
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }


    }
}
