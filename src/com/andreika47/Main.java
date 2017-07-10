package com.andreika47;

import com.andreika47.Algebra.Operations;
import com.andreika47.Algebra.Point;
import com.andreika47.EllipticCurves.EllipticCurve;
import com.andreika47.MyUtils.CipherText;

import java.io.*;
import java.math.BigInteger;

public class Main
{

    public static void main(String[] args)
    {
        String testS = "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiop";
        byte[] test = testS.getBytes();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EllipticCurve curve = new EllipticCurve("id");
        BigInteger secretKey = Operations.getSecretKey();
        Point openKey = Operations.algMult(curve, secretKey, curve.getBasePoint());
        try
        {
            out.write(test);
            System.out.println(out.toString());
            out.reset();
            CipherText cipherText = Operations.encrypt(curve, test, openKey);
            out.write(cipherText.getText());
            System.out.println(out.toString());
            out.reset();
            byte[] text = Operations.decrypt(curve, cipherText.getText(), secretKey, cipherText.getHelpers());
            out.write(text);
            System.out.println(out.toString());
            out.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
