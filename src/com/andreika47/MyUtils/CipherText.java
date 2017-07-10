package com.andreika47.MyUtils;

import com.andreika47.Algebra.Operations;
import com.andreika47.Algebra.Point;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Created by Андрей on 04.07.2017.
 */
public class CipherText
{
    private byte[] text;
    private ArrayList<Point> helpers;

    public CipherText(ArrayList<CipherWord> cipherWords) throws IOException
    {
        helpers = new ArrayList<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for(CipherWord cWord : cipherWords)
        {
            byte[] cipherPointB = Operations.cipherPointToBytes(cWord.getWord());
            out.write(cipherPointB.length);
            out.write(cipherPointB);
            helpers.add(cWord.getHelper());
        }
        text = out.toByteArray();
    }

    public byte[] getText()
    {
        return text;
    }

    public ArrayList<Point> getHelpers()
    {
        return helpers;
    }
}
