package com.andreika47.MyUtils;

import com.andreika47.Algebra.Point;

/**
 * Created by Андрей on 04.07.2017.
 */
public class CipherWord
{
    private Point word;
    private Point helper;

    public CipherWord(Point word, Point helper)
    {
        this.word = word;
        this.helper = helper;
    }

    public Point getWord()
    {
        return word;
    }

    public Point getHelper()
    {
        return helper;
    }
}
