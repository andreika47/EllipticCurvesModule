package com.andreika47.Algebra;

import java.math.BigInteger;

/**
 * Created by Андрей on 14.04.2017.
 */
public class Point
{
    private BigInteger x;
    private BigInteger y;

    public Point(BigInteger x, BigInteger y)
    {
        this.x = x;
        this.y = y;
    }

    public BigInteger getX()
    {
        return x;
    }

    public BigInteger getY()
    {
        return y;
    }
}
