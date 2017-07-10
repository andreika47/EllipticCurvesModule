package com.andreika47.MyUtils;

import java.math.BigInteger;

/**
 * Created by Андрей on 07.07.2017.
 */
public class PolynomDeg2  // ax + b
{
    private BigInteger a;
    private BigInteger b;

    public PolynomDeg2(BigInteger a, BigInteger b)
    {
        this.a = a;
        this.b = b;
    }

    public BigInteger getA()
    {
        return a;
    }

    public BigInteger getB()
    {
        return b;
    }

    @Override
    public int hashCode()
    {
        return a.hashCode() * a.hashCode() % b.hashCode();
    }
}
