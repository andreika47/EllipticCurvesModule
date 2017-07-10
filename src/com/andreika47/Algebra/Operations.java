package com.andreika47.Algebra;

import com.andreika47.EllipticCurves.EllipticCurve;
import com.andreika47.MyUtils.CipherText;
import com.andreika47.MyUtils.CipherWord;
import com.andreika47.MyUtils.PolynomDeg2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Андрей on 14.04.2017.
 */
public class Operations
{
    public static final BigInteger TWO = new BigInteger("2");
    public static final BigInteger FOUR = new BigInteger("4");
    public static final BigInteger EIGHT = new BigInteger("8");
    public static final BigInteger P = new BigInteger("6277101735386680763835789423207666416083908700390324961279"); // field order
    private static final int MESSAGE_LEN = 20;
    private static final int K = 50;   // probability that for we can't transform message to elliptic curve dot = (1 / 2^K)
    private static final BigInteger PROBABILITY = BigInteger.valueOf(K);  // K as BigInteger
    private static final BigInteger Pd2 = new BigInteger("3138550867693340381917894711603833208041954350195162480639"); // P / 2

    public static BigInteger getSecretKey()
    {
        String secretS = "";
        SecureRandom rand = new SecureRandom();

        for(int i = 0; i < Operations.MESSAGE_LEN; ++i)
            secretS += (char)(rand.nextInt(10) + '0');
        return new BigInteger(secretS);
    }

    public static CipherText encrypt(EllipticCurve curve, byte[] message, Point openKey) throws IOException
    {
        ArrayList<CipherWord> cipherWords = new ArrayList<>();
        int left = 0;
        int right = Math.min(MESSAGE_LEN , message.length);

        while(left < message.length)   // split message, because we can exceed P, so therefore more possible collisions
        {
            cipherWords.add(getCipherPoint(curve, Arrays.copyOfRange(message, left, right), openKey));
            left += MESSAGE_LEN;
            right = Math.min(left + MESSAGE_LEN, message.length);
        }
        return new CipherText(cipherWords);
    }

    public static byte[] decrypt(EllipticCurve curve, byte[] cipherText, BigInteger secretKey, ArrayList<Point> helpers)
            throws IOException
    {
        int left = 0;
        int len = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for(Point helper : helpers)
        {
            helper = algMult(curve, secretKey, helper);  // secretKey * kQ
            len = cipherText[left];
            byte[] cipherPointB = Arrays.copyOfRange(cipherText, left + 1, left + len + 1);
            Point cipherPoint = cipherNumToPoint(curve, new BigInteger(cipherPointB));   // secretKey * kQ + M
            cipherPoint = inverse(cipherPoint);
            Point text = sum(curve, cipherPoint, inverse(helper));

            out.write(pointToBytes(text));
            left += len + 1;
        }
        return out.toByteArray();
    }

    public static Point algMult(EllipticCurve curve, BigInteger alpha, Point point) // returns alpha * point
    {
        Point res = curve.INF;
        Point tempP = new Point(point.getX(), point.getY());
        boolean wasInit = false;

        while(!alpha.equals(BigInteger.ZERO))
        {
            if(alpha.mod(TWO).equals(BigInteger.ONE))
            {
                if(wasInit)
                    res = sum(curve, res, tempP);
                else
                {
                    res = new Point(tempP.getX(), tempP.getY());
                    wasInit = true;
                }
            }
            alpha = alpha.shiftRight(1);
            tempP = doublePoint(curve, tempP);
        }
        return res;
    }

    private static CipherWord getCipherPoint(EllipticCurve curve, byte[] messageB, Point openKey)
    {
        BigInteger message = new BigInteger(messageB);
        Point cipherText = numToPoint(curve, message);  // M
        Point helper = curve.getBasePoint();
        String sK = "";
        SecureRandom rand = new SecureRandom();

        for(int i = 0; i < MESSAGE_LEN; ++i)
            sK += (char)(rand.nextInt(10) + '0');

        BigInteger k = new BigInteger(sK);
        helper = algMult(curve, k, helper);  // k * Q
        openKey = algMult(curve, k, openKey); // k * secretKey * Q

        cipherText = sum(curve, cipherText, openKey);  // M + k * secretKey * Q
        return new CipherWord(cipherText, helper);
    }

    private static Point inverse(Point point)  // returns -point mod P
    {
        return new Point(point.getX(), P.subtract(point.getY()));
    }

    private static Point numToPoint(EllipticCurve curve, BigInteger message)  // transforms number to curve point
    {
        BigInteger x = message.multiply(PROBABILITY);
        BigInteger y = BigInteger.ZERO;
        BigInteger y2;

        for(int i = 0; i < K; ++i)
        {
            y2 = curve.getY2(addIntToBig(x, i));
            if(hasRoot(y2))
            {
                y = root(y2);
                if(y.equals(BigInteger.ZERO))
                    continue;
                x = addIntToBig(x, i);
                break;
            }
        }
        return new Point(x, y);
    }

    private static Point cipherNumToPoint(EllipticCurve curve, BigInteger cipherText)  // cipher point has sign, so special method
    {
        boolean isNeg = false;
        if(cipherText.signum() == -1)
        {
            isNeg = true;
            cipherText = cipherText.negate();
        }
        BigInteger y2 = curve.getY2(cipherText);
        while(!hasRoot(y2))
        {
            cipherText = addIntToBig(cipherText, 1);
            y2 = curve.getY2(cipherText);
        }
        y2 = root(y2);
        if(isNeg && y2.compareTo(Pd2) != -1 || !isNeg && y2.compareTo(Pd2) == -1)
            y2 = P.subtract(y2);
        return new Point(cipherText, y2);
    }

    private static byte[] pointToBytes(Point point) throws IOException  // transforms curve point to byte array
    {
        BigInteger x = point.getX().divide(new BigInteger(Integer.toString(K)));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(x.toByteArray());
        return out.toByteArray();
    }

    public static byte[] cipherPointToBytes(Point point) throws IOException  // transforms cipher curve point to byte array
    {
        BigInteger x = point.getX();

        // transforming number to curve point we decide x = a^2,
        // so we have two decisions: -sqrt(a) and sqrt(a),
        // where one of them is bigger than P / 2, other is smaller
        // so we make out them by adding sign
        if(point.getY().compareTo(Pd2) == -1)
            x = x.negate();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(x.toByteArray());
        return out.toByteArray();
    }

    private static boolean hasRoot(BigInteger x2)
    {
        return JacobiSymbol(x2, P);
    }

    private static boolean JacobiSymbol(BigInteger x2, BigInteger mod)
    {
        int binDeg = 0;
        if(x2.equals(BigInteger.ONE))
            return true;
        while(x2.mod(TWO).equals(BigInteger.ZERO))
        {
            ++binDeg;
            x2 = x2.shiftRight(1);
        }
        if(binDeg == 0)
        {
            if(x2.mod(FOUR).equals(BigInteger.ONE) || mod.mod(FOUR).equals(BigInteger.ONE))
                return JacobiSymbol(mod.mod(x2), x2);
            else
                return !JacobiSymbol(mod.mod(x2), x2);
        }
        else if(binDeg % 2 == 0)
        {
            return JacobiSymbol(x2, mod);
        }
        else
        {
            BigInteger m8 = mod.mod(EIGHT);
            if(m8.equals(BigInteger.ONE) || m8.equals(EIGHT.subtract(BigInteger.ONE)))
                return JacobiSymbol(x2, mod);
            else
                return !JacobiSymbol(x2, mod);
        }
    }

    private static BigInteger root(BigInteger x2) // Cipolla's Algorithm
    {
        BigInteger t = BigInteger.ONE;
        BigInteger D = t.multiply(t).subtract(FOUR.multiply(x2)).mod(P);  // Discriminant = t^2 - 4x mod P
        while(JacobiSymbol(D, P))
        {
            t = t.add(BigInteger.ONE);
            D = t.multiply(t).subtract(FOUR.multiply(x2)).mod(P);
        }
        BigInteger deg = P.add(BigInteger.ONE).shiftRight(1);

        // by elevating polynomial mod polynomial with degree = 2 we get polynomials with degree < 2
        // az + b
        // split deg into numbers 2^q
        HashMap<Integer, PolynomDeg2> coeffs = new HashMap<>();
        int curDeg = 0;
        BigInteger a = BigInteger.ONE;
        BigInteger b = BigInteger.ZERO;
        PolynomDeg2 curBin = new PolynomDeg2(a, b);
        PolynomDeg2 ans = new PolynomDeg2(BigInteger.ZERO, BigInteger.ONE);
        while(pow2IntCompBig(curDeg, deg) < 0)
        {
            coeffs.put(curDeg, curBin);
            ++curDeg;
            curBin = multPolynomsDeg2(curBin.getA(), curBin.getB(), curBin.getA(), curBin.getB(), t, x2);
        }
        while(!deg.equals(BigInteger.ZERO))
        {
            while(pow2IntCompBig(curDeg, deg) > 0)
                --curDeg;
            ans = multPolynomsDeg2(ans.getA(), ans.getB(), coeffs.get(curDeg).getA(), coeffs.get(curDeg).getB(), t, x2);
            deg = deg.subtract(TWO.modPow(new BigInteger(Integer.toString(curDeg)), P));
        }
        // check that's all going right
        if(ans.getA().equals(BigInteger.ZERO))
            return ans.getB().mod(P);
        else
            return BigInteger.ZERO;
    }

    // (az + b) * (cz + d) mod z^2 +tz + x
    private static PolynomDeg2 multPolynomsDeg2(BigInteger a, BigInteger b, BigInteger c,
                                                 BigInteger d, BigInteger t, BigInteger x)
    {
        // (az + b) * (cz + d) mod z^2 +tz + x = iz^2 + jz + k
        BigInteger i = a.multiply(c).mod(P);  // a * c mod P
        BigInteger j = a.multiply(d).add(c.multiply(b)).mod(P);  // a * d + c * b mod P
        BigInteger k = b.multiply(d).mod(P); // b * d mod P

        a = j.subtract(i.multiply(t)).mod(P);  // j - i * t mod P
        b = k .subtract(i.multiply(x)).mod(P); // k - i * x mod P
        return new PolynomDeg2(a, b);
    }

    private static int pow2IntCompBig(int l, BigInteger r)  // 2^l < r
    {
        BigInteger lBig = TWO;
        lBig = lBig.modPow(new BigInteger(Integer.toString(l)), P);
        return lBig.compareTo(r);
    }

    private static BigInteger addIntToBig(BigInteger x, int k)
    {
        String kS = Integer.toString(k);
        return x.add(new BigInteger(kS));
    }

    private static Point sum(EllipticCurve curve, Point p, Point q)
    {
        return curve.sum(p, q);
    }

    private static Point doublePoint(EllipticCurve curve, Point point)
    {
        return curve.doublePoint(point);
    }
}
