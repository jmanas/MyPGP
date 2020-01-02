package crypto;

import gui.ThreadUtilities;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.BitSet;

/**
 * GnuPG implementation of parameters for Elgamal encryption.
 *
 * @author Jose A. Manas
 * @version 17.8.2014
 */
public class GpgElgamal {
    private static final int[][] WIENER_TABLE;
    private static final SecureRandom random = new SecureRandom();

    static {
        WIENER_TABLE = new int[][]{    /*   p	  q	 attack cost */
                {512, 119},    /* 9 x 10^17 */
                {768, 145},    /* 6 x 10^21 */
                {1024, 165},    /* 7 x 10^24 */
                {1280, 183},    /* 3 x 10^27 */
                {1536, 198},    /* 7 x 10^29 */
                {1792, 212},    /* 9 x 10^31 */
                {2048, 225},    /* 8 x 10^33 */
                {2304, 237},    /* 5 x 10^35 */
                {2560, 249},    /* 3 x 10^37 */
                {2816, 259},    /* 1 x 10^39 */
                {3072, 269},    /* 3 x 10^40 */
                {3328, 279},    /* 8 x 10^41 */
                {3584, 288},    /* 2 x 10^43 */
                {3840, 296},    /* 4 x 10^44 */
                {4096, 305},    /* 7 x 10^45 */
                {4352, 313},    /* 1 x 10^47 */
                {4608, 320},    /* 2 x 10^48 */
                {4864, 328},    /* 2 x 10^49 */
                {5120, 335},    /* 3 x 10^50 */
        };
    }

    public static BigInteger[] generateParameters(int size)
            throws InterruptedException {
        BigInteger p = generateP(size);

        ThreadUtilities.ifInterruptedStop();

        BigInteger g = selectGenerator(p);
        return new BigInteger[]{p, g};
    }

    /**
     * crypto/generators/DHParametersHelper.java
     */
    private static BigInteger selectGenerator(BigInteger p)
            throws InterruptedException {
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger pMinusTwo = p.subtract(TWO);
        BigInteger g;

        /*
         * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
         */
        do {
            BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
            g = h.modPow(TWO, p);

            ThreadUtilities.ifInterruptedStop();
        } while (g.equals(BigInteger.ONE));

        return g;
    }

    // from GnuPG
    private static BigInteger generateP(int nbits)
            throws InterruptedException {
        int qbits = wiener_map(nbits);
        if (qbits % 2 != 0)
            qbits++;
        return generate_elg_prime(nbits, qbits);
    }

    private static BigInteger generate_elg_prime(int pbits, int qbits)
            throws InterruptedException {
        /* number of needed prime factors */
        int n = 1;
        while (pbits - qbits - 1 >= qbits * n)
            n++;
        n--;
        if (n == 0) {
            String msg = String.format("can't gen prime with pbits=%d qbits=%d", pbits, qbits);
            throw new IllegalArgumentException(msg);
        }

        /* length of prime factors */
        int fbits;
        fbits = (pbits - qbits - 1) / n;

        /* first prime factor (variable)*/
        qbits = pbits - n * fbits;
        BigInteger q = gen_prime(qbits);

        /* make a pool of 3n+5 primes (this is an arbitrary value) */
        int m = n * 3 + 5;
        if (m < 25)
            m = 25;
        /* pool of primes */
        BigInteger[] pool = new BigInteger[m];

        /* permutate over the pool of primes */
        BitSet perm = null;
        int count1 = 0;     // qbits increments
        int count2 = 0;     // qbits decrements
        while (true) {
            ThreadUtilities.ifInterruptedStop();
            if (perm != null) {
                if (!next_m_of_n(perm, m)) {
                    perm = null;
//                    progress('!');
                }
            }
            if (perm == null) {
                /* allocate new primes */
                Arrays.fill(pool, null);
                /* init m_out_of_n() */
                perm = new BitSet();
                perm.set(0, n);
            }
            for (int i = 0; i < m; i++) {
                if (perm.get(i) && pool[i] == null) {
                    pool[i] = gen_prime(fbits);
//                    progress('+');
                }
            }

            BigInteger prime = q.shiftLeft(1);
            for (int i = 0; i < m; i++) {
                if (perm.get(i))
                    prime = prime.multiply(pool[i]);
            }
            prime = prime.add(BigInteger.ONE);
            int primeBits = prime.bitLength();
            if (primeBits == pbits && prime.isProbablePrime(2))
                return prime;
//            progress('.');

            if (primeBits < pbits) {
                count1++;
                if (count1 > 20) {
                    count1 = 0;
                    qbits++;
//                    progress('>');
                    q = gen_prime(qbits);
                }
            } else {
                count1 = 0;
            }
            if (primeBits > pbits) {
                count2++;
                if (count2 > 20) {
                    count2 = 0;
                    qbits--;
//                    progress('<');
                    q = gen_prime(qbits);
                }
            } else {
                count2 = 0;
            }
        }
    }

    private static void progress(char c) {
        System.out.print(c);
    }

    private static BigInteger gen_prime(int nbits) {
        return new BigInteger(nbits, 20, random);
    }

    /**
     * *************
     * Michael Wiener's table about subgroup sizes to match field sizes
     * (floating around somewhere - Fixme: need a reference)
     */
    private static int wiener_map(int n) {
        for (int[] pq : WIENER_TABLE) {
            if (n <= pq[0])
                return pq[1];
        }
        /* not in table - use some arbitrary high number ;-) */
        return n / 8 + 200;
    }

    private static boolean next_m_of_n(BitSet bits, int n) {
        int balance = 0;
        while (true) {
            int pos = 0;
            boolean carry = true;
            while (carry) {
                if (pos >= n)
                    return false;
                if (bits.get(pos)) {
                    bits.clear(pos);
                    carry = true;
                    balance--;
                } else {
                    bits.set(pos);
                    carry = false;
                    balance++;
                }
                pos++;
            }
            if (balance == 0)
                return true;
        }
    }

    public static void main(String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        //        testPerms(2, 5);
//        System.exit(1);

        BigInteger p = generateP(1024);
        System.out.println(p);
        testP(p);
    }

    private static void testPerms(int m, int n) {
        BitSet bits = new BitSet();
        bits.set(0, m);
        do {
//            System.out.println(bits);
            StringBuilder builder = new StringBuilder();
            for (int p = n; p > 0; p--)
                builder.append(bits.get(p - 1) ? '1' : '0');
            System.out.println(builder.toString());
        } while (next_m_of_n(bits, n));
    }

    private static void testP(BigInteger p) {
        System.out.println(p.bitLength());
        System.out.println("  p.isProbablePrime(80): " + p.isProbablePrime(80));
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        System.out.println("  q.isProbablePrime(80): " + q.isProbablePrime(80));
    }


}



