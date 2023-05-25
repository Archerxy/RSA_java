package rsa;

/**
 * 
 * Copyright (c) 2023 Archerxy
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * @author archer
 *
 */

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/***
 * n = p1 * p2 ; (p1,p2 are prime numbers)
 * 
 * φ(n) = (p1 - 1) * (p2 - 1) ;  Euler's formula
 * 
 * e * d - k * φ(n) = 1 ;  e = random(1~φ(n)), d is calculated
 * 
 * message * e = cipher (mod n) ; 
 * 
 * cipher * d = message (mod n) ;
 * 
 * */

public class RSA {
	private static final int BITS = 512;
	/***
	 * generate (e, d, n)  pk = (n, e), sk = (n, d)  
	 * @return BigInteger[3] [e, d, n]
	 * */
	public static BigInteger[] genEDN() {
		SecureRandom sr = new SecureRandom();
		BigInteger p1 = BigInteger.probablePrime(BITS << 1, sr);
		BigInteger p2 = BigInteger.probablePrime(BITS << 1, sr);
		BigInteger n = p1.multiply(p2);
		BigInteger fiN = p1.subtract(BigInteger.ONE).multiply(p2.subtract(BigInteger.ONE));
		BigInteger e = BigInteger.probablePrime(fiN.bitCount() - 1, sr);
		while(e.compareTo(fiN) >= 0) {
			e = BigInteger.probablePrime(fiN.bitCount() - 1, sr);
		}
		
		/**
		 * Euclid's algorithm to calculate d
		 * */
		List<BigInteger[]> rs = new LinkedList<>();
		BigInteger r1 = e, r2 = fiN;
		boolean b = false;
		while(!r1.equals(BigInteger.ONE) && !r2.equals(BigInteger.ONE)) {
			rs.add(new BigInteger[] {r1, r2});
			if(b) {
				r1 = r1.mod(r2);
				b = false;
			} else {
				r2 = r2.mod(r1);
				b = true;
			}
		}
		rs.add(new BigInteger[] {r1, r2});
		Collections.reverse(rs);
		BigInteger d = BigInteger.valueOf(1), k = BigInteger.valueOf(0);
		b = r1.equals(BigInteger.ONE);
		for(BigInteger[] r : rs) {
			if(b) {
				d = k.multiply(r[1]).add(BigInteger.ONE).divide(r[0]);
				b = false;
			} else {
				k = d.multiply(r[0]).subtract(BigInteger.ONE).divide(r[1]);
				b = true;
			}
		}
		
		return new BigInteger[] {e, d, n};
	}
	
	/**
	 * rsa encryption, 
	 * @param e
	 * @param n
	 * @param message
	 * 
	 * **/
	public static BigInteger encrypt(BigInteger e, BigInteger n, BigInteger message) {
		return message.modPow(e, n);
	}

	/**
	 * rsa decryption, 
	 * @param d
	 * @param n
	 * @param cipher
	 * 
	 * **/
	public static BigInteger decrypt(BigInteger d, BigInteger n, BigInteger cipher) {
		return cipher.modPow(d, n);
	}
	
	/**
	 * test
	 * */
	public static void main(String[] args) {
		String msg = "hello";
		BigInteger[] edn = genEDN();
		BigInteger e = edn[0], d = edn[1], n = edn[2];
                //encrypt
		BigInteger cipher = encrypt(e, n, new BigInteger(1, msg.getBytes()));
		System.out.println(cipher.toString(16));
                //decrypt
		BigInteger message = decrypt(d, n, cipher);
		System.out.println(new String(message.toByteArray()));
	}
}

