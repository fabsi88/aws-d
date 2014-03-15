/**
Implementation of the MD5 hash function:

Standards: $(LINK2 http://tools.ietf.org/html/rfc1321, RFC 1321)
Copyright: Copyright © 2011 Piotr Szturmaj
License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0)
Authors: Piotr Szturmaj
Source: $(PHOBOSSRC std/crypto/hash/_md5.d)
*/

module crypto.hash.md5;

import std.algorithm, std.bitmanip, std.c.string;
public import crypto.hash.base;

private:

immutable uint[64] k = [
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

immutable uint[64] g = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
];

immutable uint[64] r = [
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

public:

final class MD5 : MerkleDamgardImpl!(uint, 4, 16, 16, 16)
{
	version (unittest) static const string[] testVectors = [
		"", "d41d8cd98f00b204e9800998ecf8427e",
		"a", "0cc175b9c0f1b6a831c399e269772661",
		"abc", "900150983cd24fb0d6963f7d28e17f72",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"8215ef0796a20bcaaae116d3876c664a",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"d174ab98d277d9f5a5611c2c9f419d9f",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"57edf4a22be3c955ac49da2e2107b67a"
	];
	
	protected override void setIV() @safe nothrow
	{
		h[0] = 0x67452301;
		h[1] = 0xefcdab89;
		h[2] = 0x98badcfe;
		h[3] = 0x10325476;
	}
	
	protected final override void transform() @safe nothrow pure
	{
		version (BigEndian)
		{
			foreach (i; 0 .. 16)
				w[i] = swapEndian(w[i]);
		}
		
		uint a, b, c, d, e, f, t;
		
		a = h[0];
		b = h[1];
		c = h[2];
		d = h[3];
		
		foreach (i; 0 .. 16)
		{
			f = d ^ (b & (c ^ d));
			t = d;
			d = c;
			c = b;
			b += rotl(a + f + k[i] + w[g[i]], r[i]);
			a = t;
		}
		
		foreach (i; 16 .. 32)
		{
			f = c ^ (d & (b ^ c));
			t = d;
			d = c;
			c = b;
			b += rotl(a + f + k[i] + w[g[i]], r[i]);
			a = t;
		}
		
		foreach (i; 32 .. 48)
		{
			f = b ^ c ^ d;
			t = d;
			d = c;
			c = b;
			b += rotl(a + f + k[i] + w[g[i]], r[i]);
			a = t;
		}
		
		foreach (i; 48 .. 64)
		{
			f = c ^ (b | ~d);
			t = d;
			d = c;
			c = b;
			b += rotl(a + f + k[i] + w[g[i]], r[i]);
			a = t;
		}
		
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
	}
	
	protected override void finishInternal(ubyte[] hash)
	{
		setByte(w, offset++, cast(ubyte)0x80); // append one bit
		padTo(56);
		
		version (BigEndian)
			bits = swapEndian(bits);
		
		memCopy(w, 56, bits, 0, 8);
		transform();
		
		version (BigEndian)
		{
			foreach(ref a; h)
				a = swapEndian(a);
		}
		
		memCopy(hash, 0, h, 0, min(hashLength, hash.length));
	}
}

unittest
{
	testHashFunction!MD5();
}