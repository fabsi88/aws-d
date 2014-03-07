/**
Implementation of SHA family hash functions:
$(UL
$(LI SHA-1)
$(LI SHA-224)
$(LI SHA-256)
$(LI SHA-384)
$(LI SHA-512)
$(LI SHA-512/224)
$(LI SHA-512/256)
$(LI SHA-512/t)
)

Standards: $(LINK2 http://csrc.nist.gov/publications/PubsDrafts.html#fips-180-4,
Secure Hash Standard (FIPS-180-4))
Copyright: Copyright © 2011 Piotr Szturmaj
License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0)
Authors: Piotr Szturmaj
Source: $(PHOBOSSRC std/crypto/hash/_sha.d)
*/

module source.common.hash.sha;

import std.algorithm, std.bitmanip, std.c.string;
public import source.common.hash.base;

private:

immutable uint[64] k256 = [
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

immutable ulong[80] k512 = [
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

public:

///
final class SHA1 : MerkleDamgardImpl!(uint, 5, 80, 16, 20)
{
	version (unittest) static const string[] testVectors = [
		"", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
		"abc", "a9993e364706816aba3e25717850c26c9cd0d89d",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"761c457bf73b14d27e9e9265c46f4b4dda11f940",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"50abf5706a150990a08b2c5ea40fa0e585554732"
	];
	
	protected override void setIV() @safe nothrow
	{
		h[0] = 0x67452301;
		h[1] = 0xefcdab89;
		h[2] = 0x98badcfe;
		h[3] = 0x10325476;
		h[4] = 0xc3d2e1f0;
	}
	
	protected override void transform() @safe nothrow pure
	{
		version (LittleEndian)
		{
			foreach (i; 0 .. 16)
				w[i] = swapEndian(w[i]);
		}
		
		foreach (i; 16 .. 80)
			w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
		
		uint a, b, c, d, e, f, k, t;
		
		a = h[0];
		b = h[1];
		c = h[2];
		d = h[3];
		e = h[4];
		
		k = 0x5a827999;
		
		foreach (i; 0 .. 20)
		{
			f = (b & c) | (~b & d);
			t = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = t;
		}
		
		k = 0x6ed9eba1;
		
		foreach (i; 20 .. 40)
		{
			f = b ^ c ^ d;
			t = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = t;
		}
		
		k = 0x8f1bbcdc;
		
		foreach (i; 40 .. 60)
		{
			f = (b & c) | (b & d) | (c & d);
			t = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = t;
		}
		
		k = 0xca62c1d6;
		
		foreach (i; 60 .. 80)
		{
			f = b ^ c ^ d;
			t = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = t;
		}
		
		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
	}
	
	protected override void finishInternal(ubyte[] hash)
	{
		setByte(w, offset++, cast(ubyte)0x80); // append one bit
		padTo(56);
		
		version (LittleEndian)
			bits = swapEndian(bits);
		
		memCopy(w, 56, bits, 0, 8);
		transform();
		
		version (LittleEndian)
		{
			foreach (ref a; h)
				a = swapEndian(a);
		}
		
		memCopy(hash, 0, h, 0, min(hashLength, hash.length));
	}
}

private class SHA256Internal(size_t hashLength) : MerkleDamgardImpl!(uint, 8, 64, 16, hashLength)
{
	protected override void setIV() @safe nothrow
	{
		h[0] = 0x6a09e667;
		h[1] = 0xbb67ae85;
		h[2] = 0x3c6ef372;
		h[3] = 0xa54ff53a;
		h[4] = 0x510e527f;
		h[5] = 0x9b05688c;
		h[6] = 0x1f83d9ab;
		h[7] = 0x5be0cd19;
	}
	
	protected override void transform() @safe nothrow pure
	{
		version (LittleEndian)
		{
			foreach (i; 0 .. 16)
				w[i] = swapEndian(w[i]);
		}
		
		uint a, b, c, d, e, f, g, h;
		uint s0, s1, ch, maj, t1, t2;
		
		foreach (i; 16 .. 64)
		{
			s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		
		a = this.h[0];
		b = this.h[1];
		c = this.h[2];
		d = this.h[3];
		e = this.h[4];
		f = this.h[5];
		g = this.h[6];
		h = this.h[7];
		
		foreach (i; 0 .. 64)
		{
			s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			ch = (e & f) ^ (~e & g);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t1 = h + s1 + ch + k256[i] + w[i];
			t2 = s0 + maj;
			
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		this.h[0] += a;
		this.h[1] += b;
		this.h[2] += c;
		this.h[3] += d;
		this.h[4] += e;
		this.h[5] += f;
		this.h[6] += g;
		this.h[7] += h;
	}
	
	protected override void finishInternal(ubyte[] hash)
	{
		setByte(w, offset++, cast(ubyte)0x80); // append one bit
		padTo(56);
		
		version (LittleEndian)
			bits = swapEndian(bits);
		
		memCopy(w, 56, bits, 0, 8);
		transform();
		
		version (LittleEndian)
		{
			foreach(ref a; h)
				a = swapEndian(a);
		}
		
		memCopy(hash, 0, h, 0, min(hashLength, hash.length));
	}
}

///
final class SHA256 : SHA256Internal!32
{
	version (unittest) static const string[] testVectors = [
		"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
	];
}

///
final class SHA224 : SHA256Internal!28
{
	version (unittest) static const string[] testVectors = [
		"", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
	];
	
	protected override void setIV() @safe nothrow
	{
		h[0] = 0xc1059ed8;
		h[1] = 0x367cd507;
		h[2] = 0x3070dd17;
		h[3] = 0xf70e5939;
		h[4] = 0xffc00b31;
		h[5] = 0x68581511;
		h[6] = 0x64f98fa7;
		h[7] = 0xbefa4fa4;
	}
}

private class SHA512Internal(size_t hashLength) : MerkleDamgardImpl!(ulong, 8, 80, 16, hashLength)
{
	protected override void setIV() @safe nothrow
	{
		h[0] = 0x6a09e667f3bcc908;
		h[1] = 0xbb67ae8584caa73b;
		h[2] = 0x3c6ef372fe94f82b;
		h[3] = 0xa54ff53a5f1d36f1;
		h[4] = 0x510e527fade682d1;
		h[5] = 0x9b05688c2b3e6c1f;
		h[6] = 0x1f83d9abfb41bd6b;
		h[7] = 0x5be0cd19137e2179;
	}
	
	protected override void transform() @safe nothrow pure
	{
		version (LittleEndian)
		{
			foreach (i; 0 .. 16)
				w[i] = swapEndian(w[i]);
		}
		
		ulong a, b, c, d, e, f, g, h;
		ulong s0, s1, ch, maj, t1, t2;
		
		foreach (i; 16 .. 80)
		{
			s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
			s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		
		a = this.h[0];
		b = this.h[1];
		c = this.h[2];
		d = this.h[3];
		e = this.h[4];
		f = this.h[5];
		g = this.h[6];
		h = this.h[7];
		
		foreach (i; 0 .. 80)
		{
			s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
			s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
			ch = (e & f) ^ (~e & g);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t1 = h + s1 + ch + k512[i] + w[i];
			t2 = s0 + maj;
			
			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
		}
		
		this.h[0] += a;
		this.h[1] += b;
		this.h[2] += c;
		this.h[3] += d;
		this.h[4] += e;
		this.h[5] += f;
		this.h[6] += g;
		this.h[7] += h;
	}
	
	protected override void finishInternal(ubyte[] hash) @trusted nothrow
	{
		setByte(w, offset++, cast(ubyte)0x80);
		padTo(112);
		
		version (LittleEndian)
			bits = swapEndian(bits);
		
		w[14] = 0;
		w[15] = bits;
		
		transform();
		
		version (LittleEndian)
		{
			foreach(ref a; h)
				a = swapEndian(a);
		}
		
		memCopy(hash, 0, h, 0, min(hashLength, hash.length));
	}
}

///
final class SHA512 : SHA512Internal!64
{
	version (unittest) static const string[] testVectors = [
		"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
		"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843"
	];
}

///
final class SHA384 : SHA512Internal!48
{
	version (unittest) static const string[] testVectors = [
		"", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"a", "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
		"abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		"1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026"
	];
	
	protected override void setIV() @safe nothrow
	{
		h[0] = 0xcbbb9d5dc1059ed8;
		h[1] = 0x629a292a367cd507;
		h[2] = 0x9159015a3070dd17;
		h[3] = 0x152fecd8f70e5939;
		h[4] = 0x67332667ffc00b31;
		h[5] = 0x8eb44a8768581511;
		h[6] = 0xdb0c2e0d64f98fa7;
		h[7] = 0x47b5481dbefa4fa4;
	}
}

///
class SHA512_t(size_t tbits) if (tbits < 512 && tbits != 384) : SHA512Internal!(tbits / 8)
{
	private static ulong[8] IV;
	
	static this()
	{
		auto sha512 = new SHA512;
		
		foreach (ref h; sha512.h)
			h ^= 0xa5a5a5a5a5a5a5a5;
		
		sha512.put(std.conv.text("SHA-512/", tbits));
		sha512.finish(cast(ubyte[])IV);
		
		version (LittleEndian)
		{
			foreach (ref h; IV)
				h = swapEndian(h);
		}
	}
	
	protected final override void setIV() @safe nothrow
	{
		h = IV;
	}
}

///
final class SHA512_224 : SHA512_t!224
{
	version (unittest) static const string[] testVectors = [
		"abc", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
	];
}

///
final class SHA512_256 : SHA512_t!256
{
	version (unittest) static const string[] testVectors = [
		"abc", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
	];
}

unittest
{
	testHashFunction!SHA1();
	testHashFunction!SHA224();
	testHashFunction!SHA256();
	testHashFunction!SHA384();
	testHashFunction!SHA512();
	testHashFunction!SHA512_224();
	testHashFunction!SHA512_256();
}