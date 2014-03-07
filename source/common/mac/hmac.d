/**
Implementation of HMAC (Hash-based Message Authentication Code).

Standards: $(LINK2 http://tools.ietf.org/html/rfc2104, RFC 2104)
Copyright: Copyright © 2011 Piotr Szturmaj
License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0)
Authors: Piotr Szturmaj
Source: $(PHOBOSSRC std/crypto/hash/_hmac.d)
*/

module source.common.mac.hmac;

public import source.common.hash.base;

final class HMAC(H : IIterativeHashFunction) if (is(H : ISaveableIV)) : HashFunction
{
	private H ifunc, ofunc; // inner and outer functions
	private ubyte[] ihash;
	
	override @property size_t hashLength()
	{
		return ifunc.hashLength;
	}
	
	override @property bool supportsBitHashing()
	{
		return ifunc.supportsBitHashing;
	}
	
	this()
	{
		ifunc = new H();
		assert(ifunc.hashLength < ifunc.blockLength);
		ofunc = new H();
		ihash = new ubyte[ifunc.hashLength];
		super();
	}
	
	void setKey(ubyte[] key)
	{
		ifunc.restoreOriginalIV();
		ofunc.restoreOriginalIV();
		
		if (key.length > ifunc.blockLength)
		{
			ifunc.reset();
			ifunc.putArray(key);
			key = ifunc.finish(key);
		}
		
		if (key.length < ifunc.blockLength)
			key.length = ifunc.blockLength;
		
		assert(key.length == ifunc.blockLength);
		
		ubyte[] ikey = key;
		ubyte[] okey = key.dup;
		
		ikey[] ^= 0x36;
		okey[] ^= 0x5c;
		
		ifunc.reset();
		ifunc.put(ikey);
		ifunc.saveIV();
		ikey[] = 0;
		
		ofunc.reset();
		ofunc.put(okey);
		ofunc.saveIV();
		okey[] = 0;
	}
	
	override void reset()
	{
		ifunc.reset();
		ofunc.reset();
	}
	
	protected override void putArray(const(ubyte)[] data)
	{
		ifunc.putArray(data);
		bits += data.length * 8;
	}
	
	protected override void finishInternal(ubyte[] mac)
	{
		ifunc.finish(ihash, getLastBits());
		ofunc.put(ihash);
		ofunc.finish(mac);
	}
}

version (unittest)
{
	import source.common.hash.md5;
}

unittest
{
	auto hmac = new HMAC!MD5();
	
	hmac.setKey(cast(ubyte[])x"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
	hmac.put("Hi There");
	assert(hmac.finish() == x"9294727a3638bb1c13f48ef8158bfc9d");
	
	hmac.setKey(cast(ubyte[])"Jefe");
	hmac.put("what do ya want for nothing?");
	assert(hmac.finish() == x"750c783e6ab0b503eaa86e310a5db738");
	
	hmac.setKey(cast(ubyte[])x"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	foreach (i; 0 .. 5)
		hmac.put(x"dddddddddddddddddddd");
	assert(hmac.finish() == x"56be34521d144c88dbb8c733f0e8b3f6");
}