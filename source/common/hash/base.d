/**
Base classes for cryptographic hash functions (message digests).

Example:
---
auto sha1 = new SHA1;
sha1.put("The quick brown fox jumps over the lazy do");
sha1.put("g");

assert(sha1.finishToHex() == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
---

Copyright: Copyright © 2011 Piotr Szturmaj
License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0)
Authors: Piotr Szturmaj
Source: $(PHOBOSSRC std/crypto/hash/_merkledamgard.d)
*/

module crypto.hash.base;

import std.ascii, std.exception, std.range, std.string, std.traits;
import std.c.string;

package:
/*
Currently DMD and GDC does not translate these templated function to ROR/ROL instructions,
so there are defined non templated functions which are properly translated
*/

// should be ror instruction for x86
T _rotr(T)(T value, uint shift) @safe pure nothrow
	if (isIntegral!T)
{
	return cast(T)((value >> shift) | (value << (T.sizeof * 8 - shift)));
}

// function that translates to ror
uint rotr(in uint value, in uint shift) @safe pure nothrow
{
	return (value >> shift) | (value << (32 - shift));
}

ulong rotr(in ulong value, in uint shift) @safe pure nothrow
{
	return (value >> shift) | (value << (64 - shift));
}

// should be rol instruction for x86
T _rotl(T)(T value, uint shift) @safe pure nothrow
	if (isIntegral!T)
{
	return cast(T)((value << shift) | (value >> (T.sizeof * 8 - shift)));
}

// function that translates to rol
uint rotl(in uint value, in uint shift) @safe pure nothrow
{
	return (value << shift) | (value >> (32 - shift));
}

ulong rotl(in ulong value, in uint shift) @safe pure nothrow
{
	return (value << shift) | (value >> (64 - shift));
}

// for CTFE
void setByte(A)(ref A a, size_t offset, ubyte value) @trusted pure nothrow
	if (isArray!A)
{
	if (__ctfe)
	{
		alias ElementType!A E;
		a[offset / E.sizeof] |= value << ((offset % E.sizeof) * 8);
	}
	else
	{
		(cast(ubyte[])a)[offset] = value;
	}
}

ubyte getByte(A)(ref A a, size_t offset) pure nothrow
	if (isArray!A)
{
	alias ElementType!A E;
	return a[offset / E.sizeof] >> ((offset % E.sizeof) * 8) & 0xFF;
}

ubyte getByte(T)(T t, size_t offset) pure nothrow
	if (isIntegral!T)
{
	return t >> (offset * 8) & 0xFF;
}

void memCopy(Dst, Src)(ref Dst dst, size_t dstOffset, in Src src, size_t srcOffset, size_t length) @trusted pure nothrow
	if ((isArray!Src || isIntegral!Src) && isArray!Dst)
{
	if (__ctfe)
	{
		foreach (i; 0 .. length)
			setByte(dst, dstOffset + i, getByte(src, srcOffset + i));
	}
	else
	{
		alias length l;
		static if (isArray!Src)
			(cast(ubyte[])dst)[dstOffset .. dstOffset + l] = (cast(ubyte[])src)[srcOffset .. srcOffset + l];
		else
			(cast(ubyte[])dst)[dstOffset .. dstOffset + l] = (cast(ubyte*)&src + srcOffset)[0 .. l];
	}
}

void memSet(A)(ref A a, size_t offset, size_t length, ubyte value) @trusted pure nothrow
	if (isArray!A)
{
	if (__ctfe)
	{
		foreach (i; 0 .. length)
			setByte(a, offset + i, value);
	}
	else
	{
		alias length l;
		(cast(ubyte[])a)[offset .. offset + l] = value;
	}
}

void memSet(A)(ref A a, size_t offset, ubyte value)
	if (isArray!A)
{
	if (__ctfe)
	{
		alias ElementType!A E;
		memSet(a, offset, a.length * E.sizeof - offset, value);
	}
	else
	{
		(cast(ubyte[])a)[offset .. $] = value;
	}
}

public:

/// Base class for all hash functions
abstract class HashFunction
{
	/*
Total hashed bits, used internally by hash function implementations
Typically useful in finishInternal() when number of bits is needed to compute a hash
*/
	protected ulong bits;
	// Used internally by hash implementations to compute a hash
	protected abstract void finishInternal(ubyte[] hash);
	/// Hash length in bytes
	abstract @property size_t hashLength();
	/**
All hash functions support byte (octet) hashing, but not all of them support messages
that have length expressed in bits. This property return true if bit hashing is supported.
*/
	abstract @property bool supportsBitHashing();
	/// Resets to the initial state
	abstract void reset();
	// Implement this to handle incoming data
	abstract void putArray(const(ubyte)[] data);
	
	this()
	{
		reset();
	}
	
	/**
Hash function update operation. This also forms an OutputRange.
Params: data = Data to append to the hash buffer. May be an input range.
*/
	final void put(T)(in T data)
	{
		static if (isArray!T)
			putArray(cast(ubyte[])data);
		else static if (isInputRange!T)
		{
			foreach (e; data)
				put(e);
		}
		else
			putArray((cast(ubyte*)&data)[0 .. T.sizeof]);
	}
	
	/**
Finalizes hash computation and returns computed hash.
Hash buffer is filled up to its length, so this may be used to get truncated hashes. If hash
buffer is not specified then full hash is returned.
Params:
hash = Optional hash buffer. If it is null the buffer is created internally. However, it is
recommended to create that buffer manually to avoid unnecessary array allocations, especially
when computing many hashes.
lastBits = If hash function support per bit hashing this specifies how many bits
was in the last appended byte.
Returns: Computed hash as ubyte array.
*/
	final ubyte[] finish(ubyte[] hash = null, ubyte lastBits = 8)
	{
		enforce(lastBits >= 1 && lastBits <= 8, "lastBits argument must be in range from 1 to 8");
		if (lastBits < 8)
			enforce(supportsBitHashing, typeof(this).stringof ~ " hash function does not support per bit hashing");
		if (!hash)
			hash = new ubyte[hashLength];
		bits -= 8 - lastBits;
		finishInternal(hash);
		return hash;
	}
	
	/**
Finalizes hash computation and returns computed hash as hex string.
Params:
lowerCase = true if hex string must be in lower case, false if in upper case
lastBits = If hash function support per bit hashing this specifies how many bits
was in the last appended byte.
Returns: Computed hash as hex string.
*/
	final string finishToHex(bool lowerCase = true, ubyte lastBits = 8)
	{
		ubyte[] hash = finish(null, lastBits);
		char[] hex = new char[hashLength * 2];
		
		foreach (i, b; hash)
		{
			hex[i * 2] = hexDigits[b >> 4];
			hex[i * 2 + 1] = hexDigits[b & 0x0F];
		}
		
		if (lowerCase)
			hex = toLower(hex);
		
		return cast(string)hex;
	}
	
	// to get lastBits from inside finishInternal()
	final protected ubyte getLastBits()
	{
		ubyte lastBits = bits % 8;
		return lastBits ? lastBits : 8;
	}
}

interface IIterativeHashFunction
{
	@property size_t blockLength();
}

interface ISaveableIV : IIterativeHashFunction
{
	void saveIV();
	void restoreOriginalIV();
}

/// Base class for Merkle–Damgård hash functions
abstract class MerkleDamgard : HashFunction, IIterativeHashFunction
{
	/// Block length in bytes;
	abstract @property size_t blockLength();
	
	override @property bool supportsBitHashing()
	{
		return true;
	}
	
	@safe nothrow
	protected abstract void setIV();
	@safe nothrow pure
	protected abstract void transform();
}

abstract class MerkleDamgardImpl(Word, size_t ivSize, size_t stateSize, size_t blockSize,
                                 size_t hashLen) : MerkleDamgard, ISaveableIV
{
	private Word[] savedIV = null;
	protected static const blockLen = blockSize * Word.sizeof;
	protected Word[ivSize] h;
	protected Word[stateSize] w;
	protected size_t offset;
	
	final override @property size_t blockLength() @safe pure nothrow const
	{
		return blockLen;
	}
	
	final override @property size_t hashLength() @safe pure nothrow const
	{
		return hashLen;
	}
	
	final override void reset() @safe nothrow
	{
		if (savedIV)
			h[] = savedIV;
		else
			setIV();
		offset = 0;
		bits = 0;
	}
	
	final void saveIV()
	{
		if (!savedIV)
			savedIV = new Word[ivSize];
		savedIV[] = h;
	}
	
	final void restoreOriginalIV()
	{
		savedIV = null;
	}
	
	final protected void padTo(in size_t bytes, in ubyte pad = 0) @trusted nothrow
	{
		assert(bytes < blockLength);
		
		if (offset > bytes)
		{
			// we need additional block
			memSet(w, offset, pad);
			transform();
			memSet(w, 0, bytes, pad);
		}
		else
		{
			memSet(w, offset, bytes - offset, pad);
		}
		
		offset = bytes;
	}
	
	final override void putArray(const(ubyte)[] data) @trusted nothrow
	{
		bits += data.length << 3;
		size_t remaining = blockLength - offset;
		
		if (data.length >= remaining)
		{
			memCopy(w, offset, data, 0, remaining);
			
			transform();
			data = data[remaining .. $];
			
			if (data.length >= blockLength)
			{
				size_t blockCount = data.length / blockLength;
				
				foreach (i; 0 .. blockCount)
				{
					memCopy(w, 0, data, i * blockLength, blockLength);
					transform();
				}
				
				data = data[blockCount * blockLength .. $];
			}
			
			offset = 0;
		}
		
		if (data.length)
		{
			memCopy(w, offset, data, 0, data.length);
			offset += data.length;
		}
	}
}

///
template hash(H : HashFunction)
{
	/**
Shorthand function to hash data
Params:
data = Data to hash
Returns: Computed hash as ubyte array.
Example:
---
ubyte[] digest = hash!SHA1("The quick brown fox jumps over the lazy dog");
assert(digest.length == 20);
---
*/
	auto hash(T)(in T data)
	{
		auto h = new H;
		h.put(data);
		return h.finish();
	}
}

///
template hashToHex(H : HashFunction)
{
	/**
Shorthand function to hash data

Params:
data = Data to hash
lowerCase = true if hex string must be in lower case, false if in upper case
Returns: Computed hash as hex string.
Example:
---
string digest = hashToHex!SHA1("The quick brown fox jumps over the lazy dog");
assert(digest == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
---
*/
	auto hashToHex(T)(in T data, bool lowerCase = true)
	{
		auto h = new H;
		h.put(data);
		return h.finishToHex(lowerCase);
	}
}

version (unittest)
{
	void testHashFunction(T : HashFunction)()
	{
		static assert(isOutputRange!(T, void[]));
		static assert(is(typeof(T.testVectors) == const string[]));
		
		auto func = new T;
		
		for (size_t i = 0; i < T.testVectors.length; i += 2)
		{
			string msg = T.testVectors[i];
			string hash = T.testVectors[i + 1];
			string result;
			auto test = {
				string inp = msg.length ? msg : "(empty string)";
				assert(result == hash, T.stringof ~ ": wrong hash!\ninput: " ~ inp ~
				       "\nhash : " ~ result ~ "\nvalid: " ~ hash);
			};
			
			func.reset();
			func.put(msg);
			result = func.finishToHex();
			test();
			
			// test the same message, but input per char
			func.reset();
			foreach (c; msg)
				func.put(c);
			result = func.finishToHex();
			test();
			
			if (msg.length > func.blockLength)
			{
				// test for input consistency
				string cat;
				func.reset();
				
				foreach (_; 0 .. 3)
				{
					cat ~= msg;
					func.put(msg);
				}
				
				hash = func.finishToHex();
				
				func.reset();
				func.put(cat);
				result = func.finishToHex();
				test();
			}
		}
	}
}