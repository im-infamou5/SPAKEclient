#include <memory>
#include <string>
#include <iostream>
#include "crypto.h"


using Crypto::HMAC;

void HMAC::Compute_HMAC(Algorithms algorithm, string text, string key, size_t length, string &mac, bool ishex)
{
	string step1, step2, step3, step4, temp;
	string ipad, opad;
	size_t block_size;

	if (ishex)
	{
		text = cvtstr(text);
		key = cvtstr(key);
		length = length / 2;
	}

	text = reorder(text);

	switch (algorithm)
	{
	case 1: block_size = 32; break;
	case 2: block_size = 64; break;
	case 3: block_size = 64; break;
	}

	if (length > block_size)
	{
		switch (algorithm)
		{
		case 1: hash(key, key.length(), key); break;
		case 2: hash512(key, key.length(), key); break;
		case 3: hash512(key, key.length(), key); break;
		}
	}
	else if (length < block_size)
	{
		for (size_t i = length; i < block_size; i++)
		key += '\0';
	}
	key = reorder(key);

	ipad.assign(block_size, 0x36);
	opad.assign(block_size, 0x5c);

	for (size_t i = 0uL; i < block_size; ++i)
	{
		ipad[i] = key[i] ^ 0x36;
		opad[i] = key[i] ^ 0x5c;
	}

	step1 = ipad + text;

	switch (algorithm)
	{
		case 1: hash(reorder(step1), step1.length(), step2); break;
		case 2: hash256(reorder(step1), step1.length(), step2); break;
		case 3: hash512(reorder(step1), step1.length(), step2); break;

	}
	/*if (algorithm == algo341194)
	{ 
		temp.assign(step2);
		for (size_t i = 0uL, e = step2.length(); i < e; ++i)
		{
			temp.replace(i, 1, 1, step2[i+1]);
		
		}
		for (size_t i = 0uL, e = step2.length(); i < e; i+=2)
		{
			temp.replace(i + 1, 1, 1, step2[i]);

		}
	}*/
	
	step3 = opad + reorder(step2);
	temp.empty();

	switch (algorithm)
	{
		case 1: hash(reorder(step3), step3.length(), mac); break;
		case 2: hash256(reorder(step3), step3.length(), mac); break;
		case 3: hash512(reorder(step3), step3.length(), mac); break;
	}
	/*if (algorithm == algo341194)
	{
		step4.assign(temp);
		for (size_t i = 0uL, e = temp.length(); i < e; ++i)
		{
			step4.replace(i, 1, 1, temp[i + 1]);

		}
		for (size_t i = 0uL, e = temp.length(); i < e; i += 2)
		{
			step4.replace(i + 1, 1, 1, temp[i]);

		}
		mac = step4;
	}*/
}
