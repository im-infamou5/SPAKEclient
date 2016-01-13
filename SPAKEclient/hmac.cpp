#include <memory>
#include <string>
#include "crypto.h"

using Crypto::HMAC;

void HMAC::Compute(Algorithms algorithm, string secret, string text, size_t length, string &mac)
{
	HMAC hmac;
	string step1, step2, step3, step4, temp;

	ipad.assign(blockSize, 0x36);
	opad.assign(blockSize, 0x5c);
	
	for (size_t i = 0uL, e = length; i < e; ++i) 
	{
		ipad.replace(i, 1, 1, secret[i] ^ 0x36);
		opad.replace(i, 1, 1, secret[i] ^ 0x5c);
	}

	step1 = ipad + text;

	switch (algorithm)
	{
		case 1: hmac.hash(step1, step1.length(), step2); break;
		//case 2: hmac.hash256(step1, step1.length(), step2); break; 
	}
	if (algorithm == algo341194)
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
	}
	
	step3 = opad + temp;
	temp.empty();

	switch (algorithm)
	{
		case 1: hmac.hash(step3, step3.length(), temp); break;
		//case 2: hmac.hash256(step3, step3.length(), mac); break;
	}
	if (algorithm == algo341194)
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
	}
}
