#include <memory>
#include <sstream>
#include <string>
#include <sstream>
#include <bitset>
#include "crypto.h"

using namespace Crypto;
using std::stringstream;
using std::bitset;

void PBKDF2::Compute_PBKDF2(Algorithms algorithm, string PW, string salt, unsigned keylen, string &key, string &out, unsigned iteration_count)
{
	bitset<256> bits256;
	bitset<512> bits512;
	string mac[1];
	stringstream stream;
	HMAC hmac;

	stream << salt << 1;
	salt = stream.str();

	for (int i = 0; i < iteration_count; i++)
	{
		if (!i)
			hmac.Compute_HMAC((Algorithms)algorithm, PW, salt, PW.length(), mac[0]);
		if (keylen == 512)
		{
			bits512 = (bitset<512>)mac[0];
		}
		else bits256 = (bitset<256>)mac[0];

		if (i)
		{
			hmac.Compute_HMAC((Algorithms)algorithm, PW, mac[0], PW.length(), mac[1]);
			if (keylen == 512)
			{
				bits512 ^= (bitset<512>)mac[1];
			}
			else
			{
				bits256 ^= (bitset<256>)mac[1];
			}
			mac[0] = mac[1];
			mac[1].assign("");
		}
	}
	stream.clear();
	switch (algorithm)
	{
		case 1: stream << std::hex << bits256; break;
		case 2: stream << std::hex << bits512; break;
	}
	out = stream.str();
}