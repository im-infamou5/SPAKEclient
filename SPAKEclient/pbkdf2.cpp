#include <memory>
#include <sstream>
#include <string>
#include <sstream>
#include <bitset>
#include "crypto.h"

using namespace Crypto;
using std::stringstream;
using std::bitset;

void PBKDF2::Compute(Algorithms algorithm, string PW, string salt, unsigned keylen, string &key, unsigned iteration_count)
{
	bitset<512> bits;
	string mac;
	stringstream stream;
	HMAC hmac;

	stream << salt << 1;
	salt = stream.str();

	for (int i = 0; i <= iteration_count; i++)
	{
		if (!i)
			hmac.Compute((Algorithms)2, PW, salt, PW.length(), mac);
		if (i)
		{
			hmac.Compute((Algorithms)2, PW, mac, PW.length(), mac);
		}
	}
}