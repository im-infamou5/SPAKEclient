#include <sstream>
#include <string>
#include <sstream>
#include "crypto.h"

using namespace Crypto;
using std::stringstream;

void PBKDF2::Compute_PBKDF2(Algorithms algorithm, string PW, string salt, string &out, unsigned iteration_count)
{
	string mac0, mac1, mac2;
	stringstream stream;

	stream << salt << 1;
	salt = stream.str();

	for (int i = 0; i < iteration_count; i++)
	{
		if (!i)
		{
			Compute_HMAC((Algorithms)algorithm, PW, salt, salt.length(), mac0);
			out = mac0;
		}
		if (i)
		{
			Compute_HMAC((Algorithms)algorithm, PW, mac0, mac0.length(), mac1);
			for (size_t i = 0uL; i < mac0.length(); ++i)
			{
				mac0[i] ^= mac1[i];
			}
			mac2 = mac0;
			mac0 = mac1;
			mac1.assign("");
		}
	}
	stream.str(std::string());

	stream << std::hex << mac2; 

	out = stream.str();


}