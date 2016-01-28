#include <sstream>
#include <string>
#include "crypto.h"

using namespace Crypto;
using std::stringstream;

void PBKDF2::Compute_PBKDF2(string PW, string salt, string &out, unsigned iteration_count, unsigned res_length)
{
	string mac0, mac1, mac2;
	stringstream stream;
	unsigned steps_count = res_length / 64;
	unsigned tail = res_length % 64;
	string label;
	if (tail)
		steps_count++;

	for (unsigned i = 1; i <= steps_count; i++)
	{
		label = salt + cvtstr(i);
		//stream << salt  << 1;
		//salt = stream.str();
		//stream.str(string());
		Compute_HMAC(algo341112_512, label, PW, PW.length(), mac0);
		mac2 = mac0;
		for (int i = 1; i < iteration_count; i++)
		{
			/*if (!i)
			{
				Compute_HMAC(algo341112_512, PW, salt, salt.length(), mac0);
				out = mac0;
			}*/
			
			Compute_HMAC(algo341112_512, mac0, PW, PW.length(), mac0);
				for (int i = 0uL; i < mac2.length(); ++i)
				{
					mac2[i] ^= mac0[i];
				}
				//mac2 = mac0;
				//mac0 = mac1;
				//mac1.assign("");
		}

		stream << mac2;
	}
	//stream.str(string());

	out = stream.str();
	if (tail)
	{	
		tail = 64 - tail;
		out.erase(out.length() - tail, tail);
	}

}