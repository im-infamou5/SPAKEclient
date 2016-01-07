#include <memory>
#include <sstream>
#include <string>
#include <sstream>
#include "crypto.h"

using Crypto::PBKDF2;
using std::stringstream;

void PBKDF2::Compute(Algorithms algorithm, string PW, unsigned iteration_count, BigInteger salt, unsigned keylen, string &key)
{

}