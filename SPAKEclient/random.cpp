/* Any copyright is dedicated to the Public Domain.
* http://creativecommons.org/publicdomain/zero/1.0/ */
// Written in 2014 by Nils Maier

#include "random.h"

#include <limits>
#include <algorithm>


#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX
#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

// Implement our "generator" only with proven OS-level stuff.
unsigned char* genRandomBytes(unsigned char* bytes, size_t len)
{
	if (!len) {
		return bytes;
	}
	static HCRYPTPROV prov = 0;
	if (!prov &&
		!CryptAcquireContext(
		&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		throw std::runtime_error("Cannot aquire random provider");
	}
	auto p = bytes;
	while (len) {
		const DWORD turn = std::min(len, (size_t)std::numeric_limits<DWORD>::max());
		if (!CryptGenRandom(prov, turn, p)) {
			throw std::runtime_error("Failed to get required number of random bytes");
		}
		p += turn;
		len -= turn;
	}
	return bytes;
}
