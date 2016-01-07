#ifndef PCG_RNG_H
#define PCG_RNG_H

#include <cstdint>
#include <string>
#include <stdexcept>

unsigned char* genRandomBytes(unsigned char* bytes, size_t len);

template<typename T>
inline T random()
{
	T rv;
	unsigned char* bytes = reinterpret_cast<unsigned char*>(&rv);
	genRandomBytes(bytes, sizeof(rv));
	return rv;
}

#endif
