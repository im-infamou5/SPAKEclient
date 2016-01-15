#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <sstream>
#include <string>
#include <bitset>
#include "stribog_data.h" 
#include "crypto.h"


using std::stringstream;
using std::string;
using std::bitset;
using Crypto::Stribog;
using Crypto::cvtstr;
using Crypto::reorder;

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include "stribog_data.h"


void Stribog::AddModulo512(const unsigned char *a, const unsigned char *b, unsigned char *c)
{
	int i = 0, t = 0;

	for (i = 63; i >= 0; i--)
	{
		t = a[i] + b[i] + (t >> 8);
		c[i] = t & 0xFF;
	}
}

void Stribog::AddXor512(const void *a, const void *b, void *c)
{
	int i = 0;
	long long *A = (long long*)a, *B = (long long*)b;
	unsigned long long *C = (unsigned long long*)c;

	for (i = 0; i<8; i++)
	{
		C[i] = A[i] ^ B[i];
	}
}

void Stribog::S(unsigned char *state)
{
	int i = 0;

	for (i = 0; i<64; i++)
	{
		state[i] = Sbox[state[i]];
	}
}

void Stribog::L(unsigned char *state)
{
	unsigned long long v = 0;
	int i = 0, j = 0, k = 0;

	for (i = 0; i<8; i++)
	{
		v = 0;
		for (k = 0; k<8; k++)
		{
			for (j = 0; j<8; j++)
			{
				if ((state[i * 8 + k] & (1 << (7 - j))) != 0)
					v ^= A[k * 8 + j];
			}
		}
		for (k = 0; k<8; k++)
		{
			state[i * 8 + k] = (v & ((unsigned long long)0xFF << (7 - k) * 8)) >> (7 - k) * 8;
		}
	}
}

void Stribog::P(unsigned char *state)
{
	int i = 0;
	unsigned char t[64] = {};

	for (i = 0; i<64; i++)
	{
		t[i] = state[Tau[i]];
	}

	memcpy(state, t, 64);
}

void Stribog::KeySchedule(unsigned char *K, int i)
{
	AddXor512(K, C[i], K);

	S(K);
	P(K);
	L(K);
}

void Stribog::E(unsigned char *K, const unsigned char *m, unsigned char *state)
{
	int i = 0;

	memcpy(K, K, 64);

	AddXor512(m, K, state);

	for (i = 0; i<12; i++)
	{
		S(state);
		P(state);
		L(state);
		KeySchedule(K, i);
		AddXor512(state, K, state);
	}
}

void Stribog::g_N(const unsigned char *N, unsigned char *h, const unsigned char *m)
{
	unsigned char t[64], K[64];

	AddXor512(N, h, K);

	S(K);
	P(K);
	L(K);

	E(K, m, t);

	AddXor512(t, h, t);
	AddXor512(t, m, h);
}

void Stribog::hash_X(unsigned char *IV, char *message, unsigned long long length, unsigned char *out)
{
	unsigned char v512[64] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00
	};
	unsigned char v0[64] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char Sigma[64] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char N[64] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	unsigned char m[64], *hash = IV;
	unsigned long long len = length;

	// Stage 2
	while (len >= 512)
	{
		memcpy(m, message + len / 8 - 63 - ((len & 0x7) == 0), 64);

		g_N(N, hash, m);
		AddModulo512(N, v512, N);
		AddModulo512(Sigma, m, Sigma);
		len -= 512;
	}

	memset(m, 0, 64);
	memcpy(m + 63 - len / 8 + ((len & 0x7) == 0), message, len / 8 + 1 - ((len & 0x7) == 0));

	// Stage 3
	m[63 - len / 8] |= (1 << (len & 0x7));

	g_N(N, hash, m);
	v512[63] = len & 0xFF;
	v512[62] = len >> 8;
	AddModulo512(N, v512, N);

	AddModulo512(Sigma, m, Sigma);

	g_N(v0, hash, N);
	g_N(v0, hash, Sigma);

	memcpy(out, hash, 64);

}


void hexPrinter(unsigned char* c, int l)
{

	while (l > 0)
	{
		printf("%02x", *c);
		l--;
		c++;
	}
	printf("\n");
}


void Stribog::hash512(char *message, unsigned long long length, unsigned char *out)
{
	unsigned char IV[64] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	hash_X(IV, message, length, out);

}

void Stribog::hash256(char *message, unsigned long long length, unsigned char *out)
{
	unsigned char IV[64] =
	{
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
	};
	unsigned char hash[64];

	hash_X(IV, message, length, hash);

	memcpy(out, hash, 32);

}

void Stribog::hash512(string msg, unsigned long long length, string &res, bool ishex)
{
	char* tmp;
	unsigned char* out;
	unsigned char* out_tmp;
	unsigned long long s_length;
	stringstream ss;
	if (ishex)
		s_length = length / 2;
	else
		s_length = length;
	tmp = (char*)malloc(s_length);
	out = (unsigned char *)malloc(65);
	out_tmp = (unsigned char *)malloc(3);
	cvtstr(msg, tmp,ishex);

	hash512(tmp, s_length * 8, out);
	
	for (int i = 0; i < 64; i++)
	{
		sprintf((char *)out_tmp, "%02x", out[i]);
		ss << (unsigned char *)out_tmp;
	}
	
	ss >> res;
	
	free(tmp);
	free(out);
	free(out_tmp);
}

void Stribog::hash256(string msg, unsigned long long length, string &res, bool ishex)
{
	char* tmp;
	unsigned char* out;
	unsigned char* out_tmp;
	unsigned long long s_length;
	stringstream ss;
	if (ishex)
		s_length = length / 2;
	else
		s_length = length;
	tmp = (char*)malloc(s_length);
	out = (unsigned char *)malloc(33);
	out_tmp = (unsigned char *)malloc(3);
	cvtstr(msg, tmp, ishex);

	hash256(tmp, s_length * 8, out);

	for (int i = 0; i < 32; i++)
	{
		sprintf((char *)out_tmp, "%02x", out[i]);
		ss << (unsigned char *)out_tmp;
	}

	ss >> res;

	free(tmp);
	free(out);
	free(out_tmp);
}