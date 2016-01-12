#ifndef _CRYPTO_H
#define _CRYPTO_H

#define GOST341194_BLOCKSIZE 256
#define GOST341112_BLOCKSIZE 512

#include <random>
#include <vector>
#include <map>
#include <cstring>
#include <memory>
#include "BigInteger.h"
#include "stribog_data.h"
#include "gost341194_data.h" 
#include "ecc.h"

using std::map;
using std::vector;

typedef struct {
	unsigned N;
	map < unsigned, ECCurve, map<unsigned, ECPoint>> Map;
} ECSet;

enum Algorithms {
	algo341194 = 0x1,
	algo341112 = 0x2,
};

namespace Crypto
{
	class GOST341194 {
	public:
		GOST341194::GOST341194(){};
		void GOST341194::hash(string message, unsigned long long length, string &out);
	private:
		int GOST341194::fi(int argument);
		void GOST341194::E_f(unsigned char A[], unsigned char K[], unsigned char R[]);//Функция f в ГОСТ 28147-89
		void GOST341194::E(unsigned char D[], unsigned char K[], unsigned char R[]);
		void GOST341194::A_Y(unsigned char Y[], unsigned char R[]);
		void GOST341194::P_Y(unsigned char Y[], unsigned char R[]);
		void GOST341194::psi_Y(unsigned char arr[]);
		void GOST341194::psi_round(unsigned char arr[], int p);
		void GOST341194::f(unsigned char H[], unsigned char M[], unsigned char newH[]);
	};

	class Stribog {
	public:
		Stribog::Stribog(){};
		void hash512(char *message, unsigned long long length, unsigned char *hash);
		void hash256(char *message, unsigned long long length, unsigned char *hash);
	private:
		void Stribog::AddModulo512(const unsigned char *a, const unsigned char *b, unsigned char *c);
		void Stribog::F(unsigned char *state);
		void Stribog::AddXor512(const void *a, const void *b, void *c);
		void Stribog::S(unsigned char *state);
		void Stribog::P(unsigned char *state);
		void Stribog::L(unsigned char *state);
		void Stribog::E(unsigned char *K, const unsigned char *m, unsigned char *state);
		void Stribog::KeySchedule(unsigned char *K, int i);
		void Stribog::g_N(const unsigned char *N, unsigned char *h, const unsigned char *m);
		void Stribog::hash_X(unsigned char *IV, char *message, unsigned long long length, unsigned char *out);
		bool Stribog::selftest();
	};

	class HMAC : public GOST341194, Stribog {
	public:
		HMAC::HMAC(){};
		void HMAC::Compute(Algorithms algorithm, string secret, string text, size_t length, string &mac);

	private:
		const size_t blockSize = GOST341194_BLOCKSIZE;
		string ipad, opad, text, mac;
	};

	class PBKDF2 : public HMAC {
	public:
		PBKDF2::PBKDF2(){};
		void PBKDF2::Compute(Algorithms algorithm, string PW, string salt, unsigned keylen, string &key, unsigned iteration_count = 2000);
	};

	class VKO : public GOST341194, Stribog {

	private:
		ECCurve curve;
		ECPoint Px;
		ECPoint Py;
		BigInteger x, y, UKM, K;

	public:
		VKO(){};
		VKO(const ECCurve &curve);
		VKO(const ECCurve &c, ECPoint &Px, BigInteger &x, BigInteger &UKM);
		VKO(const ECPoint &p);
		VKO(const BigInteger &x, const BigInteger &y);

		BigInteger getX();
		BigInteger getY();
		BigInteger getK();

		void SetUKM(BigInteger &UKM);
		void SetK(BigInteger &K);
		void SetX(BigInteger &x);
		void SetY(BigInteger &y);
		void KEK(ECCurve &curve, BigInteger &x, ECPoint &Py, BigInteger &UKM, BigInteger &K);

		bool isPointAtInfinity();
		bool operator==(ECPoint &p);
	};

	class SoftSPAKE : public VKO {
		/*friend void
		hash_512(const unsigned char *message, unsigned long long length, unsigned char *out),
		hash_256(const unsigned char *message, unsigned long long length, unsigned char *out),*/
	private:
		unsigned IDa, IDb, ind, IDalg;
		string PW;
		ECSet ecset;
		vector<unsigned> ctr;
		BigInteger salt;
		BigInteger α;
		ECPoint Qapw;
		bool za = false;
		ECPoint u1, u2, Qa;
		string Ka, MACa;
		

	public: //TODO - сделать прототипы методов в соответствии с протоколом
		SoftSPAKE(){};
		SoftSPAKE(const ECPoint &p);
		SoftSPAKE(const BigInteger &x, const BigInteger &y);

		void initializeCTR();
		void ComputeQapw();
		void Computeu1();
		void ComputeQa();
		void CheckQa();
		void ComputeKa();
		void ComputeMACa();
		void CheckMACb();
		void startCTR();
		void endCTR();

		BigInteger getX();
		BigInteger getY();

		bool isPointNull();
		bool isPointAtInfinity();
		bool operator==(ECPoint &p);
	};

	class HardSPAKE {
	private:
		ECPoint Qpw;
		unsigned IDa, IDb, ind, IDalg;
		string PW;
		ECSet ecset;
		vector<unsigned> ctr;
		BigInteger salt;
		BigInteger β;
		bool zb = false;
		ECPoint u1, u2, Qb;
		string Kb, MACa, MACb;

	public://TODO - сделать прототипы методов в соответствии с протоколом
		HardSPAKE(){};
		HardSPAKE(const ECPoint &p);
		HardSPAKE(const BigInteger &x, const BigInteger &y);

		void initializeCTR();
		void ComputeQpw();
		void ComputeQb();
		void CheckQb();
		void ComputeKb();
		void Computeu2();
		void CheckMACa();
		void ComputeMACb();

		BigInteger getX();
		BigInteger getY();

		bool isPointAtInfinity();
		bool operator==(ECPoint &p);
	};

};

#endif _CRYPTO_H