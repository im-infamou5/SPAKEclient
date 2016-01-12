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
	string reorder(string original);
	void VKO_local();

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
		void Stribog::hash512(string msg, unsigned long long length, string &res);
		void Stribog::hash256(string msg, unsigned long long length, string &res);
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

	class HMAC : public GOST341194, public Stribog {
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
		void PBKDF2::Compute(Algorithms algorithm, string PW, unsigned iteration_count, BigInteger salt, unsigned keylen, string &key);

	};

	class VKO : public PBKDF2 {

	private:
		ECCurve curve;
		ECPoint Px;
		ECPoint Py;
		BigInteger x, UKM;

	public:
		string K;
		VKO() {};
		VKO(ECCurve curve, ECPoint Px, BigInteger x, BigInteger UKM);

		ECCurve getCurve(){ return curve; };
		BigInteger getX(){ return x; };
		ECPoint getPx() { return Px; };
		ECPoint getPy() { return Py; };
		BigInteger getUKM() { return UKM; };


		void setX(BigInteger &x) { this->x = x; };
		void setPx(ECPoint &Px){ this->Px = Px; };
		void setPy(ECPoint &Py){ this->Py = Py; };
		void setUKM(BigInteger &UKM){ this->UKM = UKM; };
		void computePx();
		void KEK(Algorithms algorithm, ECCurve curve, BigInteger x, ECPoint Py, BigInteger UKM, string &KEK);

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

	};

	class HardSPAKE : public VKO {
	private:
		unsigned IDa, IDb, ind, IDalg;
		BigInteger salt;
		string PW;
		ECSet ecset;
		vector<unsigned> ctr;
		ECPoint Qpw;
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

	};

};

#endif _CRYPTO_H