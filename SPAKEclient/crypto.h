﻿#ifndef _CRYPTO_H
#define _CRYPTO_H


#include <random>
#include <vector>
#include <map>
#include <cstring>
#include <memory>
/*#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>*/
#include <string.h>
#include "BigInteger.h"
#include "stribog_data.h"
#include "gost341194_data.h" 
#include "ecc.h"

using std::map;
using std::vector;
using std::string;

typedef struct {
	unsigned IDalg;	
	string curve_label;
	ECCurve curve;
	vector<ECPoint> points;
} ECSet;

enum Algorithms {
	algo341194 = 0x1,
	algo341112 = 0x2,
	algo341112_512 = 0x3,
};


namespace Crypto
{
	void cvtstr(string str, char * out, bool ishex = false);
	string cvtstr(string str);
	string cvtstr(unsigned num);
	string cvthex(string str);
	string reorder(string original, bool ishex = false);
	int Testing_Monitor();
	int VKO_local();
	int SPAKE_local();
	int SPAKE_HPI();

	class GOST341194 {
	public:
		GOST341194::GOST341194(){};
		void GOST341194::hash(string message, unsigned long long length, string &out, bool ishex = false);
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
		void Stribog::hash512(string msg, unsigned long long length, string &res, bool ishex = false);
		void Stribog::hash256(string msg, unsigned long long length, string &res, bool ishex = false);
		void Stribog::hash512(char *message, unsigned long long length, unsigned char *out);
		void Stribog::hash256(char *message, unsigned long long length, unsigned char *out);
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
		void HMAC::Compute_HMAC(Algorithms algorithm, string text, string key, size_t length, string &mac, bool ishex = false);

	};

	class PBKDF2 : public HMAC {
	public:
		PBKDF2::PBKDF2(){};
		void PBKDF2::Compute_PBKDF2(string PW, string salt, string &out, unsigned iteration_count = 2000, unsigned res_length = 64);
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


		void VKO::setX(BigInteger &x) { this->x = x; };
		void VKO::setPx(ECPoint &Px){ this->Px = Px; };
		void VKO::setPy(ECPoint &Py){ this->Py = Py; };
		void VKO::setUKM(BigInteger &UKM){ this->UKM = UKM; };
		void VKO::computePx();
		void VKO::KEK(Algorithms algorithm, ECCurve curve, BigInteger x, ECPoint Py, BigInteger UKM, string &KEK);

	};

	class SoftSPAKE : public VKO {
	private:
		unsigned IDa, IDb, ind, IDalg;
		string PW;
		vector<ECSet> v_ecset;
		vector<unsigned> ctr;
		BigInteger salt;
		BigInteger α;
		ECPoint Qapw;
		bool za = false;
		ECPoint u1, u2, Qa;
		string Ka, MACa, MACb;
		

	public:
		SoftSPAKE::SoftSPAKE(){};
		SoftSPAKE::SoftSPAKE(string pass, vector<ECSet> vect_ecset, unsigned ID = 0, vector<unsigned> counters = {5, 20, 100000});

		void SoftSPAKE::ComputeQapw();
		void SoftSPAKE::Computeu1();
		void SoftSPAKE::Checku2();
		void SoftSPAKE::ComputeQa();
		void SoftSPAKE::CheckQa();
		void SoftSPAKE::ComputeKa();
		void SoftSPAKE::ComputeMACa();
		void SoftSPAKE::CheckMACb();
		void SoftSPAKE::Checkza();
		void SoftSPAKE::startCTR();
		void SoftSPAKE::endCTR();

		unsigned SoftSPAKE::getIDa(){ return IDa; };
		ECPoint SoftSPAKE::getu1() {return u1; };
		string SoftSPAKE::getMACa(){ return MACa; };
		BigInteger  SoftSPAKE::getα(){ return α; };
		string SoftSPAKE::getKa(){ return Ka; };

		void SoftSPAKE::setIDalg(unsigned IDalg){ this->IDalg = IDalg; };
		void SoftSPAKE::setind(unsigned ind){ this->ind = ind; };
		void SoftSPAKE::setsalt(BigInteger salt){ this->salt = salt; };
		void SoftSPAKE::setIDb(unsigned IDb){ this->IDb = IDb; };
		void SoftSPAKE::setu2(ECPoint u2){ this->u2 = u2; };
		void SoftSPAKE::setMACb(string MACb){ this->MACb = MACb; };

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

	public:
		HardSPAKE::HardSPAKE(){};
		HardSPAKE::HardSPAKE(ECSet selected_set, unsigned ident,  string pass, unsigned ID = 0, vector<unsigned> counters = { 5, 20, 100000 });

		void HardSPAKE::Checku1();
		void HardSPAKE::ComputeQb();
		void HardSPAKE::CheckQb();
		void HardSPAKE::ComputeKb();
		void HardSPAKE::Computeu2();
		void HardSPAKE::CheckMACa();
		void HardSPAKE::ComputeMACb();
		void HardSPAKE::Checkzb();
		void HardSPAKE::startCTR();
		void HardSPAKE::endCTR();

		unsigned HardSPAKE::getIDb(){ return IDb; };
		unsigned HardSPAKE::getIDalg(){ return IDalg; };
		unsigned HardSPAKE::getind(){ return ind; };
		BigInteger HardSPAKE::getsalt(){ return salt; };
		ECPoint HardSPAKE::getu2(){ return u2; };
		string HardSPAKE::getMACb(){ return MACb; };
		ECPoint HardSPAKE::getQpw(){ return Qpw; };
		BigInteger  HardSPAKE::getβ(){ return β; };
		string HardSPAKE::getKb(){ return Kb; };

		void HardSPAKE::setIDa(unsigned IDa){ this->IDa = IDa; };
		void HardSPAKE::setu1(ECPoint u1){ this->u1 = u1; };
		void HardSPAKE::setMACa(string MACa){ this->MACa = MACa; };

	};

/*	namespace Emulator
	{
		class AES
		{
		private:
			EVP_CIPHER_CTX aes_ctx;
		public:
			AES::AES();
			virtual AES::~AES();
			void AES::AESInitKey(unsigned char* key, unsigned char* iv, bool is_encrypt);
			unsigned char* AES::AESEncrypt(unsigned char *src, size_t srclen, size_t *dstlen);
			unsigned char* AES::AESDecrypt(unsigned char *src, size_t srclen, size_t *dstlen);
			void AES::Free(void* p);
		};
		class SHA256
		{
		public:
			unsigned char* SHA256::hash(unsigned char* buffer, size_t bufSize, size_t& size);
		};
		
		class HMAC 
		{
		public:
			unsigned char* HMAC::Compute(const char* key, const char* message);
		private:
			HMAC_CTX* hmac_ctx = HMAC_CTX_new();
		};
	};*/

};

#endif _CRYPTO_H