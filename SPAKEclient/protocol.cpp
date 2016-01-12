#include <random>
#include <string>
#include "crypto.h"

using namespace Crypto;

string Crypto::reorder(string original)
{
	string temp;
	temp.assign(original);

	for (size_t i = 0uL, e = original.length(); i < e / 2; i += 2)
	{
		temp.replace(i, 2, original, e - i - 2, 2);
		temp.replace(e - i - 2, 2, original, i, 2);

	}
	return temp;
}


std::random_device rd;
std::mt19937 eng(rd());
std::uniform_int_distribution<> lim1(3, 6);
std::uniform_int_distribution<> lim2(7, 20);
std::uniform_int_distribution<> lim3(1000, 100000);


void SoftSPAKE::initializeCTR()
{
	this->ctr[1] = lim1(eng);
	this->ctr[2] = lim2(eng);
	this->ctr[3] = lim3(eng);
}

void HardSPAKE::initializeCTR()
{
	this->ctr[1] = lim1(eng);
	this->ctr[2] = lim2(eng);
	this->ctr[3] = lim3(eng);
}


VKO::VKO(ECCurve curve, ECPoint Px, BigInteger x, BigInteger UKM)
{   
	this->curve = curve;
	this->x = x;
	this->UKM = UKM;
	this->Px = Px;
}
void VKO::computePx()
{	
	this->Px = this->curve.multiplyPoint(this->x, this->Px);

}
void VKO::KEK(Algorithms algorithm, ECCurve curve, BigInteger x, ECPoint Py, BigInteger UKM, string &KEK)
{
	BigInteger src;
	ECPoint res;
	string K;
	BigInteger h = curve.n()/curve.q();

	src = h*UKM*x;
	res = curve.multiplyPoint(src, Py);
	K = reorder(reorder(res.getX().toString()) + reorder(res.getY().toString()));

	switch (algorithm)
	{
		case 1: this->hash(K, K.length(), KEK); break;
		case 2: this->hash512(K, K.length(), KEK); break; 
	}
	


}

