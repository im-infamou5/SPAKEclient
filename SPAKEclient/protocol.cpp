#include <random>
#include <string>
#include <sstream>
#include "crypto.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace Crypto;
using std::stringstream;
//Вспомогательные функции протоколов*************************************************************************************


//На случай, если нужно будет генерировать числа
/*std::random_device rd;
std::mt19937 eng(rd());
std::uniform_int_distribution<> lim1(3, 6);
std::uniform_int_distribution<> lim2(7, 20);
std::uniform_int_distribution<> lim3(1000, 100000);*/

//Принимает строку, возвращает в out масcив чаров из её элементов, если ishex = 0 и массив чаров 
//из 16ричных значений её элемнтов, взятых по 2, если ishex = 1
void Crypto::cvtstr(string str, char * out, bool ishex)
{
	if (ishex)
	{
		for (int i = 0; i < str.length() - 1; i += 2)
		{
			out[i / 2] = std::stoi(str.substr(i, 2), nullptr, 16);
		}
		out[str.length()/2] = '\0';
	}
	else
	{
		for (int i = 0; i < str.length(); i ++)
		{
			out[i] = str[i];
		}

		out[str.length()] = '\0';
	}

}
//Перегрузка предыдущей ф-ции, возвращающая string, только для 16ричных входных строчек
string Crypto::cvtstr(string str)
{
	string out;
	out.assign("0", str.length()/2);

	for (int i = 0; i < str.length() - 1; i += 2)
	{
		out[i / 2] = std::stoi(str.substr(i, 2), nullptr, 16);
	}
	return out;
}
//Ещё одна перегрузка, переводит число в строковое представление его значения
string Crypto::cvtstr(unsigned num)
{
	string out(sizeof(num), ' ');
	char buf;
	for (int i = 0; i < sizeof(num); i++)
	{
		buf = num % 0x100;
		num >>= 8;
		out[sizeof(num) - i - 1] = buf;
	}
	return out;
}
//Принимает строчку, возвращает строчку, содержащую hex-представление символов исходной строчки
string Crypto::cvthex(string str)
{
	string out;
	stringstream ss;
	char* out_tmp;
	out_tmp = (char *)malloc(3);

	for (int i = 0; i <str.length(); i++)
	{
		sprintf((char *)out_tmp, "%02hx", (unsigned char)str[i]);
		ss << (unsigned char *)out_tmp;
	}
	out.clear();
	ss >> out;

	return out;
}


//Принимает строку и переупорядочивает её элементы в обратном направлении. По одному символу,если ishex = 0 и по два, если ishex = 1
string Crypto::reorder(string original, bool ishex)
{
	string temp;
	temp.assign(original);
	if (ishex)
	{
		for (size_t i = 0uL, e = original.length(); i < e / 2; i += 2)
		{
			temp.replace(i, 2, original, e - i - 2, 2);
			temp.replace(e - i - 2, 2, original, i, 2);

		}
	}
	else
	{
		for (size_t i = 0uL, e = original.length(); i < e / 2; i += 1)
		{
			temp.replace(i, 1, original, e - i - 1, 1);
			temp.replace(e - i - 1, 1, original, i, 1);

		}

	}
	return temp;
}
//Реализация VKO*************************************************************************************
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
	K = reorder(reorder(res.getX().toString(), true) + reorder(res.getY().toString(), true), true);

	switch (algorithm)
	{
		case 1: hash(K, K.length(), KEK, true); break;
		case 2: hash256(K, K.length(), KEK, true); break; 
		case 3: hash512(K, K.length(), KEK, true); break;
	}

}

//Реализация SoftSPAKE*************************************************************************************

SoftSPAKE::SoftSPAKE(string pass, vector<ECSet> vect_ecset, unsigned ID, vector<unsigned> counters)
{
	IDa = ID;
	PW = pass;
	v_ecset = vect_ecset;
	ctr = counters;
}

void SoftSPAKE::startCTR()
{	
	if ((ctr.at(0) == 0) || (ctr.at(1) == 0) || (ctr.at(2) == 0))
		throw "bad_counter";
	ctr.at(0)--;
	ctr.at(1)--;
	ctr.at(2)--;
}

void SoftSPAKE::ComputeQapw()
{
	string keymat;
	BigInteger mult;
	Compute_PBKDF2( PW, salt.toString(), keymat);
	keymat = cvthex(keymat);
	mult = BigInteger(keymat, 16);
	Qapw = v_ecset.at(IDalg).curve.multiplyPoint(mult, v_ecset.at(IDalg).points.at(ind));
}

void SoftSPAKE::Computeu1()
{
	α = randomBigInteger(v_ecset.at(IDalg).curve.q());
	za = false;
	BigInteger mult(-1);
	ECPoint negQapw = v_ecset.at(IDalg).curve.multiplyPoint(mult,Qapw);
	ECPoint αP = v_ecset.at(IDalg).curve.multiplyPoint(α, v_ecset.at(IDalg).curve.getBasepoint());
	u1 = v_ecset.at(IDalg).curve.addPoint(αP, negQapw);
}

void SoftSPAKE::Checku2()
{
	if (!v_ecset.at(IDalg).curve.pointExists(u2))
		throw "invalid_point";
	
}

void SoftSPAKE::ComputeQa()
{
	BigInteger mult(-1);
	ECPoint negQapw = v_ecset.at(IDalg).curve.multiplyPoint(mult, Qapw);
	Qa = v_ecset.at(IDalg).curve.addPoint(u2,negQapw);
}

void SoftSPAKE::CheckQa()
{
	BigInteger h = v_ecset.at(IDalg).curve.n() / v_ecset.at(IDalg).curve.q();
	if (v_ecset.at(IDalg).curve.multiplyPoint(h, Qa).isPointAtInfinity())
	{
		za = true;
		Qa = v_ecset.at(IDalg).curve.getBasepoint();
	}
}

void SoftSPAKE::ComputeKa()
{
	KEK(algo341112, v_ecset.at(IDalg).curve, α, Qa, 1, Ka);
}

void SoftSPAKE::ComputeMACa()
{
	string key;
	stringstream ss;
	ss << "01" << IDa << ind << salt.toString() << u1.getX().toString() << u1.getY().toString() << u2.getX().toString() << u2.getY().toString();
	ss >> key;
	key = cvtstr(key);
	Compute_HMAC(algo341112, Ka, key, key.length(), MACa);
}

void SoftSPAKE::CheckMACb()
{
	string key;
	stringstream ss;
	ss << "02" << IDb << ind << salt.toString() << u1.getX().toString() << u1.getY().toString() << u2.getX().toString() << u2.getY().toString();
	ss >> key;
	key = cvtstr(key);
	string local_MACb;
	Compute_HMAC(algo341112, Ka, key, key.length(), local_MACb);

	if (MACb.compare(local_MACb))
		throw "invalid_MAC";

}

void SoftSPAKE::Checkza()
{
	if (za)
		throw "error_in_u_value";
	ctr.at(0) = 5;
	ctr.at(1)++;
}


//Реализация HardSPAKE*************************************************************************************

HardSPAKE::HardSPAKE(ECSet selected_set, unsigned ident, string pass, unsigned ID, vector<unsigned> counters)
{	
	IDb = ID;
	ecset = selected_set;
	IDalg = selected_set.IDalg;
	ind = ident;
	ctr = counters;

	BigInteger lim = 2;
	lim = lim.pow(128);
	salt = randomBigInteger(lim);

	string keymat;
	BigInteger mult;
	Compute_PBKDF2( pass, salt.toString(), keymat);
	keymat = cvthex(keymat);
	mult = BigInteger(keymat, 16);
	Qpw = ecset.curve.multiplyPoint(mult, ecset.points.at(ind));

}

void HardSPAKE::startCTR()
{	
	if ((ctr.at(0) == 0) || (ctr.at(1) == 0) || (ctr.at(2) == 0))
		throw "bad_counter";
	ctr.at(0)--;
	ctr.at(1)--;
	ctr.at(2)--;
}


void HardSPAKE::Checku1()
{
	if (!ecset.curve.pointExists(u1))
		throw "invalid_point";
}

void HardSPAKE::ComputeQb()
{
	Qb = ecset.curve.addPoint(u1, Qpw);

	β = randomBigInteger(ecset.curve.q());
	zb = false;
}

void HardSPAKE::CheckQb()
{	
	BigInteger h = ecset.curve.n() / ecset.curve.q();
	if (ecset.curve.multiplyPoint(h, Qb).isPointAtInfinity())
	{
		zb = true;
		Qb = ecset.curve.getBasepoint();
	}
} 

void HardSPAKE::ComputeKb()
{
	KEK(algo341112, ecset.curve, β, Qb, 1, Kb);
}

void HardSPAKE::Computeu2()
{
	ECPoint βP = ecset.curve.multiplyPoint(β, ecset.curve.getBasepoint());
	u2 = ecset.curve.addPoint(βP,Qpw);
}

void HardSPAKE::CheckMACa()
{
	string key;
	stringstream ss;
	ss << "01" << IDa << ind << salt.toString() << u1.getX().toString() << u1.getY().toString() << u2.getX().toString() << u2.getY().toString();
	ss >> key;
	key = cvtstr(key);
	string local_MACa;
	Compute_HMAC(algo341112, Kb, key, key.length(), local_MACa);

	if (MACa.compare(local_MACa))
		throw "invalid_MAC";
	
}

void HardSPAKE::ComputeMACb()
{
	string key;
	stringstream ss;
	ss << "02" << IDb << ind << salt.toString() << u1.getX().toString() << u1.getY().toString() << u2.getX().toString() << u2.getY().toString();
	ss >> key;
	key = cvtstr(key);
	Compute_HMAC(algo341112, Kb, key, key.length(), MACb);
}

void HardSPAKE::Checkzb()
{
	if (zb)
		throw "error_in_u_value";
	ctr.at(0) = 5;
	ctr.at(1)++;
}