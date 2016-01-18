#include <random>
#include <string>
#include "crypto.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace Crypto;
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
	K = reorder(reorder(res.getX().toString(), true) + reorder(res.getY().toString(), true), true);

	switch (algorithm)
	{
		case 1: hash(K, K.length(), KEK, true); break;
		case 2: hash256(K, K.length(), KEK, true); break; 
		case 3: hash512(K, K.length(), KEK, true); break;
	}

}

