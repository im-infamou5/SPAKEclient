#include <random>
#include "crypto.h"

using Crypto::SoftSPAKE;
using Crypto::HardSPAKE;

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