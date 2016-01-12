#include "ecc.h"
#include "BigInteger.h"
#include <iomanip>
#include <sstream>

using std::hex;
using std::stringstream;
using std::string;


ECPointJacobian::ECPointJacobian()
{
}

ECPointJacobian::ECPointJacobian(const BigInteger &x, const BigInteger &y)
{
	this->x = x;
	this->y = y;
	this->z = BigInteger(1);
}

ECPointJacobian::ECPointJacobian(const BigInteger &x, const BigInteger &y, const BigInteger &z)
{
	this->x = x;
	this->y = y;
	this->z = z;
}

ECPointJacobian::ECPointJacobian(const ECPointJacobian &p)
{
	this->x = p.x;
	this->y = p.y;
	this->z = p.z;
}

BigInteger ECPointJacobian::getX()
{
	return this->x;
}

BigInteger ECPointJacobian::getY()
{
	return this->y;
}

BigInteger ECPointJacobian::getZ()
{
	return this->z;
}

bool ECPointJacobian::isPointAtInfinity()
{
	if (this->x.isZero() && this->y.isZero()) {
		return true;
	}
	else {
		return false;
	}
}

ECPoint::ECPoint()
{
}

ECPoint::ECPoint(const BigInteger &x, const BigInteger &y)
{
	this->x = x;
	this->y = y;
}

ECPoint::ECPoint(const ECPoint &p)
{
	this->x = p.x;
	this->y = p.y;
}

bool ECPoint::isPointAtInfinity()
{
	return this->x.isZero() && this->y.isZero();
}

BigInteger ECPoint::getX()
{
	return this->x;
}

BigInteger ECPoint::getY()
{
	return this->y;
}

bool ECPoint::operator==(ECPoint &p)
{
	if (this->x == p.x && this->y == p.y) {
		return true;
	}
	else {
		return false;
	}
}

/**
* Generates a set of R points for performing random walk
*/
void generateRPoints(ECCurve curve, ECPoint q, BigInteger *aAra, BigInteger *bAra, BigInteger *xAra, BigInteger *yAra, int n)
{
	ECPoint g = curve.getBasepoint();
	BigInteger order = curve.q();
	BigInteger modulus = curve.p();

	// Generate random Ri = aiG + biQ
	for (int i = 0; i < n; i++) {
		ECPoint r1;
		ECPoint r2;
		ECPoint r3;

		// Generate random multiplies
		BigInteger a = randomBigInteger(order);
		BigInteger b = randomBigInteger(order);

		// Multiply G and Q
		r1 = curve.multiplyPoint(a, g);
		r2 = curve.multiplyPoint(b, q);

		// Add the two points
		r3 = curve.addPoint(r1, r2);

		// Convert coordinates to montgomery form
		xAra[i] = r3.getX();
		yAra[i] = r3.getY();

		if (aAra != NULL) {
			aAra[i] = a;
		}

		if (bAra != NULL) {
			bAra[i] = b;
		}
	}
}