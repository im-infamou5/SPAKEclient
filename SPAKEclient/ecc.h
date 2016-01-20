#ifndef _ECC_H
#define _ECC_H

#include "BigInteger.h"

#define MEMZERO(target)	memset((void *)(target), 0, (size_t)(_countof(target)))

using std::string;

typedef struct {
	const char *p;
	const char *a;
	const char *b;
	const char *n;
	const char *q;
	const char *bpx;
	const char *bpy;
}ECParams;


class ECPoint {

private:
	BigInteger x;
	BigInteger y;

public:
	ECPoint();
	ECPoint(const ECPoint &p);
	ECPoint(const BigInteger &x, const BigInteger &y);

	BigInteger getX();
	BigInteger getY();

	bool isPointAtInfinity();
	bool operator==(ECPoint &p);
};

class ECPointJacobian {

private:
	BigInteger x;
	BigInteger y;
	BigInteger z;

public:
	ECPointJacobian();
	ECPointJacobian(const ECPointJacobian &p);
	ECPointJacobian(const BigInteger &x, const BigInteger &y);
	ECPointJacobian(const BigInteger &x, const BigInteger &y, const BigInteger &z);

	BigInteger getX();
	BigInteger getY();
	BigInteger getZ();
	bool isPointAtInfinity();

	
};

class ECCurve {

private:
	BigInteger _a;
	BigInteger _b;
	BigInteger _n;
	BigInteger _q;
	BigInteger _p;
	BigInteger _bpx;
	BigInteger _bpy;

public:
	ECCurve();
	ECCurve(ECParams &params);
	ECCurve(BigInteger p, BigInteger n, BigInteger q, BigInteger a, BigInteger b, BigInteger bpx, BigInteger bpy);
	ECPoint getBasepoint();


	ECPoint addPoint(ECPoint &p, ECPoint &q);
	ECPoint doublePoint(ECPoint &p);
	ECPoint multiplyPoint(BigInteger &k, ECPoint &p);
	ECPointJacobian toJacobian(ECPoint &p);
	ECPoint toAffine(ECPointJacobian &p);
	ECPointJacobian addJacobian(ECPointJacobian &p, ECPointJacobian &q);
	ECPointJacobian doubleJacobian(ECPointJacobian &p);

	BigInteger a() { return _a; };
	BigInteger b() { return _b; };
	BigInteger p() { return _p; };
	BigInteger n() { return _n; };
	BigInteger q() { return _q; };
	BigInteger bpx() { return _bpx; };
	BigInteger bpy() { return _bpy; };

	BigInteger compressPoint(ECPoint &p);

	bool pointExists(ECPoint &p);
};

void generateRPoints(ECCurve curve, ECPoint q, BigInteger *aAra, BigInteger *bAra, BigInteger *xAra, BigInteger *yAra, int n);
#endif
