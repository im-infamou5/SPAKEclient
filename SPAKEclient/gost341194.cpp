#include <sstream>
#include <iostream>
#include "crypto.h"
#include "gost341194_data.h"

using Crypto::GOST341194;
using std::string;
using std::stringstream;

typedef unsigned char B[32];
typedef unsigned char B32[4];
//функция чтения из файла
/*
bool GOST341194::read_file(char *fileName)
{
	ifstream in(fileName, ios::binary);

	if (in.fail())
		return false;

	in.seekg(0, ios::end);
	length = (unsigned int)in.tellg();
	in.seekg(0, ios::beg);

	buffer = new byte[length];

	in.read((char*)buffer, length);
	in.close();

	return true;
}
//Вывод хэша на экран
bool GOST341194::Show_hash()
{

	for (int i = 0; i < 32; i++)
		cout << hex << (unsigned int)res[i];

	cout << endl;
	return true;
}
*/

//Вычисление phi для преобразования P
int GOST341194::fi(int argument)
{
	int i = argument & 0x03;

	int k = argument >> 2;

	k++;

	return (i << 3) + k - 1;
}
//Функция f в ГОСТ 28147-89
void GOST341194::E_f(unsigned char A[], unsigned char K[], unsigned char R[])
{
	int c = 0;                                          //Складываем по модулю 2^32. c - перенос  в следующий разряд

	for (int i = 0; i < 4; i++)
	{
		c += A[i] + K[i];
		R[i] = c & 0xFF;
		c >>= 8;
	}

	//Заменяем 4х-битные кусочки согласно S-блокам
	for (int i = 0; i < 8; i++)
	{
		int x = R[i >> 1] & ((i & 1) ? 0xF0 : 0x0F);    //x - 4х-битный кусочек

		R[i >> 1] ^= x;                                 //Обнуляем соответствующие биты
		x >>= (i & 1) ? 4 : 0;                          //сдвигаем x либо на 0, либо на 4 бита влево
		x = S[i][x];                                    //Заменяем согласно S-блоку 
		R[i >> 1] |= x << ((i & 1) ? 4 : 0);
	}

	int tmp = R[3];                                     //Сдвигаем на 8 бит (1 байт) влево

	R[3] = R[2];
	R[2] = R[1];
	R[1] = R[0];
	R[0] = tmp;

	tmp = R[0] >> 5;                                    //Сдвигаем еще на 3 бита влево

	for (int i = 1; i < 4; i++)
	{
		int nTmp = R[i] >> 5;

		R[i] = (R[i] << 3) | tmp;
		tmp = nTmp;
	}

	R[0] = (R[0] << 3) | tmp;
}

//ГОСТ 28147-89
void GOST341194::E(unsigned char D[], unsigned char K[], unsigned char R[])
{
	B32 A, B;

	for (int i = 0; i < 4; i++)
		A[i] = D[i];

	for (int i = 0; i < 4; i++)
		B[i] = D[i + 4];

	for (int step = 0; step < 3; step++)                //K1..K24 идут в прямом порядке - три цикла K1..K8
	{
		for (int i = 0; i < 32; i += 4)
		{
			B32 tmp;

			E_f(A, K + i, tmp);                         //(K + i) - массив K с i-го элемента

			for (int i = 0; i < 4; i++)
				tmp[i] ^= B[i];

			memcpy(B, A, sizeof A);

			memcpy(A, tmp, sizeof tmp);
		}
	}

	//А K25..K32 идут в обратном порядке
	for (int i = 28; i >= 0; i -= 4)
	{
		B32 tmp;

		E_f(A, K + i, tmp);

		for (int i = 0; i < 4; i++)
			tmp[i] ^= B[i];

		memcpy(B, A, sizeof A);

		memcpy(A, tmp, sizeof tmp);
	}

	for (int i = 0; i < 4; i++)
		R[i] = B[i];

	for (int i = 0; i < 4; i++)
		R[i + 4] = A[i];
}
//Преобразование A(Y)
void GOST341194::A_Y(unsigned char Y[], unsigned char R[])
{
	for (int i = 0; i < 24; i++)
		R[i] = Y[i + 8];

	for (int i = 0; i < 8; i++)
		R[i + 24] = Y[i] ^ Y[i + 8];
}
//Преобразование P(Y)
void GOST341194::P_Y(unsigned char Y[], unsigned char R[])
{
	for (int i = 0; i < 32; i++)
		R[i] = Y[fi(i)];
}
//Вычисление PSI(Y)
void GOST341194::psi_Y(unsigned char arr[])
{
	unsigned char y16[] = { 0, 0 };

	y16[0] ^= arr[0]; y16[1] ^= arr[1];
	y16[0] ^= arr[2]; y16[1] ^= arr[3];
	y16[0] ^= arr[4]; y16[1] ^= arr[5];
	y16[0] ^= arr[6]; y16[1] ^= arr[7];
	y16[0] ^= arr[24]; y16[1] ^= arr[25];
	y16[0] ^= arr[30]; y16[1] ^= arr[31];

	for (int i = 0; i < 30; i++)
		arr[i] = arr[i + 2];

	arr[30] = y16[0]; arr[31] = y16[1];
}

//Вычисление PSI пока не закончатся раунды(своего рода регистр сдивига с линейной обратной связью)

void GOST341194::psi_round(unsigned char arr[], int p)
{
	while (p--)
		psi_Y(arr);
}

void GOST341194::f(unsigned char H[], unsigned char M[], unsigned char newH[])
{
	B C[4];

	memset(C, 0, sizeof C);

	C[2][0] = 0x00;
	C[2][1] = 0xFF;
	C[2][2] = 0x00;
	C[2][3] = 0xFF;
	C[2][4] = 0x00;
	C[2][5] = 0xFF;
	C[2][6] = 0x00;
	C[2][7] = 0xFF;
	C[2][8] = 0xFF;
	C[2][9] = 0x00;
	C[2][10] = 0xFF;
	C[2][11] = 0x00;
	C[2][12] = 0xFF;
	C[2][13] = 0x00;
	C[2][14] = 0xFF;
	C[2][15] = 0x00;
	C[2][16] = 0x00;
	C[2][17] = 0xFF;
	C[2][18] = 0xFF;
	C[2][19] = 0x00;
	C[2][20] = 0xFF;
	C[2][21] = 0x00;
	C[2][22] = 0x00;
	C[2][23] = 0xFF;
	C[2][24] = 0xFF;
	C[2][25] = 0x00;
	C[2][26] = 0x00;
	C[2][27] = 0x00;
	C[2][28] = 0xFF;
	C[2][29] = 0xFF;
	C[2][30] = 0x00;
	C[2][31] = 0xFF;

	B U, V, W, K[4], tmp;

	memcpy(U, H, sizeof U);

	memcpy(V, M, sizeof V);

	for (int i = 0; i < 32; i++)
		W[i] = U[i] ^ V[i];

	P_Y(W, K[0]);

	for (int step = 1; step < 4; step++)
	{
		A_Y(U, tmp);

		for (int i = 0; i < 32; i++)
			U[i] = tmp[i] ^ C[step][i];

		A_Y(V, tmp);

		A_Y(tmp, V);

		for (int i = 0; i < 32; i++)
			W[i] = U[i] ^ V[i];

		P_Y(W, K[step]);
	}

	B S;

	for (int i = 0; i < 32; i += 8)
		E(H + i, K[i >> 3], S + i);

	psi_round(S, 12);

	for (int i = 0; i < 32; i++)
		S[i] ^= M[i];

	psi_round(S, 1);

	for (int i = 0; i < 32; i++)
		S[i] ^= H[i];

	psi_round(S, 61);

	memcpy(newH, S, sizeof S);
}

void GOST341194::hash(string message, unsigned long long length, string &out)
{
	B block, Sum, L, H, newH;
	
	stringstream ss;
	unsigned char* to;
	unsigned char* tmp;
	uint8_t a = 0;

	to = (unsigned char *)malloc(length + 1);
	tmp = (unsigned char *)malloc(length + 1);

	unsigned int pos = 0, posIB = 0;

	memset(Sum, 0, sizeof Sum);

	memset(H, 0, sizeof H);

	while ((posIB < length) || pos)
	{
		if (posIB < length)
			block[pos++] = message[posIB++];
		else
			block[pos++] = 0;

		if (pos == 32)
		{
			pos = 0;

			int c = 0;

			for (int i = 0; i < 32; i++)
			{
				c += block[i] + Sum[i];
				Sum[i] = c & 0xFF;
				c >>= 8;
			}

			f(H, block, newH);

			memcpy(H, newH, sizeof newH);
		}
	}

	memset(L, 0, sizeof L);

	int c = length << 3;

	for (int i = 0; i < 32; i++)
	{
		L[i] = c & 0xFF;
		c >>= 8;
	}

	f(H, L, newH);

	memcpy(H, newH, sizeof newH);

	f(H, Sum, newH);
	int f = sizeof newH;
	memcpy(to, newH, sizeof newH);
	for (int i = 0; i < 32; i++)
	{
		sprintf((char *)tmp, "%02X", to[i]);
		ss << (unsigned char *)tmp;
	}
	
	free(to);
	free(tmp);
	ss >> out;
}
