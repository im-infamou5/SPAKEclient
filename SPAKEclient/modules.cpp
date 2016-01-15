#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <winscard.h>
#include <sstream>
#include "ecc.h"
#include "crypto.h"

using namespace Crypto;


void Crypto::VKO_local()
{	
	std::cout << "Тестовая реализация алгоритма согласования ключей VKO.\n";
	std::cout << "Выберите версию алгоритма:\n";
	std::cout << "1-VKO_GOSTR3410_2001_256 (Функция хэширования ГОСТ Р 34.11-94)\n";
	std::cout << "2-VKO_GOSTR3410_2012_256 (Функция хэширования ГОСТ Р 34.11-12 Streebog)\n";
	std::cout << "3-VKO_GOSTR3410_2012_512 (Функция хэширования ГОСТ Р 34.11-12 Streebog)\n";
	short choice;
	Algorithms algorithm;
	while (1)//Выбор алгоритма
	{
		std::cin >> choice;

		if ((std::cin.fail()) || (std::cin.get() != '\n'))
		{
			std::cout << "Некорректное значение!\n";
			std::cin.clear();
			while (std::cin.get() != '\n')
				continue;
		}
		else
		{
			if ((choice == 1) || (choice == 2) || (choice == 3))
			{
				break;
			}
			else
			{
				std::cout << "Некорректное значение!\n";
			}
		}
	}

	switch (choice)
	{
	case 1: algorithm = algo341194; break;
	case 2: algorithm = algo341112; break;
	case 3: algorithm = algo341112_512; break;
	}

	std::cout << "Используемая кривая: id-tc26-gost-3410-12-512-paramSetA. \n";


	ECParams test_curve_params;
	test_curve_params.a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4";


	test_curve_params.b = "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B8257"
		"4761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A7"
		"1C760";

	test_curve_params.p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7";


	test_curve_params.n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275";

	test_curve_params.q = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275";


	test_curve_params.bpx = "3";

	test_curve_params.bpy = "7503CFE87A836AE3A61B8816E25450E6CE5E1C9"
		"3ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB521"
		"5F2A4";


	ECCurve test_curve(test_curve_params);

	//UKM
	BigInteger ukm_num = BigInteger(reorder("1d80603c8544c727"), 16);
	std::cout << "UKM:\n" + reorder(ukm_num.toString()) + "\n";

	//Закрытый ключ стороны А
	BigInteger a_key = BigInteger(reorder("c990ecd972fce84ec4db022778f50fcac726f4670"
		"8384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"), 16);
	std::cout << "Закрытый ключ стороны А:\n" + reorder(a_key.toString()) + "\n";


	//Закрытый ключ стороны В
	BigInteger b_key = BigInteger(reorder("48c859f7b6f11585887cc05ec6ef1390cfea739b1"
		"a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"), 16);

	std::cout << "Закрытый ключ стороны B:\n" + reorder(b_key.toString()) + "\n";

	VKO A_side(test_curve, test_curve.getBasepoint(), a_key, ukm_num);
	VKO B_side(test_curve, test_curve.getBasepoint(), b_key, ukm_num);

	//Вычисление открытых ключей
	A_side.computePx();
	B_side.computePx();


	std::cout << "Открытый ключ стороны A:\n" + reorder(A_side.getPx().getX().toString()) + reorder(A_side.getPx().getY().toString()) + "\n";
	std::cout << "Открытый ключ стороны B:\n" + reorder(B_side.getPx().getX().toString()) + reorder(B_side.getPx().getY().toString()) + "\n";

	//Обмен открытыми ключами
	A_side.setPy(B_side.getPx());
	B_side.setPy(A_side.getPx());

	//Вычисление общего ключа сторонами
	A_side.KEK(algorithm, A_side.getCurve(), A_side.getX(), A_side.getPy(), A_side.getUKM(), A_side.K);
	B_side.KEK(algorithm, B_side.getCurve(), B_side.getX(), B_side.getPy(), B_side.getUKM(), B_side.K);


	std::cout << "Результирующий ключ стороны A:\n" + reorder(A_side.K) + "\n";
	std::cout << "Результирующий ключ стороны B:\n" + reorder(B_side.K) + "\n";
}