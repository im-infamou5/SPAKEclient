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
	//Инициализируем параметры кривой


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

	std::cout << "Используемая кривая: id-tc26-gost-3410-12-512-paramSetA. \n";
	std::cout << "Порядок:\n" << test_curve.p().toString() << std::endl;


	//UKM
	BigInteger ukm_num = BigInteger(reorder("1d80603c8544c727", true), 16);
	std::cout << "UKM:\n" + reorder(ukm_num.toString(), true) + "\n";

	//Закрытый ключ стороны А
	BigInteger a_key = BigInteger(reorder("c990ecd972fce84ec4db022778f50fcac726f4670"
		"8384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667", true), 16);
	std::cout << "Закрытый ключ стороны А:\n" + reorder(a_key.toString(), true) + "\n";


	//Закрытый ключ стороны В
	BigInteger b_key = BigInteger(reorder("48c859f7b6f11585887cc05ec6ef1390cfea739b1"
		"a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db", true), 16);

	std::cout << "Закрытый ключ стороны B:\n" + reorder(b_key.toString(), true) + "\n";

	VKO A_side(test_curve, test_curve.getBasepoint(), a_key, ukm_num);
	VKO B_side(test_curve, test_curve.getBasepoint(), b_key, ukm_num);

	//Вычисление открытых ключей
	A_side.computePx();
	B_side.computePx();


	std::cout << "Открытый ключ стороны A:\n" + reorder(A_side.getPx().getX().toString(), true) + reorder(A_side.getPx().getY().toString(), true) + "\n";
	std::cout << "Открытый ключ стороны B:\n" + reorder(B_side.getPx().getX().toString(), true) + reorder(B_side.getPx().getY().toString(), true) + "\n";

	//Обмен открытыми ключами
	A_side.setPy(B_side.getPx());
	B_side.setPy(A_side.getPx());

	//Вычисление общего ключа сторонами
	A_side.KEK(algorithm, A_side.getCurve(), A_side.getX(), A_side.getPy(), A_side.getUKM(), A_side.K);
	B_side.KEK(algorithm, B_side.getCurve(), B_side.getX(), B_side.getPy(), B_side.getUKM(), B_side.K);


	std::cout << "Результирующий ключ стороны A:\n" + cvthex(reorder(A_side.K)) + "\n";
	std::cout << "Результирующий ключ стороны B:\n" + cvthex(reorder(B_side.K)) + "\n";
}

void Crypto::SPAKE_local()
{
	std::cout << "Тестовая реализация алгоритма согласования ключей SPAKE.\n";

	//Инициализируем параметры кривых
	//Кривая id-tc26-gost-3410-12-512-paramSetA

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

	ECCurve test_curve_1(test_curve_params);

	//Набор из трех точек на кривой
	vector<ECPoint> point_set_1 (3);
	ECPoint Q;
	BigInteger Qx;
	BigInteger Qy;

	Qx = BigInteger("301aac1a3b3e9c8a65bc095b541ce1d23728b93818e8b61f963e5d5b13eec0fe"
		"e6b06f8cd481a07bb647b649232e5179b019eef7296a3d9cfa2b66ee8bf0cbf2", 16);
	Qy = BigInteger("191177dd41ce19cc849c3938abf3adaab366e5eb2d22a972b2dcc69283523e89"
		"c9907f1d89ab9d96f473f96815da6e0a47297fcdd8b3adac37d4886f7ad055e0", 16);
	Q = ECPoint(Qx,Qy);
	point_set_1.at(0) = Q;

	Qx = BigInteger("7edc38f17f88e3105bafb67c419d58fe6a9094dd4dc1a83bcaccc61f020ac447"
		"92eba888457c658ee2d82557b7c6ab6efd61ba0c3327741d09a561a8b860a085", 16);
	Qy = BigInteger("3af1400a7a469058d9ba75e65ea5d3f4d0bdb357fa57eb73fa4900e2dca4da78"
		"b8e5ff35ca70e522610bb1fc76b102c81cc4729f94b12822584f6b6229a57ea1", 16);
	Q = ECPoint(Qx, Qy);
	point_set_1.at(1) = Q;

	Qx = BigInteger("387acfba7bbc5815407474a7c1132a1bded12497243d73ef8133d9810eb21716"
		"95dde2ff15597e159464a1db207b4d1ff98fbb989f80c2db13bc8ff5fea16d59", 16);
	Qy = BigInteger("4c816d1ca3e145ac448478fb79a77e1ad2dfc69576685e2f6867ec93fbad8aa4"
		"4111acd104036317095bce467e98f295436199c8ead57f243860d1bde8d88b68", 16);
	Q = ECPoint(Qx, Qy);
	point_set_1.at(2) = Q;

	ECSet test_set_1;

	test_set_1.IDalg = 0;
	test_set_1.curve_label = "id-tc26-gost-3410-12-512-paramSetA";
	test_set_1.curve = test_curve_1;
	test_set_1.points = point_set_1;

	vector<ECSet> v_test_set (1);
	v_test_set.at(0) = test_set_1;

	std::cout << "Используемая кривая: " << test_set_1.curve_label << std::endl;
	std::cout << "Порядок:\n" << test_set_1.curve.p().toString()<< std::endl;
	std::cout << "Используемая точка: \nx:" << test_set_1.points.at(0).getX().toString() << " y:" << test_set_1.points.at(0).getY().toString() << std::endl;

	//Инициализация параметров сторон протокола
	string PW;
	std::cout << "Задайте пароль, не менее 6 символов:" << std::endl<<">";
	while (1)//Получение пароля
	{
		std::cout << ">";
		std::cin >> PW;

		if ((std::cin.fail()) || (std::cin.get() != '\n'))
		{
			std::cout << "Некорректное значение!\n";
			std::cin.clear();
			while (std::cin.get() != '\n')
				continue;
		}
		else
		{
			if ((PW.length()>=6)&&(PW.length()<=64))
			{
				break;
			}
			else
			{
				std::cout << "Некорректное значение!\n";
			}
		}
	}


	SoftSPAKE client(PW, v_test_set);
	HardSPAKE token(test_set_1, 0, PW);

	std::cout << "Сформировано парольное доказательство на стороне токена" << std::endl;
	std::cout << "Соль:" << token.getsalt().toString()<< std::endl;
	std::cout << "Qpw:" << std::endl;
	std::cout << "x:" << token.getQpw().getX().toString() << " y:" << token.getQpw().getY().toString() << std::endl;

	//Уменьшаем счетчики

	try
	{
		client.startCTR();
		token.startCTR();
	}
	catch (...)
	{
		std::cout << "Ошибка счетчика";
	}

	//Обмениваемся открытой информацией
	token.setIDa(client.getIDa());
	client.setIDb(token.getIDb());
	client.setIDalg(token.getIDalg());
	client.setind(token.getind());
	client.setsalt(token.getsalt());

	//Производим предварительные вычисления на стороне клиента

	client.ComputeQapw();
	client.Computeu1();

	std::cout << "Эфемерный ключ клиента:" << std::endl;
	std::cout << client.getα().toString() << std::endl;
	std::cout << "Значение u1:" << std::endl;
	std::cout << "x:" << client.getu1().getX().toString() << " y:" << client.getu1().getY().toString() << std::endl;

	//Производим вычисления на стороне токена, получаем общий ключ

	token.setu1(client.getu1());
	try
	{
		token.Checku1();
	}
	catch (...)
	{
		std::cout << "Ошибка при передаче значения u1";
	}
	token.ComputeQb();
	token.CheckQb();
	token.ComputeKb();
	token.Computeu2();

	std::cout << "Эфемерный ключ токена:" << std::endl;
	std::cout << token.getβ().toString() << std::endl;
	std::cout << "Значение u2:" << std::endl;
	std::cout << "x:" << token.getu2().getX().toString() << " y:" << token.getu2().getY().toString() << std::endl;
	std::cout << "Полученный общий ключ на токене:" << std::endl;
	std::cout << cvthex(token.getKb()) << std::endl;

	//Проверяем значения и получаем общий ключ на стороне клиента

	client.setu2(token.getu2());
	try
	{
		client.Checku2();
	}
	catch (...)
	{
		std::cout << "Ошибка при передаче значения u2";
	}

	client.ComputeQa();
	client.CheckQa();
	client.ComputeKa();

	std::cout << "Полученный общий ключ на клиенте:" << std::endl;
	std::cout << cvthex(client.getKa()) << std::endl;

	//Выполяем подтверждение полученных общих ключей между сторонами
	//Вычисляем MAC для клиента и проверяем его на токене

	client.ComputeMACa();

	std::cout << "MACa для клиента:" << std::endl;
	std::cout << cvthex(client.getMACa()) << std::endl;

	token.setMACa(client.getMACa());
	try
	{
		token.CheckMACa();
	}
	catch (...)
	{
		std::cout << "Ошибка при проверке MAC";
	}


	//Проверка флага корректности значения u
		try
	{
		token.Checkzb();
	}
	catch (...)
	{
		std::cout << "Некорректное значение u";
	}

	std::cout << "MACa для клиента совпадает с вычисленным на токене." << std::endl;

	//Вычисляем MAC для токена и проверяем его на клиенте

	token.ComputeMACb();

	std::cout << "MACb для токена:" << std::endl;
	std::cout << cvthex(token.getMACb()) << std::endl;

	client.setMACb(token.getMACb());
	try
	{
		client.CheckMACb();
	}
	catch (...)
	{
		std::cout << "Ошибка при проверке MAC";
	}

	//Проверка флага корректности значения u
	try
	{
		client.Checkza();
	}
	catch (...)
	{
		std::cout << "Некорректное значение u";
	}
	std::cout << "MACb для токена совпадает с вычисленным на клиенте." << std::endl;
	std::cout <<  std::endl;
	std::cout << "Клиент и токен взаимно аутентифицированы и каждая сторона имеет общий выработанный ключ K." << std::endl;
}