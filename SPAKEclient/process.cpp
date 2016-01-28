#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>



#include "crypto.h"



using namespace Crypto;



int main()
{
	SetConsoleCP(1251);// установка кодовой страницы win-cp 1251 в поток ввода
	SetConsoleOutputCP(1251); // установка кодовой страницы win-cp 1251 в поток вывода

	while (1)
	{	
		std::cout << std::endl;
		std::cout << "1 - Тестирование\n";
		std::cout << "2 - ХПИ\n";
		std::cout << "0 - Выход\n";
		std::cout << ">>";
		short choice;
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
				if ((choice == 0) || (choice == 1) || (choice == 2))
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
		case 1: 
			while (Testing_Monitor())
				continue;
		break;

		case 2:  
			while (SPAKE_HPI())
				continue;
		break;
		
		case 0:
			return 0;
		break;
		}

		continue;
	}
	
	return 0;
}