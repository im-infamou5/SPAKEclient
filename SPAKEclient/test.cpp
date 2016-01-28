#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include "ecc.h"
#include "crypto.h"
#include "gost341194_data.h"
#include <memory.h>

using namespace Crypto;
using std::stringstream;
int test_main()
{
	//SPAKE_local();
	//system("PAUSE");
	//примеры вызова hmac и hash
	/*string out, pass = "This is message, length=32 bytes", key = "s=, ehesttgiyga bnss esi2leh3 mT";
	string foo = "Suppose the original message has length = 50 bytes";
	string foo1 = "ыверог» ыкълп €ырбарх ан ималертс €ром с ътюев ,ицунв ижобирт— ,иртев е—";
	string foo2 = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
	//string key = "733d2c20656865737474676979676120626e737320657369326c656833206d54";
	string text = "54686973206973206D6573736167652C206C656E6774683D3332206279746573";
	//string out;
	HMAC hmac;
	hmac.Compute_HMAC(algo341194, pass, key, key.length(), out);
	std::cout << cvthex(out) << std::endl;
	//VKO vko;
	//vko.hash512(foo1, foo1.length(), foo1);
	//vko.hash(pass, pass.length(), pass);
	//std::cout << foo1 << std::endl;
	system("PAUSE");*/
	//HMAC
	/*string key = reorder("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", true);
	string text = cvtstr(reorder("0126bdb87800af214341456563780100", true));
	string label = "26bdb878";
	string seed = "af21434145656378";
	stringstream ss;
	ss << "01" << label << "00" << seed << "01" << "00";
	string str = ss.str();
	string out;
	HMAC hmac;
	hmac.Compute_HMAC(algo341112, reorder(str,true), key, key.length(), out, true);
	std::cout << cvthex(out) << std::endl;
	system("PAUSE");*/
	//PBKDF2
	unsigned i = 1;
	//cvtstr(i);
	stringstream stream;
	string pass = "password";
	//string pass1 = reorder(cvtstr("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"));
	string salt = "salt";
	//string salt1 = cvtstr("0126bdb878001d80603c8544c7270100");
	salt = salt + cvtstr(i);
	string out;
	PBKDF2 pb;
	pb.Compute_HMAC(algo341112_512, salt, pass, pass.length(), out);
	//pb.Compute_PBKDF2(pass1, salt, out, 2000);

	std::cout << cvthex(out) << std::endl;

	system("PAUSE");

	return 0;
}