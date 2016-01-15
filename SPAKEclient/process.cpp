#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <winscard.h>
#include <sstream>
#include "ecc.h"
#include "crypto.h"
#include "gost341194_data.h"

#ifdef WIN32
#undef UNICODE
#endif


#ifdef WIN32
static char *pcsc_stringify_error(LONG rv)
{
	static char out[20];
	sprintf_s(out, sizeof(out), "0x%08X", rv);

	return out;
}
#endif

#define CHECK(f, rv) \
	if (SCARD_S_SUCCESS != rv) \
		{ \
	printf(f ": %s\n", pcsc_stringify_error(rv)); \
	return -1; \
		}

using namespace Crypto;


int main()
{
	SetConsoleCP(1251);// установка кодовой страницы win-cp 1251 в поток ввода
	SetConsoleOutputCP(1251); // установка кодовой страницы win-cp 1251 в поток вывода
	//VKO_local();
	//system("PAUSE");
	//примеры вызова hmac и hash
	string out, pass = "This is message, length=32 bytes", key = "s=, ehesttgiyga bnss esi2leh3 mT";
	string foo = "Suppose the original message has length = 50 bytes";
	string foo1 = "ыверогИ ыкълп яырбарх ан ималертс яром с ътюев ,ицунв ижобиртС ,иртев еС";
	//HMAC hmac;
	//hmac.Compute(algo341194, key, pass, key.length(), out);
	//std::cout << out << std::endl;
	VKO vko;
	vko.hash512(foo1, foo1.length(), out);
	//vko.hash(foo1, foo1.length(), out); 
	std::cout << out << std::endl;
	system("PAUSE");
	/*string str4 = "3f6a4173c881d02fc2fccc5654fde0f853b0b99477857ad017e79ed8f3fab8a297a7c4cc7a1b4515480b218c01ac534a9575e4a98ad0f3d7b10e92eaa1538e3b3eff1cc2004f9c4933b518da9b793008c5bbf7086da25930f7c37059dfdfb78459ed495d5eec5da274a293b989aa39f08e37470f2003fc3ef972e8611b26b55f";
	char* str5;
	unsigned long long length = str4.length() / 2;
	str5 = (char*)malloc(length);
	cvtstr(str4, str5);
	unsigned char* out;
	Stribog stribog;
	out = (unsigned char *)malloc(65);
	stribog.hash512(str5, length*8, out);
	string st((char*)out);
	std::cout <<st << std::endl;
	free(str5);
	free(out);
	system("PAUSE");*/
	
	/*string str = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
	string out;
	Stribog stribog;
	stribog.hash512(str, str.length(), out);
	std::cout << out << std::endl;
	system("PAUSE");*/

	//сюда код общения pcsc с jcardsim
	/*{
	LONG rv;

	SCARDCONTEXT hContext;
	LPTSTR mszReaders;
	SCARDHANDLE hCard;
	DWORD dwReaders, dwActiveProtocol, dwRecvLength;

	SCARD_IO_REQUEST pioSendPci;
	BYTE pbRecvBuffer[258];
	BYTE cmd1[] = { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0,
	0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06, 0x01 };
	BYTE cmd2[] = { 0x00, 0x00, 0x00, 0x00 };

	unsigned int i;

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	CHECK("SCardEstablishContext", rv)

	#ifdef SCARD_AUTOALLOCATE
	dwReaders = SCARD_AUTOALLOCATE;

	rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
	CHECK("SCardListReaders", rv)
	#else
	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	CHECK("SCardListReaders", rv)

	mszReaders = calloc(dwReaders, sizeof(char));
	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	CHECK("SCardListReaders", rv)
	#endif
	printf("reader name: %s\n", mszReaders);

	rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED,
	SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
	CHECK("SCardConnect", rv)

	switch(dwActiveProtocol)
	{
	case SCARD_PROTOCOL_T0:
	pioSendPci = *SCARD_PCI_T0;
	break;

	case SCARD_PROTOCOL_T1:
	pioSendPci = *SCARD_PCI_T1;
	break;
	}
	dwRecvLength = sizeof(pbRecvBuffer);
	rv = SCardTransmit(hCard, &pioSendPci, cmd1, sizeof(cmd1),
	NULL, pbRecvBuffer, &dwRecvLength);
	CHECK("SCardTransmit", rv)

	printf("response: ");
	for(i=0; i<dwRecvLength; i++)
	printf("%02X ", pbRecvBuffer[i]);
	printf("\n");

	dwRecvLength = sizeof(pbRecvBuffer);
	rv = SCardTransmit(hCard, &pioSendPci, cmd2, sizeof(cmd2),
	NULL, pbRecvBuffer, &dwRecvLength);
	CHECK("SCardTransmit", rv)

	printf("response: ");
	for(i=0; i<dwRecvLength; i++)
	printf("%02X ", pbRecvBuffer[i]);
	printf("\n");

	rv = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	CHECK("SCardDisconnect", rv)

	#ifdef SCARD_AUTOALLOCATE
	rv = SCardFreeMemory(hContext, mszReaders);
	CHECK("SCardFreeMemory", rv)

	#else
	free(mszReaders);
	#endif

	rv = SCardReleaseContext(hContext);

	CHECK("SCardReleaseContext", rv)

	return 0;
	}
	*/
	return 0;
}