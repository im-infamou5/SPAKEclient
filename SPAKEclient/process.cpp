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
	/*VKO_local();
	system("PAUSE");*/
	/*//примеры вызова hmac и hash
	string out, pass = "This is message, length=32 bytes", key = "s=, ehesttgiyga bnss esi2leh3 mT";
	string foo = "Suppose the original message has length = 50 bytes";
	string foo1 = "ыверогИ ыкълп яырбарх ан ималертс яром с ътюев ,ицунв ижобиртС ,иртев еС";
	string foo2 = "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1";
	//HMAC hmac;
	//hmac.Compute_HMAC(algo341194, pass, key, key.length(), out);
	//std::cout << out << std::endl;
	VKO vko;
	vko.hash256(cvtstr(foo2), foo2.length()/2, foo1);
	//vko.hash(pass, pass.length(), pass); 
	std::cout << foo1 << std::endl;
	system("PAUSE");*/
	//HMAC
	string key = reorder("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", true);
	string text = reorder("0126bdb87800af214341456563780100", true);
	string out;
	HMAC hmac;
	hmac.Compute_HMAC(algo341112, text, key, key.length(), out, true);
	std::cout << out << std::endl;
	system("PAUSE");
	/*string out, pass = "This is message, length=32 bytes", key = "s=, ehesttgiyga bnss esi2leh3 mT";
	HMAC hmac;
	hmac.Compute(algo341194, key, pass, key.length(), out);
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