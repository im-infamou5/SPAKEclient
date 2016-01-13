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

	//примеры вызова hmac и hash
	/*string out, pass = "This is message, length=32 bytes", key = "s=, ehesttgiyga bnss esi2leh3 mT";
	string foo = "Suppose the original message has length = 50 bytes";
	HMAC hmac;
	hmac.Compute(algo341194, key, pass, key.length(), out);
	std::cout << out << std::endl;
	VKO vko;
	vko.hash(foo, foo.length(), out); 
	std::cout << out << std::endl;
	system("PAUSE");*/
	char str2[64] = "210987654321098765432109876543210987654321098765432109876543210";
	char str[257] = "3f6a4173c881d02fc2fccc5654fde0f853b0b99477857ad017e79ed8f3fab8a297a7c4cc7a1b4515480b218c01ac534a9575e4a98ad0f3d7b10e92eaa1538e3b3eff1cc2004f9c4933b518da9b793008c5bbf7086da25930f7c37059dfdfb78459ed495d5eec5da274a293b989aa39f08e37470f2003fc3ef972e8611b26b55f";
	char str1[257] = "5fb5261b61e872f93efc03200f47378ef039aa89b993a274a25dec5e5d49ed5984b7dfdf5970c3f73059a26d08f7bbc50830799bda18b533499c4f00c21cff3e3b8e53a1ea920eb1d7f3d08aa9e475954a53ac018c210b4815451b7accc4a797a2b8faf3d89ee717d07a857794b9b053f8e0fd5456ccfcc22fd081c873416a3f";
	char str3[257] = "?jAsÈÐ/ÂüÌVTýàøS°¹”w…zÐçžØóú¸¢—§ÄÌzEH!Œ¬SJ•uä©ŠÐó×±’ê¡SŽ;>ÿÂOœI3µÚ›y0Å»÷m¢Y0÷ÃpYßß·„YíI]^ì]¢t¢“¹‰ª9ðŽ7G ü>ùrèa&µ_";
	unsigned char* out;
	Stribog stribog;
	out = (unsigned char *)malloc(65);
	stribog.hash512(str3, 2048, out);
	string st((char*)out);
	std::cout << st << std::endl;
	free(out);
	system("PAUSE");
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