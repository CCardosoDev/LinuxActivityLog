#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "pteidlib.h"
#include "cryptoki.h"

#include "CCkpubFile.h"

#include "../loggerClientFuncs/cryptography.h"
#include "../loggerClientFuncs/base64.h"

/*
* This function extracts the RSA authentication public key from the
* Citizens' Card
*/

static void
pteiderror ( char * msg, long code )
{
    fprintf ( stderr, "Error in %s: %s (%ld)\n",
    		msg, /*PTEID_errorString ( code ),*/ code );
}

/*
* This function extracts the RSA authentication public key from the
* Citizens' Card
*/

static RSA *
loadCCPubKey ()
{
    long ret;
    int i;
    unsigned char * asn1cert;
    X509 * cert;
    RSA * rsaKey;
    PTEID_Certifs certs;

    ret = PTEID_Init ( 0 );
    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_Init", ret );
	return 0;
    }

    /*
    * Activate CC integrity check
    */

    ret = PTEID_SetSODCAs ( 0 );
    ret = PTEID_SetSODChecking ( 1 );

    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_SetSODChecking", ret );
	return 0;
    }

    /*
    * Extract all CC certificates
    */

    ret = PTEID_GetCertificates ( &certs );
    if (ret != PTEID_OK) {
        pteiderror ( "PTEID_GetCertificates", ret );
	return 0;
    }

    /*
    * Find certificate with label "CITIZEN AUTHENTICATION CERTIFICATE"
    */

    for (i = 0; i < certs.certificatesLength; i++) {
	if (strcmp ( certs.certificates[i].certifLabel,
			"CITIZEN AUTHENTICATION CERTIFICATE" ) != 0) continue;
	cert = 0;
	asn1cert = certs.certificates[i].certif;
	cert = d2i_X509 ( &cert, (const unsigned char **) &asn1cert,
			    certs.certificates[i].certifLength );
        if (cert == 0) {
	    fprintf ( stderr, "Certificate conversion error with d2i_X509\n" );
	    return 0;
	}
	
	/*
	* Extract subject's RSA key from certificate
	*/

	rsaKey = EVP_PKEY_get1_RSA ( X509_PUBKEY_get ( cert->cert_info->key ) );
	if (rsaKey == 0) {
	    fprintf ( stderr,
	    		"RSA key extraction error with EVP_PKEY_get1_RSA\n" );
	    return 0;
	}

	return rsaKey;
    }

    return NULL;
}


char * certString = "-----BEGIN CERTIFICATE-----\n"
"MIIHFjCCBf6gAwIBAgIIQZhP2zb18CIwDQYJKoZIhvcNAQEFBQAwfDELMAkGA1UEBhMCUFQxHDAa\n"
"BgNVBAoME0NhcnTDo28gZGUgQ2lkYWTDo28xFDASBgNVBAsMC3N1YkVDRXN0YWRvMTkwNwYDVQQD\n"
"DDBFQyBkZSBBdXRlbnRpY2HDp8OjbyBkbyBDYXJ0w6NvIGRlIENpZGFkw6NvIDAwMDUwHhcNMTEx\n"
"MjI5MTExNDM2WhcNMTYxMjI5MDAwMDAwWjCB1DELMAkGA1UEBhMCUFQxHDAaBgNVBAoME0NhcnTD\n"
"o28gZGUgQ2lkYWTDo28xHDAaBgNVBAsME0NpZGFkw6NvIFBvcnR1Z3XDqnMxIzAhBgNVBAsMGkF1\n"
"dGVudGljYcOnw6NvIGRvIENpZGFkw6NvMRUwEwYDVQQEDAxTw4EgREEgU0lMVkExFDASBgNVBCoM\n"
"C0pPw4NPIFBBVUxPMRQwEgYDVQQFEwtCSTEzNzYwOTA5NDEhMB8GA1UEAwwYSk/Dg08gUEFVTE8g\n"
"U8OBIERBIFNJTFZBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrWoBZiayJ2oRv7B07f/uV\n"
"LbXxuvFUQAmgZO5k3kDPW7I0jzq+6+B/snzz3+jV4oWKdAg3cvnT4grA3f/vlzBLvXJy4bsx90Y3\n"
"clMbTImkLFJbmd1V8/zq2GVZLW3uQnuLlOFrPrmH0bUU6ABk3GTFbvEhLeX9LnCDMb7/IrWTiwID\n"
"AQABo4IDxTCCA8EwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCA4gwHQYDVR0OBBYEFOx8q+U9\n"
"G5+G8ofqD7rVEqOIqtWrMB8GA1UdIwQYMBaAFMu8aIu4gPEWNGRz5Yx1ebtckwlRMIIB9QYDVR0g\n"
"BIIB7DCCAegwgfIGCGCEbAEBAQIUMIHlMCgGCCsGAQUFBwIBFhxodHRwOi8vd3d3LnNjZWUuZ292\n"
"LnB0L3BjZXJ0MIG4BggrBgEFBQcCAjCBqx6BqABPACAAYwBlAHIAdABpAGYAaQBjAGEAZABvACAA\n"
"ZQBtAGkAdABpAGQAbwAgAHMAZQBnAHUAbgBkAG8AIABlAHMAdABhACAAcABvAGwA7QB0AGkAYwBh\n"
"ACAA6QAgAHUAdABpAGwAaQB6AGEAZABvACAAcABhAHIAYQAgAGEAdQB0AGUAbgB0AGkAYwBhAOcA\n"
"4wBvACAAZABvACAAQwBpAGQAYQBkAOMAbzB4BgtghGwBAQECBAIABzBpMGcGCCsGAQUFBwIBFlto\n"
"dHRwOi8vcGtpLmNhcnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL3BvbGl0aWNhcy9kcGMvY2Nfc3Vi\n"
"LWVjX2NpZGFkYW9fYXV0ZW50aWNhY2FvX2RwYy5odG1sMHcGDGCEbAEBAQIEAgABATBnMGUGCCsG\n"
"AQUFBwIBFllodHRwOi8vcGtpLmNhcnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL3BvbGl0aWNhcy9w\n"
"Yy9jY19zdWItZWNfY2lkYWRhb19hdXRlbnRpY2FjYW9fcGMuaHRtbDBrBgNVHR8EZDBiMGCgXqBc\n"
"hlpodHRwOi8vcGtpLmNhcnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL2xyYy9jY19zdWItZWNfY2lk\n"
"YWRhb19hdXRlbnRpY2FjYW9fY3JsMDAwNV9wMDAwNC5jcmwwcQYDVR0uBGowaDBmoGSgYoZgaHR0\n"
"cDovL3BraS5jYXJ0YW9kZWNpZGFkYW8ucHQvcHVibGljby9scmMvY2Nfc3ViLWVjX2NpZGFkYW9f\n"
"YXV0ZW50aWNhY2FvX2NybDAwMDVfZGVsdGFfcDAwMDQuY3JsMEsGCCsGAQUFBwEBBD8wPTA7Bggr\n"
"BgEFBQcwAYYvaHR0cDovL29jc3AuYXVjLmNhcnRhb2RlY2lkYWRhby5wdC9wdWJsaWNvL29jc3Aw\n"
"EQYJYIZIAYb4QgEBBAQDAgCgMCgGA1UdCQQhMB8wHQYIKwYBBQUHCQExERgPMTk5MDA4MjMxMjAw\n"
"MDBaMA0GCSqGSIb3DQEBBQUAA4IBAQCtduT6W5h/y1cb1ghHirUMo6PGOpkHAv3AWy2axus/cEKT\n"
"8ML8B3NWlg5lbxsj7hGAGbX7PumyODJw/rLhp7bwt17kOOy0EX3RpozPSVQ9sH0XN0p2hcczjkva\n"
"cT4lBUJjKjzAqS/cMzidsDt0mkzvHQ+F0aGYTwi5ep/BC5usjUklnky4AYi3J+HOwt1TpvezFIeA\n"
"OeSueTAxzpHLLQHETz55LgvwyLA8fWZYblYZGv8KA6iQyTkFC4NQW3aj+mucNmJrHDUC3BPb4MXf\n"
"CifVJPCCUorlRqlSp+hr6lDijZ0/Ru6xJuu9XTgMZvA1AYuMjy3m1EcFDAL6AK6XQZTj\n"
"-----END CERTIFICATE-----";

int
main(void)
{
	int res;
	unsigned char *message = (unsigned char*)"ola tudo bem?kugbfffgfdgfddgfdgdgdjhkkjiuuyreqw";
	unsigned int messageSize = strlen((char *)message);
	unsigned char signature[128];
	int signatureLen;
	char *b64message;
	X509* cert;
	EVP_PKEY *EVPpubkey;
    RSA *pubKey;

	/*RSA *pubKey = loadCCPubKey ();

	if (pubKey == NULL)
		return 0;*/



	cert = getX509fromPEM((unsigned char *)certString, strlen(certString));
    if(cert == NULL)
    {
    	printf("Certificado nulo!\n");
    	return -1;
    }

   	EVPpubkey = X509_get_pubkey(cert);
    if(EVPpubkey == NULL) return 0;

    pubKey = EVP_PKEY_get1_RSA(EVPpubkey);
    if(pubKey == NULL) return 0;



    signatureLen = signCitizenCard(message, messageSize, signature);
    /*printf("\nAssinatura Lau\n%s\n", b64encode(signature, 128));*/

	res = verifySignaturePubKey(cert, message, messageSize, signature, signatureLen);

	ERR_load_crypto_strings();
	ERR_print_errors_fp(stdout);
	printf("Res verify: %d\n", res);

	return 0;
}