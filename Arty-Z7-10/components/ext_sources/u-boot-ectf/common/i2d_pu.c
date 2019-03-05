#include "openssl/cryptlib.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/objects.h"
#ifndef OPENSSL_NO_RSA
#include "openssl/rsa.h"
#endif


int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp)
	{
	switch (a->type)
		{
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		return(i2d_RSAPublicKey(a->pkey.rsa,pp));
#endif

	default:
		ASN1err(ASN1_F_I2D_PUBLICKEY,ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
		return(-1);
		}
	}

