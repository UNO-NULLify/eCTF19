#include "./include/bearssl_rsa.h"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *const argv[])
{
  // do the SIGN
  br_rsa_private_key *priv;
  unsigned char *hash_buffer;
  unsigned char *sign_out;
  char *path_to_hash;
  char *path_to_sig;
  size_t  hash_len;


  // grab the arguments
  path_to_hash = argv[1];
  hash_buffer = argv[2];
  priv->p = argv[3];
  priv->q = argv[4];
  priv->dp = argv[5];
  priv->dq = argv[6];
  priv->iq = argv[7];

  // initialize lens
  priv->n_bitlen = 2048;
  priv->plen = sizeof(argv[3]);
  priv->qlen = sizeof(argv[4]);
  priv->dplen = sizeof(argv[5]);
  priv->dqlen = sizeof(argv[6]);
  priv->iqlen = sizeof(argv[7]);

  printf("Here is your hash, %s\n", hash_buffer);
  printf("Here is your hash_len, %s\n", hash_len);
  printf("Here is the path to the hash, %s\n", path_to_hash);

  // sign hash
  br_rsa_i31_pkcs1_sign(BR_HASH_OID_SHA256, hash_buffer, hash_len, priv, sign_out)

  // create path to signature file
  path_to_sig = (char*) malloc(snprintf(NULL, 0, "%s.SHA256.SIG", path_to_hash) + 1);
  sprintf(path_to_sig, "%s.SHA256.SIG", path_to_hash);

  // open the file for write binary mode
  FILE * signature = fopen(path_to_sig, "wb");
  // write to the file
  fwrite(sign_out, sizeof(sign_out), sizeof(char), signature);
  // close file
  fclose(signature);
  // end of function
  return 0;
}

