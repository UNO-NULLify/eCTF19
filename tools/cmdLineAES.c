#include "./aes.c"
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *const argv[])
{
  // do the AES
  struct AES_ctx ctx;
  uint32_t  game_size;
  char * path_to_game;
  char * key = calloc(32, sizeof(char));
  char * pre_nonce = calloc(8, sizeof(char));
  uint8_t * nonce = calloc(16,sizeof(uint8_t));
  char * game_buffer;


  //Grab the arguments
  path_to_game = argv[1];
  memcpy(key, argv[2], 32);
  memcpy(pre_nonce, argv[3], 8);


  FILE * game = fopen(path_to_game, "rb");
  // get the size of the game
  // Seek to the end of the file
  fseek(game, 0L, SEEK_END);
  // Use ftell to grab the size of the game file at the end
  game_size = ftell(game);
  // set the buffer to correct size
  game_buffer = (char *) calloc(game_size, sizeof(char));
  // reset the file pointer
  fseek(game, 0L, SEEK_SET);

  // Insert the NONCE into the nonce buffer that is 16 bytes and keeps the last 8 bytes NULL <-- we should change this
  strncat(nonce, pre_nonce, 8);

  printf("Here is your key, %s\n", key);
  printf("Here is your nonce, %s\n", nonce);
  printf("Here is the path to the game, %s\n", path_to_game);

  //read the file  into the buffer
  fread(game_buffer, sizeof(char), game_size, game);
  fclose(game);

  // Initialize the ctx
  AES_init_ctx_iv(&ctx, (uint8_t*) key, (uint8_t *) nonce);
  // Decrypt the game
  AES_CTR_xcrypt_buffer(&ctx, (uint8_t *) game_buffer, game_size);

  // write the game buffer out to a file.  File name is _enc for now.

  // create a string of size path_to_game + 5 to include "_enc" and null terminator
  char * encrypted_game = calloc(strlen(path_to_game), sizeof(char));
  // append to the end the file_name
  strncat(encrypted_game, path_to_game, strlen(path_to_game));
  // Open the file for write binary mode
  FILE * enc_game = fopen(encrypted_game, "wb");
  // Write to the file
  fwrite(game_buffer, game_size, sizeof(char), enc_game);
  // Close file
  fclose(enc_game);
  // End of function
  return 0;
}
