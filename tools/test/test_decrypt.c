//
// Created by artificial on 2/24/19.
//
#include "aes.h"
#include "../../Arty-Z7-10/components/ext_sources/u-boot-ectf/include/linux/stat.h"
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    struct AES_ctx ctx;
    uint8_t key[] = {84, 83, 101, 76, 115, 73, 72, 116, 101, 117, 101, 98, 56, 99, 103, 56, 118, 114, 75, 104, 105, 114, 81, 112, 76, 90, 56, 49, 88, 68, 81, 90, '\0'};
    FILE *fp;
    char file_name[] = "/home/artificial/docs/projects/school/eCTF19/tools/files/generated/games/2048-v1.1";
    uint32_t game_size;
    uint8_t *game_buffer;
    uint8_t* nonce = calloc(16,sizeof(uint8_t));
    strncat(nonce, "UtkDDx4E",8);

    fp = fopen(file_name, "r");
    fseek(fp, 0, SEEK_END);
    game_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("Game size: %d\n", game_size);

    printf("Here is your key, %s\n", key);
    printf("Here is your nonce, %s\n", nonce);

    game_buffer = (uint8_t*)malloc((size_t) game_size);

    fp = fopen(file_name, "rb");
    fread(game_buffer, game_size, 1, fp);
    fclose(fp);

    printf("\nRead file.\n");

    // Decrypt the game
    // What is the counter?
    AES_init_ctx_iv(&ctx, (uint8_t*) key, (uint8_t*) nonce);
    AES_CTR_xcrypt_buffer(&ctx, (uint8_t *) game_buffer, game_size);

    fp = fopen(file_name, "wb");
    fwrite(game_buffer, game_size, 1, fp);
    fclose(fp);

    printf("Decrypted file.\n");

    return 0;
}