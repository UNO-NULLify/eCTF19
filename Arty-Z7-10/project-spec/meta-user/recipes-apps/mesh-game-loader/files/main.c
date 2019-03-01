#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "./aes.c"
#include "./mesh_users.h"

// this is the path where the game will be written to
#define GAMEPATH "/usr/bin/game"

// this is the linux device representing the Zynq ram
#define MEMPATH "/dev/mem"

// the reserved address in ram where uboot writes the game to
#define BASE_ADDR 0x1fc00000

// the size of the reserved memory in ram where uboot writes the game to
#define MAPSIZE 0x400000

// this funciton advances the
unsigned char *skip_line(unsigned char *buf){
    int i=0;

    while (buf[i++] != '\n'){
        continue;
    }

    return buf + i;
}

int mesh_decrypt_game(char *inputBuffer, loff_t game_size){
    struct AES_ctx ctx;
    uint8_t* nonce = calloc(16,sizeof(uint8_t));
    char * key;

    strncat(nonce, NONCE, 8);
    key = KEY;

    AES_init_ctx_iv(&ctx, (uint8_t*) key, (uint8_t *) nonce);
    AES_CTR_xcrypt_buffer(&ctx, (uint8_t *) inputBuffer, game_size);

    return 0;
}

/*
    @brief Main entry point.
    @param argc Argument count.
    @param argv Argument vector.
    @return status code
 */
int main(int argc, char **argv)
{
    int fd;
    unsigned char *map;
    unsigned char *map_tmp;
    int gameSize;
    FILE * gameFp;
    int written;

    // open the memory device
    fd = open(MEMPATH, O_RDWR | O_SYNC);

    if (fd == -1) {
        printf("mem open failed\r\n");
        return 1;
    }

    // map the memory device so your can access it like a chunk of memory
    map = mmap(0, MAPSIZE, (PROT_READ | PROT_WRITE), MAP_SHARED, fd, BASE_ADDR);
    gameSize = *(int *)map;

    mesh_decrypt_game(map, gameSize);

    for(int i=0; i < 25; i++)
    {
      printf("%c\n", map[i]);
    }

    gameFp = NULL;

    gameFp = fopen(GAMEPATH, "w+b");

    if (gameFp == NULL) {
        printf("Error opening game file\r\n");
        return 1;
    }
    printf("Here is the NONCE: %s\n", NONCE);
    printf("Here is the KEY: %s\n", KEY);
    printf("Launching game from reserved ddr. Game Size: %d\r\n", gameSize);

    // jump ahead to the reserved region for the game binary
    map += 0x40;

    // dump first 4 header lines of the game so it is executable
    map_tmp = map;
    for (int i=0; i < 4; i++){
        map_tmp = skip_line(map_tmp);
    }

    // write the game
    written = fwrite(map_tmp, sizeof(char), gameSize - (map_tmp - map), gameFp);

    if (ferror(gameFp)) {
        printf("fwrite error.\r\n");
    }

    printf("%d bytes written\r\n", written);


    fclose(gameFp);

    return 1;
}
