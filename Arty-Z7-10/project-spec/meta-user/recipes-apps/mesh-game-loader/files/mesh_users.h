
/*
* This is an automatically generated file by provisionSystem.py
*
*
*/

#ifndef __MESH_USERS_H__
#define __MESH_USERS_H__

#define NUM_MESH_USERS 4

struct MeshUser {
    char username[16];
    char pin[64+1];
    char salt[16+1];
};

static struct MeshUser mesh_users[] = {
    {.username="user1", .pin="01a9297a0587f9277716b88976fbb10e3d307bf37194c33cbeea16f9ae9a6ea3", .salt="sVMMMDqqTxN1cNC3"},
    {.username="user", .pin="1fa8b83117fc132a730e665c8a9df174bfa2a1dc4eda83a893c6f7dca8925bd3", .salt="fihtAdHMIG40un4q"},
    {.username="user2", .pin="01fb9773aff71d7b1d0cf16d267e4e5fabd52af449ce9f47e91c53224cb83775", .salt="NhCzRVtScQkUhysw"},
    {.username="demo", .pin="8ed23818baf29814773ebf7f18d6fa8c1dc3714d7c4beb2d5d0584c0f7b93a17", .salt="BPaLslRGL7MJokSE"},

};

#endif /* __MESH_USERS_H__ */
#define NONCE "PoD9SR381XI8su9t"
#define KEY "z8TpeEqmubuwlBFBIB4JPs1NozwVgbzj"
