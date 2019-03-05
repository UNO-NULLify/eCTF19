
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
    {.username="user1", .pin="9830227ee2c8229fcc292ffdfa099ead67e5147711c24effc70aef8f4b778f32", .salt="6KkOdb3okBCHrm25"},
    {.username="user", .pin="c46b17313b6a08d297deccf64bb84aeab1ad87a61d1a623dc57a546969c107ea", .salt="0myQVLdWa5f1LmH9"},
    {.username="user2", .pin="6ab3204bd0b0198afd143f1a0acac1be9cf36069e55111257e9927e66f0e4465", .salt="sP1rwX5U3JXKo3NF"},
    {.username="demo", .pin="c556d76920b63ec3d2d26739ace68322a74e4117f90837da6dede651cac54d25", .salt="fZvJKp240JWtwZLl"},

};

#endif /* __MESH_USERS_H__ */
#define NONCE "oME4ZL9spPySEdMA"
#define KEY "smdVIMRIfUGGpNBWD1orb7iopgh1UtEp"
