
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
    {.username="user1", .pin="66d2b5e5706659905a2cb479b7eb78d5c91abd1cd3a0525a0aa5d8c5d42af9eb", .salt="nfFgv6f6QLUGNCdi"},
    {.username="user", .pin="a28f85bca56bac601c9e8324bbabd87794c145ba69a5746fcb94aed6fd87eec2", .salt="0UWqBvhVSvs1Itai"},
    {.username="user2", .pin="7927e903cec507ee1e9cb6a288ffb187d4d6d185aa91580cb4cb749b3b01dc0a", .salt="rS3Axg9uZOQWHGMD"},
    {.username="demo", .pin="87bdf35dc818fc2acd8fa3bf3efc94082b4b8b97ace7dd02a7dbc73a15db69ba", .salt="oGIZ80yr8a2hrKAG"},

};

#endif /* __MESH_USERS_H__ */
#define NONCE "n1m345XRjzwvwz1l"
#define KEY "m0pa5LuXt5rx99vtwK6iI17nOdZ7ExGv"
