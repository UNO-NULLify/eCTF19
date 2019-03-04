#ifndef __MESH_H__
#define __MESH_H__

#include <ext4fs.h>

#define MAX_STR_LEN 64
#define MAX_USERNAME_LENGTH 15
#define MAX_PIN_LENGTH 8
#define MAX_GAME_LENGTH 31
#define MAX_NUM_USERS 5

#define MESH_SENTINEL_LOCATION 0x00000040
#define MESH_SENTINEL_VALUE 0x12345678
#define MESH_SENTINEL_LENGTH 4
#define MESH_INSTALL_GAME_OFFSET 0x00000044

#define MESH_TABLE_UNINSTALLED 0x00
#define MESH_TABLE_INSTALLED 0x01
#define MESH_TABLE_END 0xff

#define SHA256_DIGEST_LENGTH 64

// To erase (or call update) on flash, it needs to be done
// on boundaries of size 64K
#define FLASH_PAGE_SIZE 65536

typedef struct {
    char name[MAX_USERNAME_LENGTH + 1];
    char pin[MAX_PIN_LENGTH + 1];
} User;

typedef struct game {
    char name[MAX_GAME_LENGTH + 1];
    unsigned int major_version;
    unsigned int minor_version;
    char users[MAX_NUM_USERS][MAX_USERNAME_LENGTH + 1];
    int num_users;
} Game;

struct games_tbl_row {
    char install_flag; // 00 no longer installed, 01 installed, ff end
    char game_name[MAX_GAME_LENGTH + 1];
    unsigned int major_version;
    unsigned int minor_version;
    char user_name[MAX_USERNAME_LENGTH + 1];
    unsigned char hash[SHA256_DIGEST_LENGTH+1]; // sha256 is 32 bytes, one for '\0'
};

/*
    Helper functions
*/
int mesh_game_installed(char *game_name);
int mesh_play_validate_args(char **args);
int mesh_game_exists(char *game_name);
int mesh_check_downgrade(char *game_name, unsigned int major_version, unsigned int minor_version);
int mesh_check_user(Game *game);
void mesh_get_game_header(Game *game, char *game_name);
int mesh_install_validate_args(char **args);
int mesh_execute(char **args);
int mesh_is_first_table_write(void);
int mesh_validate_user(User *user);
int mesh_num_builtins(void) ;
char* mesh_read_line(int bufsize);
int mesh_get_argv(char **args);
char **mesh_split_line(char *line) ;
char* mesh_input(char* prompt);
char* mesh_input_creds(char* prompt, int mode);
int mesh_valid_install(char *game_name);
void ptr_to_string(void* ptr, char* buf);
void full_name_from_short_name(char* full_name, struct games_tbl_row* row);
int mesh_read_hash(char *game_name);

int mesh_check_hash(char *game_name);

/*
    Ext 4 functions
*/
int mesh_ls_ext4(const char *dirname, char *filename);
int mesh_ls_iterate_dir(struct ext2fs_node *dir, char *fname);
int mesh_query_ext4(const char *dirname, char *filename);
loff_t mesh_size_ext4(char *fname);
loff_t mesh_read_ext4(char *fname, char*buf, loff_t size);

/*
    Function Declarations for builtin shell commands:
 */

int mesh_help(char **args);
int mesh_shutdown(char **args);
int mesh_logout(char **args);
int mesh_list(char **args);
int mesh_play(char **args);
int mesh_query(char **args);
int mesh_install(char **args);
int mesh_uninstall(char **args);
int mesh_dump_flash(char **args);
int mesh_reset_flash(char **args);
int mesh_login(User *user) ;
void mesh_loop(void);

/*
 * Mesh flash commands
 */
int mesh_flash_init(void);
int mesh_flash_write(void* data, unsigned int flash_location, unsigned int flash_length);
int mesh_flash_read(void* data, unsigned int flash_location, unsigned int flash_length);
int mesh_is_first_table_write(void);

#ifndef OPENSSL_NO_CAMELLIA
# define OPENSSL_NO_CAMELLIA
#endif
#ifndef OPENSSL_NO_CAPIENG
# define OPENSSL_NO_CAPIENG
#endif
#ifndef OPENSSL_NO_CMS
# define OPENSSL_NO_CMS
#endif
#ifndef OPENSSL_NO_GMP
# define OPENSSL_NO_GMP
#endif
#ifndef OPENSSL_NO_JPAKE
# define OPENSSL_NO_JPAKE
#endif
#ifndef OPENSSL_NO_KRB5
# define OPENSSL_NO_KRB5
#endif
#ifndef OPENSSL_NO_MDC2
# define OPENSSL_NO_MDC2
#endif
#ifndef OPENSSL_NO_RC5
# define OPENSSL_NO_RC5
#endif
#ifndef OPENSSL_NO_RFC3779
# define OPENSSL_NO_RFC3779
#endif
#ifndef OPENSSL_NO_SEED
# define OPENSSL_NO_SEED
#endif

#ifndef OPENSSL_THREADS
# define OPENSSL_THREADS
#endif

/* The OPENSSL_NO_* macros are also defined as NO_* if the application
   asks for it.  This is a transient feature that is provided for those
   who haven't had the time to do the appropriate changes in their
   applications.  */
#ifdef OPENSSL_ALGORITHM_DEFINES
# if defined(OPENSSL_NO_CAMELLIA) && !defined(NO_CAMELLIA)
#  define NO_CAMELLIA
# endif
# if defined(OPENSSL_NO_CAPIENG) && !defined(NO_CAPIENG)
#  define NO_CAPIENG
# endif
# if defined(OPENSSL_NO_CMS) && !defined(NO_CMS)
#  define NO_CMS
# endif
# if defined(OPENSSL_NO_GMP) && !defined(NO_GMP)
#  define NO_GMP
# endif
# if defined(OPENSSL_NO_JPAKE) && !defined(NO_JPAKE)
#  define NO_JPAKE
# endif
# if defined(OPENSSL_NO_KRB5) && !defined(NO_KRB5)
#  define NO_KRB5
# endif
# if defined(OPENSSL_NO_MDC2) && !defined(NO_MDC2)
#  define NO_MDC2
# endif
# if defined(OPENSSL_NO_RC5) && !defined(NO_RC5)
#  define NO_RC5
# endif
# if defined(OPENSSL_NO_RFC3779) && !defined(NO_RFC3779)
#  define NO_RFC3779
# endif
# if defined(OPENSSL_NO_SEED) && !defined(NO_SEED)
#  define NO_SEED
# endif
#endif

/* crypto/opensslconf.h.in */

#ifdef OPENSSL_DOING_MAKEDEPEND

/* Include any symbols here that have to be explicitly set to enable a feature
 * that should be visible to makedepend.
 *
 * [Our "make depend" doesn't actually look at this, we use actual build settings
 * instead; we want to make it easy to remove subdirectories with disabled algorithms.]
 */

#ifndef OPENSSL_FIPS
#define OPENSSL_FIPS
#endif

#endif

/* Generate 80386 code? */
#undef I386_ONLY

#if !(defined(VMS) || defined(__VMS)) /* VMS uses logical names instead */
#if defined(HEADER_CRYPTLIB_H) && !defined(OPENSSLDIR)
#define ENGINESDIR "C:\\openssl-0.9.8r/lib/engines"
#define OPENSSLDIR "C:\\openssl-0.9.8r/ssl"
#endif
#endif

#undef OPENSSL_UNISTD
#define OPENSSL_UNISTD <unistd.h>

#undef OPENSSL_EXPORT_VAR_AS_FUNCTION
#define OPENSSL_EXPORT_VAR_AS_FUNCTION

#if defined(HEADER_IDEA_H) && !defined(IDEA_INT)
#define IDEA_INT unsigned int
#endif

#if defined(HEADER_MD2_H) && !defined(MD2_INT)
#define MD2_INT unsigned int
#endif

#if defined(HEADER_RC2_H) && !defined(RC2_INT)
/* I need to put in a mod for the alpha - eay */
#define RC2_INT unsigned int
#endif

#if defined(HEADER_RC4_H)
#if !defined(RC4_INT)
/* using int types make the structure larger but make the code faster
 * on most boxes I have tested - up to %20 faster. */
/*
 * I don't know what does "most" mean, but declaring "int" is a must on:
 * - Intel P6 because partial register stalls are very expensive;
 * - elder Alpha because it lacks byte load/store instructions;
 */
#define RC4_INT unsigned int
#endif
#if !defined(RC4_CHUNK)
/*
 * This enables code handling data aligned at natural CPU word
 * boundary. See crypto/rc4/rc4_enc.c for further details.
 */
#undef RC4_CHUNK
#endif
#endif

#if (defined(HEADER_NEW_DES_H) || defined(HEADER_DES_H)) && !defined(DES_LONG)
/* If this is set to 'unsigned int' on a DEC Alpha, this gives about a
 * %20 speed up (longs are 8 bytes, int's are 4). */
#ifndef DES_LONG
#define DES_LONG unsigned long
#endif
#endif

#if defined(HEADER_BN_H) && !defined(CONFIG_HEADER_BN_H)
#define CONFIG_HEADER_BN_H
#define BN_LLONG

/* Should we define BN_DIV2W here? */

/* Only one for the following should be defined */
/* The prime number generation stuff may not work when
 * EIGHT_BIT but I don't care since I've only used this mode
 * for debuging the bignum libraries */
#undef SIXTY_FOUR_BIT_LONG
#undef SIXTY_FOUR_BIT
#define THIRTY_TWO_BIT
#undef SIXTEEN_BIT
#undef EIGHT_BIT
#endif

#if defined(HEADER_RC4_LOCL_H) && !defined(CONFIG_HEADER_RC4_LOCL_H)
#define CONFIG_HEADER_RC4_LOCL_H
/* if this is defined data[i] is used instead of *data, this is a %20
 * speedup on x86 */
#define RC4_INDEX
#endif

#if defined(HEADER_BF_LOCL_H) && !defined(CONFIG_HEADER_BF_LOCL_H)
#define CONFIG_HEADER_BF_LOCL_H
#undef BF_PTR
#endif /* HEADER_BF_LOCL_H */

#if defined(HEADER_DES_LOCL_H) && !defined(CONFIG_HEADER_DES_LOCL_H)
#define CONFIG_HEADER_DES_LOCL_H
#ifndef DES_DEFAULT_OPTIONS
/* the following is tweaked from a config script, that is why it is a
 * protected undef/define */
#ifndef DES_PTR
#undef DES_PTR
#endif

/* This helps C compiler generate the correct code for multiple functional
 * units.  It reduces register dependancies at the expense of 2 more
 * registers */
#ifndef DES_RISC1
#undef DES_RISC1
#endif

#ifndef DES_RISC2
#undef DES_RISC2
#endif

#if defined(DES_RISC1) && defined(DES_RISC2)
YOU SHOULD NOT HAVE BOTH DES_RISC1 AND DES_RISC2 DEFINED!!!!!
#endif

/* Unroll the inner loop, this sometimes helps, sometimes hinders.
 * Very mucy CPU dependant */
#ifndef DES_UNROLL
#undef DES_UNROLL
#endif

/* These default values were supplied by
 * Peter Gutman <pgut001@cs.auckland.ac.nz>
 * They are only used if nothing else has been defined */
#if !defined(DES_PTR) && !defined(DES_RISC1) && !defined(DES_RISC2) && !defined(DES_UNROLL)
/* Special defines which change the way the code is built depending on the
   CPU and OS.  For SGI machines you can use _MIPS_SZLONG (32 or 64) to find
   even newer MIPS CPU's, but at the moment one size fits all for
   optimization options.  Older Sparc's work better with only UNROLL, but
   there's no way to tell at compile time what it is you're running on */

#if defined( sun )		/* Newer Sparc's */
#  define DES_PTR
#  define DES_RISC1
#  define DES_UNROLL
#elif defined( __ultrix )	/* Older MIPS */
#  define DES_PTR
#  define DES_RISC2
#  define DES_UNROLL
#elif defined( __osf1__ )	/* Alpha */
#  define DES_PTR
#  define DES_RISC2
#elif defined ( _AIX )		/* RS6000 */
  /* Unknown */
#elif defined( __hpux )		/* HP-PA */
  /* Unknown */
#elif defined( __aux )		/* 68K */
  /* Unknown */
#elif defined( __dgux )		/* 88K (but P6 in latest boxes) */
#  define DES_UNROLL
#elif defined( __sgi )		/* Newer MIPS */
#  define DES_PTR
#  define DES_RISC2
#  define DES_UNROLL
#elif defined(i386) || defined(__i386__)	/* x86 boxes, should be gcc */
#  define DES_PTR
#  define DES_RISC1
#  define DES_UNROLL
#endif /* Systems-specific speed defines */
#endif

#endif /* DES_DEFAULT_OPTIONS */
#endif /* HEADER_DES_LOCL_H */



/******************************************************************************
 * Detect operating systems.  This probably needs completing.
 * The result is that at least one OPENSSL_SYS_os macro should be defined.
 * However, if none is defined, Unix is assumed.
 **/

#define OPENSSL_SYS_UNIX

/* ----------------------- Macintosh, before MacOS X ----------------------- */
#if defined(__MWERKS__) && defined(macintosh) || defined(OPENSSL_SYSNAME_MAC)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_MACINTOSH_CLASSIC
#endif

/* ----------------------- NetWare ----------------------------------------- */
#if defined(NETWARE) || defined(OPENSSL_SYSNAME_NETWARE)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_NETWARE
#endif

/* ---------------------- Microsoft operating systems ---------------------- */

/* Note that MSDOS actually denotes 32-bit environments running on top of
   MS-DOS, such as DJGPP one. */
#if defined(OPENSSL_SYSNAME_MSDOS)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_MSDOS
#endif

/* For 32 bit environment, there seems to be the CygWin environment and then
   all the others that try to do the same thing Microsoft does... */
#if defined(OPENSSL_SYSNAME_UWIN)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_WIN32_UWIN
#else
# if defined(__CYGWIN32__) || defined(OPENSSL_SYSNAME_CYGWIN32)
#  undef OPENSSL_SYS_UNIX
#  define OPENSSL_SYS_WIN32_CYGWIN
# else
#  if defined(_WIN32) || defined(OPENSSL_SYSNAME_WIN32)
#   undef OPENSSL_SYS_UNIX
#   define OPENSSL_SYS_WIN32
#  endif
#  if defined(OPENSSL_SYSNAME_WINNT)
#   undef OPENSSL_SYS_UNIX
#   define OPENSSL_SYS_WINNT
#  endif
#  if defined(OPENSSL_SYSNAME_WINCE)
#   undef OPENSSL_SYS_UNIX
#   define OPENSSL_SYS_WINCE
#  endif
# endif
#endif

/* Anything that tries to look like Microsoft is "Windows" */
#if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINNT) || defined(OPENSSL_SYS_WINCE)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_WINDOWS
# ifndef OPENSSL_SYS_MSDOS
#  define OPENSSL_SYS_MSDOS
# endif
#endif

/* DLL settings.  This part is a bit tough, because it's up to the application
   implementor how he or she will link the application, so it requires some
   macro to be used. */
#ifdef OPENSSL_SYS_WINDOWS
# ifndef OPENSSL_OPT_WINDLL
#  if defined(_WINDLL) /* This is used when building OpenSSL to indicate that
                          DLL linkage should be used */
#   define OPENSSL_OPT_WINDLL
#  endif
# endif
#endif

/* -------------------------------- OpenVMS -------------------------------- */
#if defined(__VMS) || defined(VMS) || defined(OPENSSL_SYSNAME_VMS)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_VMS
# if defined(__DECC)
#  define OPENSSL_SYS_VMS_DECC
# elif defined(__DECCXX)
#  define OPENSSL_SYS_VMS_DECC
#  define OPENSSL_SYS_VMS_DECCXX
# else
#  define OPENSSL_SYS_VMS_NODECC
# endif
#endif

/* --------------------------------- OS/2 ---------------------------------- */
#if defined(__EMX__) || defined(__OS2__)
# undef OPENSSL_SYS_UNIX
# define OPENSSL_SYS_OS2
#endif

/* --------------------------------- Unix ---------------------------------- */
#ifdef OPENSSL_SYS_UNIX
# if defined(linux) || defined(__linux__) || defined(OPENSSL_SYSNAME_LINUX)
#  define OPENSSL_SYS_LINUX
# endif
# ifdef OPENSSL_SYSNAME_MPE
#  define OPENSSL_SYS_MPE
# endif
# ifdef OPENSSL_SYSNAME_SNI
#  define OPENSSL_SYS_SNI
# endif
# ifdef OPENSSL_SYSNAME_ULTRASPARC
#  define OPENSSL_SYS_ULTRASPARC
# endif
# ifdef OPENSSL_SYSNAME_NEWS4
#  define OPENSSL_SYS_NEWS4
# endif
# ifdef OPENSSL_SYSNAME_MACOSX
#  define OPENSSL_SYS_MACOSX
# endif
# ifdef OPENSSL_SYSNAME_MACOSX_RHAPSODY
#  define OPENSSL_SYS_MACOSX_RHAPSODY
#  define OPENSSL_SYS_MACOSX
# endif
# ifdef OPENSSL_SYSNAME_SUNOS
#  define OPENSSL_SYS_SUNOS
#endif
# if defined(_CRAY) || defined(OPENSSL_SYSNAME_CRAY)
#  define OPENSSL_SYS_CRAY
# endif
# if defined(_AIX) || defined(OPENSSL_SYSNAME_AIX)
#  define OPENSSL_SYS_AIX
# endif
#endif

/* --------------------------------- VOS ----------------------------------- */
#ifdef OPENSSL_SYSNAME_VOS
# define OPENSSL_SYS_VOS
#endif

/* ------------------------------- VxWorks --------------------------------- */
#ifdef OPENSSL_SYSNAME_VXWORKS
# define OPENSSL_SYS_VXWORKS
#endif

/**
 * That's it for OS-specific stuff
 *****************************************************************************/


/* Specials for I/O an exit */
#ifdef OPENSSL_SYS_MSDOS
# define OPENSSL_UNISTD_IO <io.h>
# define OPENSSL_DECLARE_EXIT extern void exit(int);
#else
# define OPENSSL_UNISTD_IO OPENSSL_UNISTD
# define OPENSSL_DECLARE_EXIT /* declared in unistd.h */
#endif

/* Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN, to define and declare
   certain global symbols that, with some compilers under VMS, have to be
   defined and declared explicitely with globaldef and globalref.
   Definitions of OPENSSL_EXPORT and OPENSSL_IMPORT, to define and declare
   DLL exports and imports for compilers under Win32.  These are a little
   more complicated to use.  Basically, for any library that exports some
   global variables, the following code must be present in the header file
   that declares them, before OPENSSL_EXTERN is used:

   #ifdef SOME_BUILD_FLAG_MACRO
   # undef OPENSSL_EXTERN
   # define OPENSSL_EXTERN OPENSSL_EXPORT
   #endif

   The default is to have OPENSSL_EXPORT, OPENSSL_IMPORT and OPENSSL_GLOBAL
   have some generally sensible values, and for OPENSSL_EXTERN to have the
   value OPENSSL_IMPORT.
*/

#if defined(OPENSSL_SYS_VMS_NODECC)
# define OPENSSL_EXPORT globalref
# define OPENSSL_IMPORT globalref
# define OPENSSL_GLOBAL globaldef
#elif defined(OPENSSL_SYS_WINDOWS) && defined(OPENSSL_OPT_WINDLL)
# define OPENSSL_EXPORT extern __declspec(dllexport)
# define OPENSSL_IMPORT extern __declspec(dllimport)
# define OPENSSL_GLOBAL
#else
# define OPENSSL_EXPORT extern
# define OPENSSL_IMPORT extern
# define OPENSSL_GLOBAL
#endif
#define OPENSSL_EXTERN OPENSSL_IMPORT

/* Macros to allow global variables to be reached through function calls when
   required (if a shared library version requvres it, for example.
   The way it's done allows definitions like this:

	// in foobar.c
	OPENSSL_IMPLEMENT_GLOBAL(int,foobar) = 0;
	// in foobar.h
	OPENSSL_DECLARE_GLOBAL(int,foobar);
	#define foobar OPENSSL_GLOBAL_REF(foobar)
*/
#ifdef OPENSSL_EXPORT_VAR_AS_FUNCTION
# define OPENSSL_IMPLEMENT_GLOBAL(type,name)			     \
	extern type _hide_##name;				     \
	type *_shadow_##name(void) { return &_hide_##name; }	     \
	static type _hide_##name
# define OPENSSL_DECLARE_GLOBAL(type,name) type *_shadow_##name(void)
# define OPENSSL_GLOBAL_REF(name) (*(_shadow_##name()))
#else
# define OPENSSL_IMPLEMENT_GLOBAL(type,name) OPENSSL_GLOBAL type _shadow_##name
# define OPENSSL_DECLARE_GLOBAL(type,name) OPENSSL_EXPORT type _shadow_##name
# define OPENSSL_GLOBAL_REF(name) _shadow_##name
#endif

typedef struct stack_st
{
    int num;
    char **data;
    int sorted;

    int num_alloc;
    int (*comp)(const char * const *, const char * const *);
} STACK;

#define M_sk_num(sk)		((sk) ? (sk)->num:-1)
#define M_sk_value(sk,n)	((sk) ? (sk)->data[n] : NULL)

int sk_num(const STACK *);
char *sk_value(const STACK *, int);

char *sk_set(STACK *, int, char *);

STACK *sk_new(int (*cmp)(const char * const *, const char * const *));
STACK *sk_new_null(void);
void sk_free(STACK *);
void sk_pop_free(STACK *st, void (*func)(void *));
int sk_insert(STACK *sk,char *data,int where);
char *sk_delete(STACK *st,int loc);
char *sk_delete_ptr(STACK *st, char *p);
int sk_find(STACK *st,char *data);
int sk_find_ex(STACK *st,char *data);
int sk_push(STACK *st,char *data);
int sk_unshift(STACK *st,char *data);
char *sk_shift(STACK *st);
char *sk_pop(STACK *st);
void sk_zero(STACK *st);
int (*sk_set_cmp_func(STACK *sk, int (*c)(const char * const *,
                                          const char * const *)))
        (const char * const *, const char * const *);
STACK *sk_dup(STACK *st);
void sk_sort(STACK *st);
int sk_is_sorted(const STACK *st);


#ifdef DEBUG_SAFESTACK

#ifndef CHECKED_PTR_OF
#define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
#endif

#define CHECKED_SK_FREE_FUNC(type, p) \
    ((void (*)(void *)) ((1 ? p : (void (*)(type *))0)))

#define CHECKED_SK_CMP_FUNC(type, p) \
    ((int (*)(const char * const *, const char * const *)) \
	((1 ? p : (int (*)(const type * const *, const type * const *))0)))

#define STACK_OF(type) struct stack_st_##type
#define PREDECLARE_STACK_OF(type) STACK_OF(type);

#define DECLARE_STACK_OF(type) \
STACK_OF(type) \
    { \
    STACK stack; \
    };

#define IMPLEMENT_STACK_OF(type) /* nada (obsolete in new safestack approach)*/

/* SKM_sk_... stack macros are internal to safestack.h:
 * never use them directly, use sk_<type>_... instead */
#define SKM_sk_new(type, cmp) \
	((STACK_OF(type) *)sk_new(CHECKED_SK_CMP_FUNC(type, cmp)))
#define SKM_sk_new_null(type) \
	((STACK_OF(type) *)sk_new_null())
#define SKM_sk_free(type, st) \
	sk_free(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_num(type, st) \
	sk_num(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_value(type, st,i) \
	((type *)sk_value(CHECKED_PTR_OF(STACK_OF(type), st), i))
#define SKM_sk_set(type, st,i,val) \
	sk_set(CHECKED_PTR_OF(STACK_OF(type), st), i, CHECKED_PTR_OF(type, val))
#define SKM_sk_zero(type, st) \
	sk_zero(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_push(type, st,val) \
	sk_push(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_PTR_OF(type, val))
#define SKM_sk_unshift(type, st,val) \
	sk_unshift(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_PTR_OF(type, val))
#define SKM_sk_find(type, st,val) \
	sk_find(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_PTR_OF(type, val))
#define SKM_sk_delete(type, st,i) \
	(type *)sk_delete(CHECKED_PTR_OF(STACK_OF(type), st), i)
#define SKM_sk_delete_ptr(type, st,ptr) \
	(type *)sk_delete_ptr(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_PTR_OF(type, ptr))
#define SKM_sk_insert(type, st,val,i) \
	sk_insert(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_PTR_OF(type, val), i)
#define SKM_sk_set_cmp_func(type, st,cmp) \
	((int (*)(const type * const *,const type * const *)) \
	sk_set_cmp_func(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_SK_CMP_FUNC(type, cmp)))
#define SKM_sk_dup(type, st) \
	(STACK_OF(type) *)sk_dup(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_pop_free(type, st,free_func) \
	sk_pop_free(CHECKED_PTR_OF(STACK_OF(type), st), CHECKED_SK_FREE_FUNC(type, free_func))
#define SKM_sk_shift(type, st) \
	(type *)sk_shift(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_pop(type, st) \
	(type *)sk_pop(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_sort(type, st) \
	sk_sort(CHECKED_PTR_OF(STACK_OF(type), st))
#define SKM_sk_is_sorted(type, st) \
	sk_is_sorted(CHECKED_PTR_OF(STACK_OF(type), st))

#define	SKM_ASN1_SET_OF_d2i(type, st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	(STACK_OF(type) *)d2i_ASN1_SET(CHECKED_PTR_OF(STACK_OF(type)*, st), \
				pp, length, \
				CHECKED_D2I_OF(type, d2i_func), \
				CHECKED_SK_FREE_FUNC(type, free_func), \
				ex_tag, ex_class)

#define	SKM_ASN1_SET_OF_i2d(type, st, pp, i2d_func, ex_tag, ex_class, is_set) \
	i2d_ASN1_SET(CHECKED_PTR_OF(STACK_OF(type), st), pp, \
				CHECKED_I2D_OF(type, i2d_func), \
				ex_tag, ex_class, is_set)

#define	SKM_ASN1_seq_pack(type, st, i2d_func, buf, len) \
	ASN1_seq_pack(CHECKED_PTR_OF(STACK_OF(type), st), \
			CHECKED_I2D_OF(type, i2d_func), buf, len)

#define	SKM_ASN1_seq_unpack(type, buf, len, d2i_func, free_func) \
	(STACK_OF(type) *)ASN1_seq_unpack(buf, len, CHECKED_D2I_OF(type, d2i_func), CHECKED_SK_FREE_FUNC(type, free_func))

#define SKM_PKCS12_decrypt_d2i(type, algor, d2i_func, free_func, pass, passlen, oct, seq) \
	(STACK_OF(type) *)PKCS12_decrypt_d2i(algor, \
				CHECKED_D2I_OF(type, d2i_func), \
				CHECKED_SK_FREE_FUNC(type, free_func), \
				pass, passlen, oct, seq)

#else

#define STACK_OF(type) STACK
#define PREDECLARE_STACK_OF(type) /* nada */
#define DECLARE_STACK_OF(type)    /* nada */
#define IMPLEMENT_STACK_OF(type)  /* nada */

#define SKM_sk_new(type, cmp) \
	sk_new((int (*)(const char * const *, const char * const *))(cmp))
#define SKM_sk_new_null(type) \
	sk_new_null()
#define SKM_sk_free(type, st) \
	sk_free(st)
#define SKM_sk_num(type, st) \
	sk_num(st)
#define SKM_sk_value(type, st,i) \
	((type *)sk_value(st, i))
#define SKM_sk_set(type, st,i,val) \
	((type *)sk_set(st, i,(char *)val))
#define SKM_sk_zero(type, st) \
	sk_zero(st)
#define SKM_sk_push(type, st,val) \
	sk_push(st, (char *)val)
#define SKM_sk_unshift(type, st,val) \
	sk_unshift(st, (char *)val)
#define SKM_sk_find(type, st,val) \
	sk_find(st, (char *)val)
#define SKM_sk_delete(type, st,i) \
	((type *)sk_delete(st, i))
#define SKM_sk_delete_ptr(type, st,ptr) \
	((type *)sk_delete_ptr(st,(char *)ptr))
#define SKM_sk_insert(type, st,val,i) \
	sk_insert(st, (char *)val, i)
#define SKM_sk_set_cmp_func(type, st,cmp) \
	((int (*)(const type * const *,const type * const *)) \
	sk_set_cmp_func(st, (int (*)(const char * const *, const char * const *))(cmp)))
#define SKM_sk_dup(type, st) \
	sk_dup(st)
#define SKM_sk_pop_free(type, st,free_func) \
	sk_pop_free(st, (void (*)(void *))free_func)
#define SKM_sk_shift(type, st) \
	((type *)sk_shift(st))
#define SKM_sk_pop(type, st) \
	((type *)sk_pop(st))
#define SKM_sk_sort(type, st) \
	sk_sort(st)
#define SKM_sk_is_sorted(type, st) \
	sk_is_sorted(st)

#define	SKM_ASN1_SET_OF_d2i(type, st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	d2i_ASN1_SET(st,pp,length, (void *(*)(void ** ,const unsigned char ** ,long))d2i_func, (void (*)(void *))free_func, ex_tag,ex_class)
#define	SKM_ASN1_SET_OF_i2d(type, st, pp, i2d_func, ex_tag, ex_class, is_set) \
	i2d_ASN1_SET(st,pp,(int (*)(void *, unsigned char **))i2d_func,ex_tag,ex_class,is_set)

#define	SKM_ASN1_seq_pack(type, st, i2d_func, buf, len) \
	ASN1_seq_pack(st, (int (*)(void *, unsigned char **))i2d_func, buf, len)
#define	SKM_ASN1_seq_unpack(type, buf, len, d2i_func, free_func) \
	ASN1_seq_unpack(buf,len,(void *(*)(void **,const unsigned char **,long))d2i_func, (void(*)(void *))free_func)

#define SKM_PKCS12_decrypt_d2i(type, algor, d2i_func, free_func, pass, passlen, oct, seq) \
	((STACK *)PKCS12_decrypt_d2i(algor,(char *(*)())d2i_func, (void(*)(void *))free_func,pass,passlen,oct,seq))

#endif

/* This block of defines is updated by util/mkstack.pl, please do not touch! */
#define sk_ACCESS_DESCRIPTION_new(st) SKM_sk_new(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_new_null() SKM_sk_new_null(ACCESS_DESCRIPTION)
#define sk_ACCESS_DESCRIPTION_free(st) SKM_sk_free(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_num(st) SKM_sk_num(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_value(st, i) SKM_sk_value(ACCESS_DESCRIPTION, (st), (i))
#define sk_ACCESS_DESCRIPTION_set(st, i, val) SKM_sk_set(ACCESS_DESCRIPTION, (st), (i), (val))
#define sk_ACCESS_DESCRIPTION_zero(st) SKM_sk_zero(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_push(st, val) SKM_sk_push(ACCESS_DESCRIPTION, (st), (val))
#define sk_ACCESS_DESCRIPTION_unshift(st, val) SKM_sk_unshift(ACCESS_DESCRIPTION, (st), (val))
#define sk_ACCESS_DESCRIPTION_find(st, val) SKM_sk_find(ACCESS_DESCRIPTION, (st), (val))
#define sk_ACCESS_DESCRIPTION_find_ex(st, val) SKM_sk_find_ex(ACCESS_DESCRIPTION, (st), (val))
#define sk_ACCESS_DESCRIPTION_delete(st, i) SKM_sk_delete(ACCESS_DESCRIPTION, (st), (i))
#define sk_ACCESS_DESCRIPTION_delete_ptr(st, ptr) SKM_sk_delete_ptr(ACCESS_DESCRIPTION, (st), (ptr))
#define sk_ACCESS_DESCRIPTION_insert(st, val, i) SKM_sk_insert(ACCESS_DESCRIPTION, (st), (val), (i))
#define sk_ACCESS_DESCRIPTION_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ACCESS_DESCRIPTION, (st), (cmp))
#define sk_ACCESS_DESCRIPTION_dup(st) SKM_sk_dup(ACCESS_DESCRIPTION, st)
#define sk_ACCESS_DESCRIPTION_pop_free(st, free_func) SKM_sk_pop_free(ACCESS_DESCRIPTION, (st), (free_func))
#define sk_ACCESS_DESCRIPTION_shift(st) SKM_sk_shift(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_pop(st) SKM_sk_pop(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_sort(st) SKM_sk_sort(ACCESS_DESCRIPTION, (st))
#define sk_ACCESS_DESCRIPTION_is_sorted(st) SKM_sk_is_sorted(ACCESS_DESCRIPTION, (st))

#define sk_ASIdOrRange_new(st) SKM_sk_new(ASIdOrRange, (st))
#define sk_ASIdOrRange_new_null() SKM_sk_new_null(ASIdOrRange)
#define sk_ASIdOrRange_free(st) SKM_sk_free(ASIdOrRange, (st))
#define sk_ASIdOrRange_num(st) SKM_sk_num(ASIdOrRange, (st))
#define sk_ASIdOrRange_value(st, i) SKM_sk_value(ASIdOrRange, (st), (i))
#define sk_ASIdOrRange_set(st, i, val) SKM_sk_set(ASIdOrRange, (st), (i), (val))
#define sk_ASIdOrRange_zero(st) SKM_sk_zero(ASIdOrRange, (st))
#define sk_ASIdOrRange_push(st, val) SKM_sk_push(ASIdOrRange, (st), (val))
#define sk_ASIdOrRange_unshift(st, val) SKM_sk_unshift(ASIdOrRange, (st), (val))
#define sk_ASIdOrRange_find(st, val) SKM_sk_find(ASIdOrRange, (st), (val))
#define sk_ASIdOrRange_find_ex(st, val) SKM_sk_find_ex(ASIdOrRange, (st), (val))
#define sk_ASIdOrRange_delete(st, i) SKM_sk_delete(ASIdOrRange, (st), (i))
#define sk_ASIdOrRange_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASIdOrRange, (st), (ptr))
#define sk_ASIdOrRange_insert(st, val, i) SKM_sk_insert(ASIdOrRange, (st), (val), (i))
#define sk_ASIdOrRange_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASIdOrRange, (st), (cmp))
#define sk_ASIdOrRange_dup(st) SKM_sk_dup(ASIdOrRange, st)
#define sk_ASIdOrRange_pop_free(st, free_func) SKM_sk_pop_free(ASIdOrRange, (st), (free_func))
#define sk_ASIdOrRange_shift(st) SKM_sk_shift(ASIdOrRange, (st))
#define sk_ASIdOrRange_pop(st) SKM_sk_pop(ASIdOrRange, (st))
#define sk_ASIdOrRange_sort(st) SKM_sk_sort(ASIdOrRange, (st))
#define sk_ASIdOrRange_is_sorted(st) SKM_sk_is_sorted(ASIdOrRange, (st))

#define sk_ASN1_GENERALSTRING_new(st) SKM_sk_new(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_new_null() SKM_sk_new_null(ASN1_GENERALSTRING)
#define sk_ASN1_GENERALSTRING_free(st) SKM_sk_free(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_num(st) SKM_sk_num(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_value(st, i) SKM_sk_value(ASN1_GENERALSTRING, (st), (i))
#define sk_ASN1_GENERALSTRING_set(st, i, val) SKM_sk_set(ASN1_GENERALSTRING, (st), (i), (val))
#define sk_ASN1_GENERALSTRING_zero(st) SKM_sk_zero(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_push(st, val) SKM_sk_push(ASN1_GENERALSTRING, (st), (val))
#define sk_ASN1_GENERALSTRING_unshift(st, val) SKM_sk_unshift(ASN1_GENERALSTRING, (st), (val))
#define sk_ASN1_GENERALSTRING_find(st, val) SKM_sk_find(ASN1_GENERALSTRING, (st), (val))
#define sk_ASN1_GENERALSTRING_find_ex(st, val) SKM_sk_find_ex(ASN1_GENERALSTRING, (st), (val))
#define sk_ASN1_GENERALSTRING_delete(st, i) SKM_sk_delete(ASN1_GENERALSTRING, (st), (i))
#define sk_ASN1_GENERALSTRING_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_GENERALSTRING, (st), (ptr))
#define sk_ASN1_GENERALSTRING_insert(st, val, i) SKM_sk_insert(ASN1_GENERALSTRING, (st), (val), (i))
#define sk_ASN1_GENERALSTRING_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_GENERALSTRING, (st), (cmp))
#define sk_ASN1_GENERALSTRING_dup(st) SKM_sk_dup(ASN1_GENERALSTRING, st)
#define sk_ASN1_GENERALSTRING_pop_free(st, free_func) SKM_sk_pop_free(ASN1_GENERALSTRING, (st), (free_func))
#define sk_ASN1_GENERALSTRING_shift(st) SKM_sk_shift(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_pop(st) SKM_sk_pop(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_sort(st) SKM_sk_sort(ASN1_GENERALSTRING, (st))
#define sk_ASN1_GENERALSTRING_is_sorted(st) SKM_sk_is_sorted(ASN1_GENERALSTRING, (st))

#define sk_ASN1_INTEGER_new(st) SKM_sk_new(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_new_null() SKM_sk_new_null(ASN1_INTEGER)
#define sk_ASN1_INTEGER_free(st) SKM_sk_free(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_num(st) SKM_sk_num(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_value(st, i) SKM_sk_value(ASN1_INTEGER, (st), (i))
#define sk_ASN1_INTEGER_set(st, i, val) SKM_sk_set(ASN1_INTEGER, (st), (i), (val))
#define sk_ASN1_INTEGER_zero(st) SKM_sk_zero(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_push(st, val) SKM_sk_push(ASN1_INTEGER, (st), (val))
#define sk_ASN1_INTEGER_unshift(st, val) SKM_sk_unshift(ASN1_INTEGER, (st), (val))
#define sk_ASN1_INTEGER_find(st, val) SKM_sk_find(ASN1_INTEGER, (st), (val))
#define sk_ASN1_INTEGER_find_ex(st, val) SKM_sk_find_ex(ASN1_INTEGER, (st), (val))
#define sk_ASN1_INTEGER_delete(st, i) SKM_sk_delete(ASN1_INTEGER, (st), (i))
#define sk_ASN1_INTEGER_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_INTEGER, (st), (ptr))
#define sk_ASN1_INTEGER_insert(st, val, i) SKM_sk_insert(ASN1_INTEGER, (st), (val), (i))
#define sk_ASN1_INTEGER_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_INTEGER, (st), (cmp))
#define sk_ASN1_INTEGER_dup(st) SKM_sk_dup(ASN1_INTEGER, st)
#define sk_ASN1_INTEGER_pop_free(st, free_func) SKM_sk_pop_free(ASN1_INTEGER, (st), (free_func))
#define sk_ASN1_INTEGER_shift(st) SKM_sk_shift(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_pop(st) SKM_sk_pop(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_sort(st) SKM_sk_sort(ASN1_INTEGER, (st))
#define sk_ASN1_INTEGER_is_sorted(st) SKM_sk_is_sorted(ASN1_INTEGER, (st))

#define sk_ASN1_OBJECT_new(st) SKM_sk_new(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_new_null() SKM_sk_new_null(ASN1_OBJECT)
#define sk_ASN1_OBJECT_free(st) SKM_sk_free(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_num(st) SKM_sk_num(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_value(st, i) SKM_sk_value(ASN1_OBJECT, (st), (i))
#define sk_ASN1_OBJECT_set(st, i, val) SKM_sk_set(ASN1_OBJECT, (st), (i), (val))
#define sk_ASN1_OBJECT_zero(st) SKM_sk_zero(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_push(st, val) SKM_sk_push(ASN1_OBJECT, (st), (val))
#define sk_ASN1_OBJECT_unshift(st, val) SKM_sk_unshift(ASN1_OBJECT, (st), (val))
#define sk_ASN1_OBJECT_find(st, val) SKM_sk_find(ASN1_OBJECT, (st), (val))
#define sk_ASN1_OBJECT_find_ex(st, val) SKM_sk_find_ex(ASN1_OBJECT, (st), (val))
#define sk_ASN1_OBJECT_delete(st, i) SKM_sk_delete(ASN1_OBJECT, (st), (i))
#define sk_ASN1_OBJECT_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_OBJECT, (st), (ptr))
#define sk_ASN1_OBJECT_insert(st, val, i) SKM_sk_insert(ASN1_OBJECT, (st), (val), (i))
#define sk_ASN1_OBJECT_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_OBJECT, (st), (cmp))
#define sk_ASN1_OBJECT_dup(st) SKM_sk_dup(ASN1_OBJECT, st)
#define sk_ASN1_OBJECT_pop_free(st, free_func) SKM_sk_pop_free(ASN1_OBJECT, (st), (free_func))
#define sk_ASN1_OBJECT_shift(st) SKM_sk_shift(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_pop(st) SKM_sk_pop(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_sort(st) SKM_sk_sort(ASN1_OBJECT, (st))
#define sk_ASN1_OBJECT_is_sorted(st) SKM_sk_is_sorted(ASN1_OBJECT, (st))

#define sk_ASN1_STRING_TABLE_new(st) SKM_sk_new(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_new_null() SKM_sk_new_null(ASN1_STRING_TABLE)
#define sk_ASN1_STRING_TABLE_free(st) SKM_sk_free(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_num(st) SKM_sk_num(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_value(st, i) SKM_sk_value(ASN1_STRING_TABLE, (st), (i))
#define sk_ASN1_STRING_TABLE_set(st, i, val) SKM_sk_set(ASN1_STRING_TABLE, (st), (i), (val))
#define sk_ASN1_STRING_TABLE_zero(st) SKM_sk_zero(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_push(st, val) SKM_sk_push(ASN1_STRING_TABLE, (st), (val))
#define sk_ASN1_STRING_TABLE_unshift(st, val) SKM_sk_unshift(ASN1_STRING_TABLE, (st), (val))
#define sk_ASN1_STRING_TABLE_find(st, val) SKM_sk_find(ASN1_STRING_TABLE, (st), (val))
#define sk_ASN1_STRING_TABLE_find_ex(st, val) SKM_sk_find_ex(ASN1_STRING_TABLE, (st), (val))
#define sk_ASN1_STRING_TABLE_delete(st, i) SKM_sk_delete(ASN1_STRING_TABLE, (st), (i))
#define sk_ASN1_STRING_TABLE_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_STRING_TABLE, (st), (ptr))
#define sk_ASN1_STRING_TABLE_insert(st, val, i) SKM_sk_insert(ASN1_STRING_TABLE, (st), (val), (i))
#define sk_ASN1_STRING_TABLE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_STRING_TABLE, (st), (cmp))
#define sk_ASN1_STRING_TABLE_dup(st) SKM_sk_dup(ASN1_STRING_TABLE, st)
#define sk_ASN1_STRING_TABLE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_STRING_TABLE, (st), (free_func))
#define sk_ASN1_STRING_TABLE_shift(st) SKM_sk_shift(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_pop(st) SKM_sk_pop(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_sort(st) SKM_sk_sort(ASN1_STRING_TABLE, (st))
#define sk_ASN1_STRING_TABLE_is_sorted(st) SKM_sk_is_sorted(ASN1_STRING_TABLE, (st))

#define sk_ASN1_TYPE_new(st) SKM_sk_new(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_new_null() SKM_sk_new_null(ASN1_TYPE)
#define sk_ASN1_TYPE_free(st) SKM_sk_free(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_num(st) SKM_sk_num(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_value(st, i) SKM_sk_value(ASN1_TYPE, (st), (i))
#define sk_ASN1_TYPE_set(st, i, val) SKM_sk_set(ASN1_TYPE, (st), (i), (val))
#define sk_ASN1_TYPE_zero(st) SKM_sk_zero(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_push(st, val) SKM_sk_push(ASN1_TYPE, (st), (val))
#define sk_ASN1_TYPE_unshift(st, val) SKM_sk_unshift(ASN1_TYPE, (st), (val))
#define sk_ASN1_TYPE_find(st, val) SKM_sk_find(ASN1_TYPE, (st), (val))
#define sk_ASN1_TYPE_find_ex(st, val) SKM_sk_find_ex(ASN1_TYPE, (st), (val))
#define sk_ASN1_TYPE_delete(st, i) SKM_sk_delete(ASN1_TYPE, (st), (i))
#define sk_ASN1_TYPE_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_TYPE, (st), (ptr))
#define sk_ASN1_TYPE_insert(st, val, i) SKM_sk_insert(ASN1_TYPE, (st), (val), (i))
#define sk_ASN1_TYPE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_TYPE, (st), (cmp))
#define sk_ASN1_TYPE_dup(st) SKM_sk_dup(ASN1_TYPE, st)
#define sk_ASN1_TYPE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_TYPE, (st), (free_func))
#define sk_ASN1_TYPE_shift(st) SKM_sk_shift(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_pop(st) SKM_sk_pop(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_sort(st) SKM_sk_sort(ASN1_TYPE, (st))
#define sk_ASN1_TYPE_is_sorted(st) SKM_sk_is_sorted(ASN1_TYPE, (st))

#define sk_ASN1_VALUE_new(st) SKM_sk_new(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_new_null() SKM_sk_new_null(ASN1_VALUE)
#define sk_ASN1_VALUE_free(st) SKM_sk_free(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_num(st) SKM_sk_num(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_value(st, i) SKM_sk_value(ASN1_VALUE, (st), (i))
#define sk_ASN1_VALUE_set(st, i, val) SKM_sk_set(ASN1_VALUE, (st), (i), (val))
#define sk_ASN1_VALUE_zero(st) SKM_sk_zero(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_push(st, val) SKM_sk_push(ASN1_VALUE, (st), (val))
#define sk_ASN1_VALUE_unshift(st, val) SKM_sk_unshift(ASN1_VALUE, (st), (val))
#define sk_ASN1_VALUE_find(st, val) SKM_sk_find(ASN1_VALUE, (st), (val))
#define sk_ASN1_VALUE_find_ex(st, val) SKM_sk_find_ex(ASN1_VALUE, (st), (val))
#define sk_ASN1_VALUE_delete(st, i) SKM_sk_delete(ASN1_VALUE, (st), (i))
#define sk_ASN1_VALUE_delete_ptr(st, ptr) SKM_sk_delete_ptr(ASN1_VALUE, (st), (ptr))
#define sk_ASN1_VALUE_insert(st, val, i) SKM_sk_insert(ASN1_VALUE, (st), (val), (i))
#define sk_ASN1_VALUE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ASN1_VALUE, (st), (cmp))
#define sk_ASN1_VALUE_dup(st) SKM_sk_dup(ASN1_VALUE, st)
#define sk_ASN1_VALUE_pop_free(st, free_func) SKM_sk_pop_free(ASN1_VALUE, (st), (free_func))
#define sk_ASN1_VALUE_shift(st) SKM_sk_shift(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_pop(st) SKM_sk_pop(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_sort(st) SKM_sk_sort(ASN1_VALUE, (st))
#define sk_ASN1_VALUE_is_sorted(st) SKM_sk_is_sorted(ASN1_VALUE, (st))

#define sk_BIO_new(st) SKM_sk_new(BIO, (st))
#define sk_BIO_new_null() SKM_sk_new_null(BIO)
#define sk_BIO_free(st) SKM_sk_free(BIO, (st))
#define sk_BIO_num(st) SKM_sk_num(BIO, (st))
#define sk_BIO_value(st, i) SKM_sk_value(BIO, (st), (i))
#define sk_BIO_set(st, i, val) SKM_sk_set(BIO, (st), (i), (val))
#define sk_BIO_zero(st) SKM_sk_zero(BIO, (st))
#define sk_BIO_push(st, val) SKM_sk_push(BIO, (st), (val))
#define sk_BIO_unshift(st, val) SKM_sk_unshift(BIO, (st), (val))
#define sk_BIO_find(st, val) SKM_sk_find(BIO, (st), (val))
#define sk_BIO_find_ex(st, val) SKM_sk_find_ex(BIO, (st), (val))
#define sk_BIO_delete(st, i) SKM_sk_delete(BIO, (st), (i))
#define sk_BIO_delete_ptr(st, ptr) SKM_sk_delete_ptr(BIO, (st), (ptr))
#define sk_BIO_insert(st, val, i) SKM_sk_insert(BIO, (st), (val), (i))
#define sk_BIO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(BIO, (st), (cmp))
#define sk_BIO_dup(st) SKM_sk_dup(BIO, st)
#define sk_BIO_pop_free(st, free_func) SKM_sk_pop_free(BIO, (st), (free_func))
#define sk_BIO_shift(st) SKM_sk_shift(BIO, (st))
#define sk_BIO_pop(st) SKM_sk_pop(BIO, (st))
#define sk_BIO_sort(st) SKM_sk_sort(BIO, (st))
#define sk_BIO_is_sorted(st) SKM_sk_is_sorted(BIO, (st))

#define sk_CMS_CertificateChoices_new(st) SKM_sk_new(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_new_null() SKM_sk_new_null(CMS_CertificateChoices)
#define sk_CMS_CertificateChoices_free(st) SKM_sk_free(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_num(st) SKM_sk_num(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_value(st, i) SKM_sk_value(CMS_CertificateChoices, (st), (i))
#define sk_CMS_CertificateChoices_set(st, i, val) SKM_sk_set(CMS_CertificateChoices, (st), (i), (val))
#define sk_CMS_CertificateChoices_zero(st) SKM_sk_zero(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_push(st, val) SKM_sk_push(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_unshift(st, val) SKM_sk_unshift(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_find(st, val) SKM_sk_find(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_find_ex(st, val) SKM_sk_find_ex(CMS_CertificateChoices, (st), (val))
#define sk_CMS_CertificateChoices_delete(st, i) SKM_sk_delete(CMS_CertificateChoices, (st), (i))
#define sk_CMS_CertificateChoices_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_CertificateChoices, (st), (ptr))
#define sk_CMS_CertificateChoices_insert(st, val, i) SKM_sk_insert(CMS_CertificateChoices, (st), (val), (i))
#define sk_CMS_CertificateChoices_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_CertificateChoices, (st), (cmp))
#define sk_CMS_CertificateChoices_dup(st) SKM_sk_dup(CMS_CertificateChoices, st)
#define sk_CMS_CertificateChoices_pop_free(st, free_func) SKM_sk_pop_free(CMS_CertificateChoices, (st), (free_func))
#define sk_CMS_CertificateChoices_shift(st) SKM_sk_shift(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_pop(st) SKM_sk_pop(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_sort(st) SKM_sk_sort(CMS_CertificateChoices, (st))
#define sk_CMS_CertificateChoices_is_sorted(st) SKM_sk_is_sorted(CMS_CertificateChoices, (st))

#define sk_CMS_RecipientInfo_new(st) SKM_sk_new(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_new_null() SKM_sk_new_null(CMS_RecipientInfo)
#define sk_CMS_RecipientInfo_free(st) SKM_sk_free(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_num(st) SKM_sk_num(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_value(st, i) SKM_sk_value(CMS_RecipientInfo, (st), (i))
#define sk_CMS_RecipientInfo_set(st, i, val) SKM_sk_set(CMS_RecipientInfo, (st), (i), (val))
#define sk_CMS_RecipientInfo_zero(st) SKM_sk_zero(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_push(st, val) SKM_sk_push(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_unshift(st, val) SKM_sk_unshift(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_find(st, val) SKM_sk_find(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_find_ex(st, val) SKM_sk_find_ex(CMS_RecipientInfo, (st), (val))
#define sk_CMS_RecipientInfo_delete(st, i) SKM_sk_delete(CMS_RecipientInfo, (st), (i))
#define sk_CMS_RecipientInfo_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_RecipientInfo, (st), (ptr))
#define sk_CMS_RecipientInfo_insert(st, val, i) SKM_sk_insert(CMS_RecipientInfo, (st), (val), (i))
#define sk_CMS_RecipientInfo_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_RecipientInfo, (st), (cmp))
#define sk_CMS_RecipientInfo_dup(st) SKM_sk_dup(CMS_RecipientInfo, st)
#define sk_CMS_RecipientInfo_pop_free(st, free_func) SKM_sk_pop_free(CMS_RecipientInfo, (st), (free_func))
#define sk_CMS_RecipientInfo_shift(st) SKM_sk_shift(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_pop(st) SKM_sk_pop(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_sort(st) SKM_sk_sort(CMS_RecipientInfo, (st))
#define sk_CMS_RecipientInfo_is_sorted(st) SKM_sk_is_sorted(CMS_RecipientInfo, (st))

#define sk_CMS_RevocationInfoChoice_new(st) SKM_sk_new(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_new_null() SKM_sk_new_null(CMS_RevocationInfoChoice)
#define sk_CMS_RevocationInfoChoice_free(st) SKM_sk_free(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_num(st) SKM_sk_num(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_value(st, i) SKM_sk_value(CMS_RevocationInfoChoice, (st), (i))
#define sk_CMS_RevocationInfoChoice_set(st, i, val) SKM_sk_set(CMS_RevocationInfoChoice, (st), (i), (val))
#define sk_CMS_RevocationInfoChoice_zero(st) SKM_sk_zero(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_push(st, val) SKM_sk_push(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_unshift(st, val) SKM_sk_unshift(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_find(st, val) SKM_sk_find(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_find_ex(st, val) SKM_sk_find_ex(CMS_RevocationInfoChoice, (st), (val))
#define sk_CMS_RevocationInfoChoice_delete(st, i) SKM_sk_delete(CMS_RevocationInfoChoice, (st), (i))
#define sk_CMS_RevocationInfoChoice_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_RevocationInfoChoice, (st), (ptr))
#define sk_CMS_RevocationInfoChoice_insert(st, val, i) SKM_sk_insert(CMS_RevocationInfoChoice, (st), (val), (i))
#define sk_CMS_RevocationInfoChoice_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_RevocationInfoChoice, (st), (cmp))
#define sk_CMS_RevocationInfoChoice_dup(st) SKM_sk_dup(CMS_RevocationInfoChoice, st)
#define sk_CMS_RevocationInfoChoice_pop_free(st, free_func) SKM_sk_pop_free(CMS_RevocationInfoChoice, (st), (free_func))
#define sk_CMS_RevocationInfoChoice_shift(st) SKM_sk_shift(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_pop(st) SKM_sk_pop(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_sort(st) SKM_sk_sort(CMS_RevocationInfoChoice, (st))
#define sk_CMS_RevocationInfoChoice_is_sorted(st) SKM_sk_is_sorted(CMS_RevocationInfoChoice, (st))

#define sk_CMS_SignerInfo_new(st) SKM_sk_new(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_new_null() SKM_sk_new_null(CMS_SignerInfo)
#define sk_CMS_SignerInfo_free(st) SKM_sk_free(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_num(st) SKM_sk_num(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_value(st, i) SKM_sk_value(CMS_SignerInfo, (st), (i))
#define sk_CMS_SignerInfo_set(st, i, val) SKM_sk_set(CMS_SignerInfo, (st), (i), (val))
#define sk_CMS_SignerInfo_zero(st) SKM_sk_zero(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_push(st, val) SKM_sk_push(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_unshift(st, val) SKM_sk_unshift(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_find(st, val) SKM_sk_find(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_find_ex(st, val) SKM_sk_find_ex(CMS_SignerInfo, (st), (val))
#define sk_CMS_SignerInfo_delete(st, i) SKM_sk_delete(CMS_SignerInfo, (st), (i))
#define sk_CMS_SignerInfo_delete_ptr(st, ptr) SKM_sk_delete_ptr(CMS_SignerInfo, (st), (ptr))
#define sk_CMS_SignerInfo_insert(st, val, i) SKM_sk_insert(CMS_SignerInfo, (st), (val), (i))
#define sk_CMS_SignerInfo_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CMS_SignerInfo, (st), (cmp))
#define sk_CMS_SignerInfo_dup(st) SKM_sk_dup(CMS_SignerInfo, st)
#define sk_CMS_SignerInfo_pop_free(st, free_func) SKM_sk_pop_free(CMS_SignerInfo, (st), (free_func))
#define sk_CMS_SignerInfo_shift(st) SKM_sk_shift(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_pop(st) SKM_sk_pop(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_sort(st) SKM_sk_sort(CMS_SignerInfo, (st))
#define sk_CMS_SignerInfo_is_sorted(st) SKM_sk_is_sorted(CMS_SignerInfo, (st))

#define sk_CONF_IMODULE_new(st) SKM_sk_new(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_new_null() SKM_sk_new_null(CONF_IMODULE)
#define sk_CONF_IMODULE_free(st) SKM_sk_free(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_num(st) SKM_sk_num(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_value(st, i) SKM_sk_value(CONF_IMODULE, (st), (i))
#define sk_CONF_IMODULE_set(st, i, val) SKM_sk_set(CONF_IMODULE, (st), (i), (val))
#define sk_CONF_IMODULE_zero(st) SKM_sk_zero(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_push(st, val) SKM_sk_push(CONF_IMODULE, (st), (val))
#define sk_CONF_IMODULE_unshift(st, val) SKM_sk_unshift(CONF_IMODULE, (st), (val))
#define sk_CONF_IMODULE_find(st, val) SKM_sk_find(CONF_IMODULE, (st), (val))
#define sk_CONF_IMODULE_find_ex(st, val) SKM_sk_find_ex(CONF_IMODULE, (st), (val))
#define sk_CONF_IMODULE_delete(st, i) SKM_sk_delete(CONF_IMODULE, (st), (i))
#define sk_CONF_IMODULE_delete_ptr(st, ptr) SKM_sk_delete_ptr(CONF_IMODULE, (st), (ptr))
#define sk_CONF_IMODULE_insert(st, val, i) SKM_sk_insert(CONF_IMODULE, (st), (val), (i))
#define sk_CONF_IMODULE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CONF_IMODULE, (st), (cmp))
#define sk_CONF_IMODULE_dup(st) SKM_sk_dup(CONF_IMODULE, st)
#define sk_CONF_IMODULE_pop_free(st, free_func) SKM_sk_pop_free(CONF_IMODULE, (st), (free_func))
#define sk_CONF_IMODULE_shift(st) SKM_sk_shift(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_pop(st) SKM_sk_pop(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_sort(st) SKM_sk_sort(CONF_IMODULE, (st))
#define sk_CONF_IMODULE_is_sorted(st) SKM_sk_is_sorted(CONF_IMODULE, (st))

#define sk_CONF_MODULE_new(st) SKM_sk_new(CONF_MODULE, (st))
#define sk_CONF_MODULE_new_null() SKM_sk_new_null(CONF_MODULE)
#define sk_CONF_MODULE_free(st) SKM_sk_free(CONF_MODULE, (st))
#define sk_CONF_MODULE_num(st) SKM_sk_num(CONF_MODULE, (st))
#define sk_CONF_MODULE_value(st, i) SKM_sk_value(CONF_MODULE, (st), (i))
#define sk_CONF_MODULE_set(st, i, val) SKM_sk_set(CONF_MODULE, (st), (i), (val))
#define sk_CONF_MODULE_zero(st) SKM_sk_zero(CONF_MODULE, (st))
#define sk_CONF_MODULE_push(st, val) SKM_sk_push(CONF_MODULE, (st), (val))
#define sk_CONF_MODULE_unshift(st, val) SKM_sk_unshift(CONF_MODULE, (st), (val))
#define sk_CONF_MODULE_find(st, val) SKM_sk_find(CONF_MODULE, (st), (val))
#define sk_CONF_MODULE_find_ex(st, val) SKM_sk_find_ex(CONF_MODULE, (st), (val))
#define sk_CONF_MODULE_delete(st, i) SKM_sk_delete(CONF_MODULE, (st), (i))
#define sk_CONF_MODULE_delete_ptr(st, ptr) SKM_sk_delete_ptr(CONF_MODULE, (st), (ptr))
#define sk_CONF_MODULE_insert(st, val, i) SKM_sk_insert(CONF_MODULE, (st), (val), (i))
#define sk_CONF_MODULE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CONF_MODULE, (st), (cmp))
#define sk_CONF_MODULE_dup(st) SKM_sk_dup(CONF_MODULE, st)
#define sk_CONF_MODULE_pop_free(st, free_func) SKM_sk_pop_free(CONF_MODULE, (st), (free_func))
#define sk_CONF_MODULE_shift(st) SKM_sk_shift(CONF_MODULE, (st))
#define sk_CONF_MODULE_pop(st) SKM_sk_pop(CONF_MODULE, (st))
#define sk_CONF_MODULE_sort(st) SKM_sk_sort(CONF_MODULE, (st))
#define sk_CONF_MODULE_is_sorted(st) SKM_sk_is_sorted(CONF_MODULE, (st))

#define sk_CONF_VALUE_new(st) SKM_sk_new(CONF_VALUE, (st))
#define sk_CONF_VALUE_new_null() SKM_sk_new_null(CONF_VALUE)
#define sk_CONF_VALUE_free(st) SKM_sk_free(CONF_VALUE, (st))
#define sk_CONF_VALUE_num(st) SKM_sk_num(CONF_VALUE, (st))
#define sk_CONF_VALUE_value(st, i) SKM_sk_value(CONF_VALUE, (st), (i))
#define sk_CONF_VALUE_set(st, i, val) SKM_sk_set(CONF_VALUE, (st), (i), (val))
#define sk_CONF_VALUE_zero(st) SKM_sk_zero(CONF_VALUE, (st))
#define sk_CONF_VALUE_push(st, val) SKM_sk_push(CONF_VALUE, (st), (val))
#define sk_CONF_VALUE_unshift(st, val) SKM_sk_unshift(CONF_VALUE, (st), (val))
#define sk_CONF_VALUE_find(st, val) SKM_sk_find(CONF_VALUE, (st), (val))
#define sk_CONF_VALUE_find_ex(st, val) SKM_sk_find_ex(CONF_VALUE, (st), (val))
#define sk_CONF_VALUE_delete(st, i) SKM_sk_delete(CONF_VALUE, (st), (i))
#define sk_CONF_VALUE_delete_ptr(st, ptr) SKM_sk_delete_ptr(CONF_VALUE, (st), (ptr))
#define sk_CONF_VALUE_insert(st, val, i) SKM_sk_insert(CONF_VALUE, (st), (val), (i))
#define sk_CONF_VALUE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CONF_VALUE, (st), (cmp))
#define sk_CONF_VALUE_dup(st) SKM_sk_dup(CONF_VALUE, st)
#define sk_CONF_VALUE_pop_free(st, free_func) SKM_sk_pop_free(CONF_VALUE, (st), (free_func))
#define sk_CONF_VALUE_shift(st) SKM_sk_shift(CONF_VALUE, (st))
#define sk_CONF_VALUE_pop(st) SKM_sk_pop(CONF_VALUE, (st))
#define sk_CONF_VALUE_sort(st) SKM_sk_sort(CONF_VALUE, (st))
#define sk_CONF_VALUE_is_sorted(st) SKM_sk_is_sorted(CONF_VALUE, (st))

#define sk_CRYPTO_EX_DATA_FUNCS_new(st) SKM_sk_new(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_new_null() SKM_sk_new_null(CRYPTO_EX_DATA_FUNCS)
#define sk_CRYPTO_EX_DATA_FUNCS_free(st) SKM_sk_free(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_num(st) SKM_sk_num(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_value(st, i) SKM_sk_value(CRYPTO_EX_DATA_FUNCS, (st), (i))
#define sk_CRYPTO_EX_DATA_FUNCS_set(st, i, val) SKM_sk_set(CRYPTO_EX_DATA_FUNCS, (st), (i), (val))
#define sk_CRYPTO_EX_DATA_FUNCS_zero(st) SKM_sk_zero(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_push(st, val) SKM_sk_push(CRYPTO_EX_DATA_FUNCS, (st), (val))
#define sk_CRYPTO_EX_DATA_FUNCS_unshift(st, val) SKM_sk_unshift(CRYPTO_EX_DATA_FUNCS, (st), (val))
#define sk_CRYPTO_EX_DATA_FUNCS_find(st, val) SKM_sk_find(CRYPTO_EX_DATA_FUNCS, (st), (val))
#define sk_CRYPTO_EX_DATA_FUNCS_find_ex(st, val) SKM_sk_find_ex(CRYPTO_EX_DATA_FUNCS, (st), (val))
#define sk_CRYPTO_EX_DATA_FUNCS_delete(st, i) SKM_sk_delete(CRYPTO_EX_DATA_FUNCS, (st), (i))
#define sk_CRYPTO_EX_DATA_FUNCS_delete_ptr(st, ptr) SKM_sk_delete_ptr(CRYPTO_EX_DATA_FUNCS, (st), (ptr))
#define sk_CRYPTO_EX_DATA_FUNCS_insert(st, val, i) SKM_sk_insert(CRYPTO_EX_DATA_FUNCS, (st), (val), (i))
#define sk_CRYPTO_EX_DATA_FUNCS_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CRYPTO_EX_DATA_FUNCS, (st), (cmp))
#define sk_CRYPTO_EX_DATA_FUNCS_dup(st) SKM_sk_dup(CRYPTO_EX_DATA_FUNCS, st)
#define sk_CRYPTO_EX_DATA_FUNCS_pop_free(st, free_func) SKM_sk_pop_free(CRYPTO_EX_DATA_FUNCS, (st), (free_func))
#define sk_CRYPTO_EX_DATA_FUNCS_shift(st) SKM_sk_shift(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_pop(st) SKM_sk_pop(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_sort(st) SKM_sk_sort(CRYPTO_EX_DATA_FUNCS, (st))
#define sk_CRYPTO_EX_DATA_FUNCS_is_sorted(st) SKM_sk_is_sorted(CRYPTO_EX_DATA_FUNCS, (st))

#define sk_CRYPTO_dynlock_new(st) SKM_sk_new(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_new_null() SKM_sk_new_null(CRYPTO_dynlock)
#define sk_CRYPTO_dynlock_free(st) SKM_sk_free(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_num(st) SKM_sk_num(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_value(st, i) SKM_sk_value(CRYPTO_dynlock, (st), (i))
#define sk_CRYPTO_dynlock_set(st, i, val) SKM_sk_set(CRYPTO_dynlock, (st), (i), (val))
#define sk_CRYPTO_dynlock_zero(st) SKM_sk_zero(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_push(st, val) SKM_sk_push(CRYPTO_dynlock, (st), (val))
#define sk_CRYPTO_dynlock_unshift(st, val) SKM_sk_unshift(CRYPTO_dynlock, (st), (val))
#define sk_CRYPTO_dynlock_find(st, val) SKM_sk_find(CRYPTO_dynlock, (st), (val))
#define sk_CRYPTO_dynlock_find_ex(st, val) SKM_sk_find_ex(CRYPTO_dynlock, (st), (val))
#define sk_CRYPTO_dynlock_delete(st, i) SKM_sk_delete(CRYPTO_dynlock, (st), (i))
#define sk_CRYPTO_dynlock_delete_ptr(st, ptr) SKM_sk_delete_ptr(CRYPTO_dynlock, (st), (ptr))
#define sk_CRYPTO_dynlock_insert(st, val, i) SKM_sk_insert(CRYPTO_dynlock, (st), (val), (i))
#define sk_CRYPTO_dynlock_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(CRYPTO_dynlock, (st), (cmp))
#define sk_CRYPTO_dynlock_dup(st) SKM_sk_dup(CRYPTO_dynlock, st)
#define sk_CRYPTO_dynlock_pop_free(st, free_func) SKM_sk_pop_free(CRYPTO_dynlock, (st), (free_func))
#define sk_CRYPTO_dynlock_shift(st) SKM_sk_shift(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_pop(st) SKM_sk_pop(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_sort(st) SKM_sk_sort(CRYPTO_dynlock, (st))
#define sk_CRYPTO_dynlock_is_sorted(st) SKM_sk_is_sorted(CRYPTO_dynlock, (st))

#define sk_DIST_POINT_new(st) SKM_sk_new(DIST_POINT, (st))
#define sk_DIST_POINT_new_null() SKM_sk_new_null(DIST_POINT)
#define sk_DIST_POINT_free(st) SKM_sk_free(DIST_POINT, (st))
#define sk_DIST_POINT_num(st) SKM_sk_num(DIST_POINT, (st))
#define sk_DIST_POINT_value(st, i) SKM_sk_value(DIST_POINT, (st), (i))
#define sk_DIST_POINT_set(st, i, val) SKM_sk_set(DIST_POINT, (st), (i), (val))
#define sk_DIST_POINT_zero(st) SKM_sk_zero(DIST_POINT, (st))
#define sk_DIST_POINT_push(st, val) SKM_sk_push(DIST_POINT, (st), (val))
#define sk_DIST_POINT_unshift(st, val) SKM_sk_unshift(DIST_POINT, (st), (val))
#define sk_DIST_POINT_find(st, val) SKM_sk_find(DIST_POINT, (st), (val))
#define sk_DIST_POINT_find_ex(st, val) SKM_sk_find_ex(DIST_POINT, (st), (val))
#define sk_DIST_POINT_delete(st, i) SKM_sk_delete(DIST_POINT, (st), (i))
#define sk_DIST_POINT_delete_ptr(st, ptr) SKM_sk_delete_ptr(DIST_POINT, (st), (ptr))
#define sk_DIST_POINT_insert(st, val, i) SKM_sk_insert(DIST_POINT, (st), (val), (i))
#define sk_DIST_POINT_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(DIST_POINT, (st), (cmp))
#define sk_DIST_POINT_dup(st) SKM_sk_dup(DIST_POINT, st)
#define sk_DIST_POINT_pop_free(st, free_func) SKM_sk_pop_free(DIST_POINT, (st), (free_func))
#define sk_DIST_POINT_shift(st) SKM_sk_shift(DIST_POINT, (st))
#define sk_DIST_POINT_pop(st) SKM_sk_pop(DIST_POINT, (st))
#define sk_DIST_POINT_sort(st) SKM_sk_sort(DIST_POINT, (st))
#define sk_DIST_POINT_is_sorted(st) SKM_sk_is_sorted(DIST_POINT, (st))

#define sk_ENGINE_new(st) SKM_sk_new(ENGINE, (st))
#define sk_ENGINE_new_null() SKM_sk_new_null(ENGINE)
#define sk_ENGINE_free(st) SKM_sk_free(ENGINE, (st))
#define sk_ENGINE_num(st) SKM_sk_num(ENGINE, (st))
#define sk_ENGINE_value(st, i) SKM_sk_value(ENGINE, (st), (i))
#define sk_ENGINE_set(st, i, val) SKM_sk_set(ENGINE, (st), (i), (val))
#define sk_ENGINE_zero(st) SKM_sk_zero(ENGINE, (st))
#define sk_ENGINE_push(st, val) SKM_sk_push(ENGINE, (st), (val))
#define sk_ENGINE_unshift(st, val) SKM_sk_unshift(ENGINE, (st), (val))
#define sk_ENGINE_find(st, val) SKM_sk_find(ENGINE, (st), (val))
#define sk_ENGINE_find_ex(st, val) SKM_sk_find_ex(ENGINE, (st), (val))
#define sk_ENGINE_delete(st, i) SKM_sk_delete(ENGINE, (st), (i))
#define sk_ENGINE_delete_ptr(st, ptr) SKM_sk_delete_ptr(ENGINE, (st), (ptr))
#define sk_ENGINE_insert(st, val, i) SKM_sk_insert(ENGINE, (st), (val), (i))
#define sk_ENGINE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ENGINE, (st), (cmp))
#define sk_ENGINE_dup(st) SKM_sk_dup(ENGINE, st)
#define sk_ENGINE_pop_free(st, free_func) SKM_sk_pop_free(ENGINE, (st), (free_func))
#define sk_ENGINE_shift(st) SKM_sk_shift(ENGINE, (st))
#define sk_ENGINE_pop(st) SKM_sk_pop(ENGINE, (st))
#define sk_ENGINE_sort(st) SKM_sk_sort(ENGINE, (st))
#define sk_ENGINE_is_sorted(st) SKM_sk_is_sorted(ENGINE, (st))

#define sk_ENGINE_CLEANUP_ITEM_new(st) SKM_sk_new(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_new_null() SKM_sk_new_null(ENGINE_CLEANUP_ITEM)
#define sk_ENGINE_CLEANUP_ITEM_free(st) SKM_sk_free(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_num(st) SKM_sk_num(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_value(st, i) SKM_sk_value(ENGINE_CLEANUP_ITEM, (st), (i))
#define sk_ENGINE_CLEANUP_ITEM_set(st, i, val) SKM_sk_set(ENGINE_CLEANUP_ITEM, (st), (i), (val))
#define sk_ENGINE_CLEANUP_ITEM_zero(st) SKM_sk_zero(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_push(st, val) SKM_sk_push(ENGINE_CLEANUP_ITEM, (st), (val))
#define sk_ENGINE_CLEANUP_ITEM_unshift(st, val) SKM_sk_unshift(ENGINE_CLEANUP_ITEM, (st), (val))
#define sk_ENGINE_CLEANUP_ITEM_find(st, val) SKM_sk_find(ENGINE_CLEANUP_ITEM, (st), (val))
#define sk_ENGINE_CLEANUP_ITEM_find_ex(st, val) SKM_sk_find_ex(ENGINE_CLEANUP_ITEM, (st), (val))
#define sk_ENGINE_CLEANUP_ITEM_delete(st, i) SKM_sk_delete(ENGINE_CLEANUP_ITEM, (st), (i))
#define sk_ENGINE_CLEANUP_ITEM_delete_ptr(st, ptr) SKM_sk_delete_ptr(ENGINE_CLEANUP_ITEM, (st), (ptr))
#define sk_ENGINE_CLEANUP_ITEM_insert(st, val, i) SKM_sk_insert(ENGINE_CLEANUP_ITEM, (st), (val), (i))
#define sk_ENGINE_CLEANUP_ITEM_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(ENGINE_CLEANUP_ITEM, (st), (cmp))
#define sk_ENGINE_CLEANUP_ITEM_dup(st) SKM_sk_dup(ENGINE_CLEANUP_ITEM, st)
#define sk_ENGINE_CLEANUP_ITEM_pop_free(st, free_func) SKM_sk_pop_free(ENGINE_CLEANUP_ITEM, (st), (free_func))
#define sk_ENGINE_CLEANUP_ITEM_shift(st) SKM_sk_shift(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_pop(st) SKM_sk_pop(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_sort(st) SKM_sk_sort(ENGINE_CLEANUP_ITEM, (st))
#define sk_ENGINE_CLEANUP_ITEM_is_sorted(st) SKM_sk_is_sorted(ENGINE_CLEANUP_ITEM, (st))

#define sk_GENERAL_NAME_new(st) SKM_sk_new(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_new_null() SKM_sk_new_null(GENERAL_NAME)
#define sk_GENERAL_NAME_free(st) SKM_sk_free(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_num(st) SKM_sk_num(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_value(st, i) SKM_sk_value(GENERAL_NAME, (st), (i))
#define sk_GENERAL_NAME_set(st, i, val) SKM_sk_set(GENERAL_NAME, (st), (i), (val))
#define sk_GENERAL_NAME_zero(st) SKM_sk_zero(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_push(st, val) SKM_sk_push(GENERAL_NAME, (st), (val))
#define sk_GENERAL_NAME_unshift(st, val) SKM_sk_unshift(GENERAL_NAME, (st), (val))
#define sk_GENERAL_NAME_find(st, val) SKM_sk_find(GENERAL_NAME, (st), (val))
#define sk_GENERAL_NAME_find_ex(st, val) SKM_sk_find_ex(GENERAL_NAME, (st), (val))
#define sk_GENERAL_NAME_delete(st, i) SKM_sk_delete(GENERAL_NAME, (st), (i))
#define sk_GENERAL_NAME_delete_ptr(st, ptr) SKM_sk_delete_ptr(GENERAL_NAME, (st), (ptr))
#define sk_GENERAL_NAME_insert(st, val, i) SKM_sk_insert(GENERAL_NAME, (st), (val), (i))
#define sk_GENERAL_NAME_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(GENERAL_NAME, (st), (cmp))
#define sk_GENERAL_NAME_dup(st) SKM_sk_dup(GENERAL_NAME, st)
#define sk_GENERAL_NAME_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_NAME, (st), (free_func))
#define sk_GENERAL_NAME_shift(st) SKM_sk_shift(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_pop(st) SKM_sk_pop(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_sort(st) SKM_sk_sort(GENERAL_NAME, (st))
#define sk_GENERAL_NAME_is_sorted(st) SKM_sk_is_sorted(GENERAL_NAME, (st))

#define sk_GENERAL_NAMES_new(st) SKM_sk_new(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_new_null() SKM_sk_new_null(GENERAL_NAMES)
#define sk_GENERAL_NAMES_free(st) SKM_sk_free(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_num(st) SKM_sk_num(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_value(st, i) SKM_sk_value(GENERAL_NAMES, (st), (i))
#define sk_GENERAL_NAMES_set(st, i, val) SKM_sk_set(GENERAL_NAMES, (st), (i), (val))
#define sk_GENERAL_NAMES_zero(st) SKM_sk_zero(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_push(st, val) SKM_sk_push(GENERAL_NAMES, (st), (val))
#define sk_GENERAL_NAMES_unshift(st, val) SKM_sk_unshift(GENERAL_NAMES, (st), (val))
#define sk_GENERAL_NAMES_find(st, val) SKM_sk_find(GENERAL_NAMES, (st), (val))
#define sk_GENERAL_NAMES_find_ex(st, val) SKM_sk_find_ex(GENERAL_NAMES, (st), (val))
#define sk_GENERAL_NAMES_delete(st, i) SKM_sk_delete(GENERAL_NAMES, (st), (i))
#define sk_GENERAL_NAMES_delete_ptr(st, ptr) SKM_sk_delete_ptr(GENERAL_NAMES, (st), (ptr))
#define sk_GENERAL_NAMES_insert(st, val, i) SKM_sk_insert(GENERAL_NAMES, (st), (val), (i))
#define sk_GENERAL_NAMES_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(GENERAL_NAMES, (st), (cmp))
#define sk_GENERAL_NAMES_dup(st) SKM_sk_dup(GENERAL_NAMES, st)
#define sk_GENERAL_NAMES_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_NAMES, (st), (free_func))
#define sk_GENERAL_NAMES_shift(st) SKM_sk_shift(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_pop(st) SKM_sk_pop(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_sort(st) SKM_sk_sort(GENERAL_NAMES, (st))
#define sk_GENERAL_NAMES_is_sorted(st) SKM_sk_is_sorted(GENERAL_NAMES, (st))

#define sk_GENERAL_SUBTREE_new(st) SKM_sk_new(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_new_null() SKM_sk_new_null(GENERAL_SUBTREE)
#define sk_GENERAL_SUBTREE_free(st) SKM_sk_free(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_num(st) SKM_sk_num(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_value(st, i) SKM_sk_value(GENERAL_SUBTREE, (st), (i))
#define sk_GENERAL_SUBTREE_set(st, i, val) SKM_sk_set(GENERAL_SUBTREE, (st), (i), (val))
#define sk_GENERAL_SUBTREE_zero(st) SKM_sk_zero(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_push(st, val) SKM_sk_push(GENERAL_SUBTREE, (st), (val))
#define sk_GENERAL_SUBTREE_unshift(st, val) SKM_sk_unshift(GENERAL_SUBTREE, (st), (val))
#define sk_GENERAL_SUBTREE_find(st, val) SKM_sk_find(GENERAL_SUBTREE, (st), (val))
#define sk_GENERAL_SUBTREE_find_ex(st, val) SKM_sk_find_ex(GENERAL_SUBTREE, (st), (val))
#define sk_GENERAL_SUBTREE_delete(st, i) SKM_sk_delete(GENERAL_SUBTREE, (st), (i))
#define sk_GENERAL_SUBTREE_delete_ptr(st, ptr) SKM_sk_delete_ptr(GENERAL_SUBTREE, (st), (ptr))
#define sk_GENERAL_SUBTREE_insert(st, val, i) SKM_sk_insert(GENERAL_SUBTREE, (st), (val), (i))
#define sk_GENERAL_SUBTREE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(GENERAL_SUBTREE, (st), (cmp))
#define sk_GENERAL_SUBTREE_dup(st) SKM_sk_dup(GENERAL_SUBTREE, st)
#define sk_GENERAL_SUBTREE_pop_free(st, free_func) SKM_sk_pop_free(GENERAL_SUBTREE, (st), (free_func))
#define sk_GENERAL_SUBTREE_shift(st) SKM_sk_shift(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_pop(st) SKM_sk_pop(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_sort(st) SKM_sk_sort(GENERAL_SUBTREE, (st))
#define sk_GENERAL_SUBTREE_is_sorted(st) SKM_sk_is_sorted(GENERAL_SUBTREE, (st))

#define sk_IPAddressFamily_new(st) SKM_sk_new(IPAddressFamily, (st))
#define sk_IPAddressFamily_new_null() SKM_sk_new_null(IPAddressFamily)
#define sk_IPAddressFamily_free(st) SKM_sk_free(IPAddressFamily, (st))
#define sk_IPAddressFamily_num(st) SKM_sk_num(IPAddressFamily, (st))
#define sk_IPAddressFamily_value(st, i) SKM_sk_value(IPAddressFamily, (st), (i))
#define sk_IPAddressFamily_set(st, i, val) SKM_sk_set(IPAddressFamily, (st), (i), (val))
#define sk_IPAddressFamily_zero(st) SKM_sk_zero(IPAddressFamily, (st))
#define sk_IPAddressFamily_push(st, val) SKM_sk_push(IPAddressFamily, (st), (val))
#define sk_IPAddressFamily_unshift(st, val) SKM_sk_unshift(IPAddressFamily, (st), (val))
#define sk_IPAddressFamily_find(st, val) SKM_sk_find(IPAddressFamily, (st), (val))
#define sk_IPAddressFamily_find_ex(st, val) SKM_sk_find_ex(IPAddressFamily, (st), (val))
#define sk_IPAddressFamily_delete(st, i) SKM_sk_delete(IPAddressFamily, (st), (i))
#define sk_IPAddressFamily_delete_ptr(st, ptr) SKM_sk_delete_ptr(IPAddressFamily, (st), (ptr))
#define sk_IPAddressFamily_insert(st, val, i) SKM_sk_insert(IPAddressFamily, (st), (val), (i))
#define sk_IPAddressFamily_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(IPAddressFamily, (st), (cmp))
#define sk_IPAddressFamily_dup(st) SKM_sk_dup(IPAddressFamily, st)
#define sk_IPAddressFamily_pop_free(st, free_func) SKM_sk_pop_free(IPAddressFamily, (st), (free_func))
#define sk_IPAddressFamily_shift(st) SKM_sk_shift(IPAddressFamily, (st))
#define sk_IPAddressFamily_pop(st) SKM_sk_pop(IPAddressFamily, (st))
#define sk_IPAddressFamily_sort(st) SKM_sk_sort(IPAddressFamily, (st))
#define sk_IPAddressFamily_is_sorted(st) SKM_sk_is_sorted(IPAddressFamily, (st))

#define sk_IPAddressOrRange_new(st) SKM_sk_new(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_new_null() SKM_sk_new_null(IPAddressOrRange)
#define sk_IPAddressOrRange_free(st) SKM_sk_free(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_num(st) SKM_sk_num(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_value(st, i) SKM_sk_value(IPAddressOrRange, (st), (i))
#define sk_IPAddressOrRange_set(st, i, val) SKM_sk_set(IPAddressOrRange, (st), (i), (val))
#define sk_IPAddressOrRange_zero(st) SKM_sk_zero(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_push(st, val) SKM_sk_push(IPAddressOrRange, (st), (val))
#define sk_IPAddressOrRange_unshift(st, val) SKM_sk_unshift(IPAddressOrRange, (st), (val))
#define sk_IPAddressOrRange_find(st, val) SKM_sk_find(IPAddressOrRange, (st), (val))
#define sk_IPAddressOrRange_find_ex(st, val) SKM_sk_find_ex(IPAddressOrRange, (st), (val))
#define sk_IPAddressOrRange_delete(st, i) SKM_sk_delete(IPAddressOrRange, (st), (i))
#define sk_IPAddressOrRange_delete_ptr(st, ptr) SKM_sk_delete_ptr(IPAddressOrRange, (st), (ptr))
#define sk_IPAddressOrRange_insert(st, val, i) SKM_sk_insert(IPAddressOrRange, (st), (val), (i))
#define sk_IPAddressOrRange_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(IPAddressOrRange, (st), (cmp))
#define sk_IPAddressOrRange_dup(st) SKM_sk_dup(IPAddressOrRange, st)
#define sk_IPAddressOrRange_pop_free(st, free_func) SKM_sk_pop_free(IPAddressOrRange, (st), (free_func))
#define sk_IPAddressOrRange_shift(st) SKM_sk_shift(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_pop(st) SKM_sk_pop(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_sort(st) SKM_sk_sort(IPAddressOrRange, (st))
#define sk_IPAddressOrRange_is_sorted(st) SKM_sk_is_sorted(IPAddressOrRange, (st))

#define sk_KRB5_APREQBODY_new(st) SKM_sk_new(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_new_null() SKM_sk_new_null(KRB5_APREQBODY)
#define sk_KRB5_APREQBODY_free(st) SKM_sk_free(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_num(st) SKM_sk_num(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_value(st, i) SKM_sk_value(KRB5_APREQBODY, (st), (i))
#define sk_KRB5_APREQBODY_set(st, i, val) SKM_sk_set(KRB5_APREQBODY, (st), (i), (val))
#define sk_KRB5_APREQBODY_zero(st) SKM_sk_zero(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_push(st, val) SKM_sk_push(KRB5_APREQBODY, (st), (val))
#define sk_KRB5_APREQBODY_unshift(st, val) SKM_sk_unshift(KRB5_APREQBODY, (st), (val))
#define sk_KRB5_APREQBODY_find(st, val) SKM_sk_find(KRB5_APREQBODY, (st), (val))
#define sk_KRB5_APREQBODY_find_ex(st, val) SKM_sk_find_ex(KRB5_APREQBODY, (st), (val))
#define sk_KRB5_APREQBODY_delete(st, i) SKM_sk_delete(KRB5_APREQBODY, (st), (i))
#define sk_KRB5_APREQBODY_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_APREQBODY, (st), (ptr))
#define sk_KRB5_APREQBODY_insert(st, val, i) SKM_sk_insert(KRB5_APREQBODY, (st), (val), (i))
#define sk_KRB5_APREQBODY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_APREQBODY, (st), (cmp))
#define sk_KRB5_APREQBODY_dup(st) SKM_sk_dup(KRB5_APREQBODY, st)
#define sk_KRB5_APREQBODY_pop_free(st, free_func) SKM_sk_pop_free(KRB5_APREQBODY, (st), (free_func))
#define sk_KRB5_APREQBODY_shift(st) SKM_sk_shift(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_pop(st) SKM_sk_pop(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_sort(st) SKM_sk_sort(KRB5_APREQBODY, (st))
#define sk_KRB5_APREQBODY_is_sorted(st) SKM_sk_is_sorted(KRB5_APREQBODY, (st))

#define sk_KRB5_AUTHDATA_new(st) SKM_sk_new(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_new_null() SKM_sk_new_null(KRB5_AUTHDATA)
#define sk_KRB5_AUTHDATA_free(st) SKM_sk_free(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_num(st) SKM_sk_num(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_value(st, i) SKM_sk_value(KRB5_AUTHDATA, (st), (i))
#define sk_KRB5_AUTHDATA_set(st, i, val) SKM_sk_set(KRB5_AUTHDATA, (st), (i), (val))
#define sk_KRB5_AUTHDATA_zero(st) SKM_sk_zero(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_push(st, val) SKM_sk_push(KRB5_AUTHDATA, (st), (val))
#define sk_KRB5_AUTHDATA_unshift(st, val) SKM_sk_unshift(KRB5_AUTHDATA, (st), (val))
#define sk_KRB5_AUTHDATA_find(st, val) SKM_sk_find(KRB5_AUTHDATA, (st), (val))
#define sk_KRB5_AUTHDATA_find_ex(st, val) SKM_sk_find_ex(KRB5_AUTHDATA, (st), (val))
#define sk_KRB5_AUTHDATA_delete(st, i) SKM_sk_delete(KRB5_AUTHDATA, (st), (i))
#define sk_KRB5_AUTHDATA_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_AUTHDATA, (st), (ptr))
#define sk_KRB5_AUTHDATA_insert(st, val, i) SKM_sk_insert(KRB5_AUTHDATA, (st), (val), (i))
#define sk_KRB5_AUTHDATA_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_AUTHDATA, (st), (cmp))
#define sk_KRB5_AUTHDATA_dup(st) SKM_sk_dup(KRB5_AUTHDATA, st)
#define sk_KRB5_AUTHDATA_pop_free(st, free_func) SKM_sk_pop_free(KRB5_AUTHDATA, (st), (free_func))
#define sk_KRB5_AUTHDATA_shift(st) SKM_sk_shift(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_pop(st) SKM_sk_pop(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_sort(st) SKM_sk_sort(KRB5_AUTHDATA, (st))
#define sk_KRB5_AUTHDATA_is_sorted(st) SKM_sk_is_sorted(KRB5_AUTHDATA, (st))

#define sk_KRB5_AUTHENTBODY_new(st) SKM_sk_new(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_new_null() SKM_sk_new_null(KRB5_AUTHENTBODY)
#define sk_KRB5_AUTHENTBODY_free(st) SKM_sk_free(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_num(st) SKM_sk_num(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_value(st, i) SKM_sk_value(KRB5_AUTHENTBODY, (st), (i))
#define sk_KRB5_AUTHENTBODY_set(st, i, val) SKM_sk_set(KRB5_AUTHENTBODY, (st), (i), (val))
#define sk_KRB5_AUTHENTBODY_zero(st) SKM_sk_zero(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_push(st, val) SKM_sk_push(KRB5_AUTHENTBODY, (st), (val))
#define sk_KRB5_AUTHENTBODY_unshift(st, val) SKM_sk_unshift(KRB5_AUTHENTBODY, (st), (val))
#define sk_KRB5_AUTHENTBODY_find(st, val) SKM_sk_find(KRB5_AUTHENTBODY, (st), (val))
#define sk_KRB5_AUTHENTBODY_find_ex(st, val) SKM_sk_find_ex(KRB5_AUTHENTBODY, (st), (val))
#define sk_KRB5_AUTHENTBODY_delete(st, i) SKM_sk_delete(KRB5_AUTHENTBODY, (st), (i))
#define sk_KRB5_AUTHENTBODY_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_AUTHENTBODY, (st), (ptr))
#define sk_KRB5_AUTHENTBODY_insert(st, val, i) SKM_sk_insert(KRB5_AUTHENTBODY, (st), (val), (i))
#define sk_KRB5_AUTHENTBODY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_AUTHENTBODY, (st), (cmp))
#define sk_KRB5_AUTHENTBODY_dup(st) SKM_sk_dup(KRB5_AUTHENTBODY, st)
#define sk_KRB5_AUTHENTBODY_pop_free(st, free_func) SKM_sk_pop_free(KRB5_AUTHENTBODY, (st), (free_func))
#define sk_KRB5_AUTHENTBODY_shift(st) SKM_sk_shift(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_pop(st) SKM_sk_pop(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_sort(st) SKM_sk_sort(KRB5_AUTHENTBODY, (st))
#define sk_KRB5_AUTHENTBODY_is_sorted(st) SKM_sk_is_sorted(KRB5_AUTHENTBODY, (st))

#define sk_KRB5_CHECKSUM_new(st) SKM_sk_new(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_new_null() SKM_sk_new_null(KRB5_CHECKSUM)
#define sk_KRB5_CHECKSUM_free(st) SKM_sk_free(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_num(st) SKM_sk_num(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_value(st, i) SKM_sk_value(KRB5_CHECKSUM, (st), (i))
#define sk_KRB5_CHECKSUM_set(st, i, val) SKM_sk_set(KRB5_CHECKSUM, (st), (i), (val))
#define sk_KRB5_CHECKSUM_zero(st) SKM_sk_zero(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_push(st, val) SKM_sk_push(KRB5_CHECKSUM, (st), (val))
#define sk_KRB5_CHECKSUM_unshift(st, val) SKM_sk_unshift(KRB5_CHECKSUM, (st), (val))
#define sk_KRB5_CHECKSUM_find(st, val) SKM_sk_find(KRB5_CHECKSUM, (st), (val))
#define sk_KRB5_CHECKSUM_find_ex(st, val) SKM_sk_find_ex(KRB5_CHECKSUM, (st), (val))
#define sk_KRB5_CHECKSUM_delete(st, i) SKM_sk_delete(KRB5_CHECKSUM, (st), (i))
#define sk_KRB5_CHECKSUM_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_CHECKSUM, (st), (ptr))
#define sk_KRB5_CHECKSUM_insert(st, val, i) SKM_sk_insert(KRB5_CHECKSUM, (st), (val), (i))
#define sk_KRB5_CHECKSUM_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_CHECKSUM, (st), (cmp))
#define sk_KRB5_CHECKSUM_dup(st) SKM_sk_dup(KRB5_CHECKSUM, st)
#define sk_KRB5_CHECKSUM_pop_free(st, free_func) SKM_sk_pop_free(KRB5_CHECKSUM, (st), (free_func))
#define sk_KRB5_CHECKSUM_shift(st) SKM_sk_shift(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_pop(st) SKM_sk_pop(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_sort(st) SKM_sk_sort(KRB5_CHECKSUM, (st))
#define sk_KRB5_CHECKSUM_is_sorted(st) SKM_sk_is_sorted(KRB5_CHECKSUM, (st))

#define sk_KRB5_ENCDATA_new(st) SKM_sk_new(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_new_null() SKM_sk_new_null(KRB5_ENCDATA)
#define sk_KRB5_ENCDATA_free(st) SKM_sk_free(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_num(st) SKM_sk_num(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_value(st, i) SKM_sk_value(KRB5_ENCDATA, (st), (i))
#define sk_KRB5_ENCDATA_set(st, i, val) SKM_sk_set(KRB5_ENCDATA, (st), (i), (val))
#define sk_KRB5_ENCDATA_zero(st) SKM_sk_zero(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_push(st, val) SKM_sk_push(KRB5_ENCDATA, (st), (val))
#define sk_KRB5_ENCDATA_unshift(st, val) SKM_sk_unshift(KRB5_ENCDATA, (st), (val))
#define sk_KRB5_ENCDATA_find(st, val) SKM_sk_find(KRB5_ENCDATA, (st), (val))
#define sk_KRB5_ENCDATA_find_ex(st, val) SKM_sk_find_ex(KRB5_ENCDATA, (st), (val))
#define sk_KRB5_ENCDATA_delete(st, i) SKM_sk_delete(KRB5_ENCDATA, (st), (i))
#define sk_KRB5_ENCDATA_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_ENCDATA, (st), (ptr))
#define sk_KRB5_ENCDATA_insert(st, val, i) SKM_sk_insert(KRB5_ENCDATA, (st), (val), (i))
#define sk_KRB5_ENCDATA_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_ENCDATA, (st), (cmp))
#define sk_KRB5_ENCDATA_dup(st) SKM_sk_dup(KRB5_ENCDATA, st)
#define sk_KRB5_ENCDATA_pop_free(st, free_func) SKM_sk_pop_free(KRB5_ENCDATA, (st), (free_func))
#define sk_KRB5_ENCDATA_shift(st) SKM_sk_shift(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_pop(st) SKM_sk_pop(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_sort(st) SKM_sk_sort(KRB5_ENCDATA, (st))
#define sk_KRB5_ENCDATA_is_sorted(st) SKM_sk_is_sorted(KRB5_ENCDATA, (st))

#define sk_KRB5_ENCKEY_new(st) SKM_sk_new(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_new_null() SKM_sk_new_null(KRB5_ENCKEY)
#define sk_KRB5_ENCKEY_free(st) SKM_sk_free(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_num(st) SKM_sk_num(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_value(st, i) SKM_sk_value(KRB5_ENCKEY, (st), (i))
#define sk_KRB5_ENCKEY_set(st, i, val) SKM_sk_set(KRB5_ENCKEY, (st), (i), (val))
#define sk_KRB5_ENCKEY_zero(st) SKM_sk_zero(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_push(st, val) SKM_sk_push(KRB5_ENCKEY, (st), (val))
#define sk_KRB5_ENCKEY_unshift(st, val) SKM_sk_unshift(KRB5_ENCKEY, (st), (val))
#define sk_KRB5_ENCKEY_find(st, val) SKM_sk_find(KRB5_ENCKEY, (st), (val))
#define sk_KRB5_ENCKEY_find_ex(st, val) SKM_sk_find_ex(KRB5_ENCKEY, (st), (val))
#define sk_KRB5_ENCKEY_delete(st, i) SKM_sk_delete(KRB5_ENCKEY, (st), (i))
#define sk_KRB5_ENCKEY_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_ENCKEY, (st), (ptr))
#define sk_KRB5_ENCKEY_insert(st, val, i) SKM_sk_insert(KRB5_ENCKEY, (st), (val), (i))
#define sk_KRB5_ENCKEY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_ENCKEY, (st), (cmp))
#define sk_KRB5_ENCKEY_dup(st) SKM_sk_dup(KRB5_ENCKEY, st)
#define sk_KRB5_ENCKEY_pop_free(st, free_func) SKM_sk_pop_free(KRB5_ENCKEY, (st), (free_func))
#define sk_KRB5_ENCKEY_shift(st) SKM_sk_shift(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_pop(st) SKM_sk_pop(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_sort(st) SKM_sk_sort(KRB5_ENCKEY, (st))
#define sk_KRB5_ENCKEY_is_sorted(st) SKM_sk_is_sorted(KRB5_ENCKEY, (st))

#define sk_KRB5_PRINCNAME_new(st) SKM_sk_new(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_new_null() SKM_sk_new_null(KRB5_PRINCNAME)
#define sk_KRB5_PRINCNAME_free(st) SKM_sk_free(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_num(st) SKM_sk_num(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_value(st, i) SKM_sk_value(KRB5_PRINCNAME, (st), (i))
#define sk_KRB5_PRINCNAME_set(st, i, val) SKM_sk_set(KRB5_PRINCNAME, (st), (i), (val))
#define sk_KRB5_PRINCNAME_zero(st) SKM_sk_zero(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_push(st, val) SKM_sk_push(KRB5_PRINCNAME, (st), (val))
#define sk_KRB5_PRINCNAME_unshift(st, val) SKM_sk_unshift(KRB5_PRINCNAME, (st), (val))
#define sk_KRB5_PRINCNAME_find(st, val) SKM_sk_find(KRB5_PRINCNAME, (st), (val))
#define sk_KRB5_PRINCNAME_find_ex(st, val) SKM_sk_find_ex(KRB5_PRINCNAME, (st), (val))
#define sk_KRB5_PRINCNAME_delete(st, i) SKM_sk_delete(KRB5_PRINCNAME, (st), (i))
#define sk_KRB5_PRINCNAME_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_PRINCNAME, (st), (ptr))
#define sk_KRB5_PRINCNAME_insert(st, val, i) SKM_sk_insert(KRB5_PRINCNAME, (st), (val), (i))
#define sk_KRB5_PRINCNAME_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_PRINCNAME, (st), (cmp))
#define sk_KRB5_PRINCNAME_dup(st) SKM_sk_dup(KRB5_PRINCNAME, st)
#define sk_KRB5_PRINCNAME_pop_free(st, free_func) SKM_sk_pop_free(KRB5_PRINCNAME, (st), (free_func))
#define sk_KRB5_PRINCNAME_shift(st) SKM_sk_shift(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_pop(st) SKM_sk_pop(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_sort(st) SKM_sk_sort(KRB5_PRINCNAME, (st))
#define sk_KRB5_PRINCNAME_is_sorted(st) SKM_sk_is_sorted(KRB5_PRINCNAME, (st))

#define sk_KRB5_TKTBODY_new(st) SKM_sk_new(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_new_null() SKM_sk_new_null(KRB5_TKTBODY)
#define sk_KRB5_TKTBODY_free(st) SKM_sk_free(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_num(st) SKM_sk_num(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_value(st, i) SKM_sk_value(KRB5_TKTBODY, (st), (i))
#define sk_KRB5_TKTBODY_set(st, i, val) SKM_sk_set(KRB5_TKTBODY, (st), (i), (val))
#define sk_KRB5_TKTBODY_zero(st) SKM_sk_zero(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_push(st, val) SKM_sk_push(KRB5_TKTBODY, (st), (val))
#define sk_KRB5_TKTBODY_unshift(st, val) SKM_sk_unshift(KRB5_TKTBODY, (st), (val))
#define sk_KRB5_TKTBODY_find(st, val) SKM_sk_find(KRB5_TKTBODY, (st), (val))
#define sk_KRB5_TKTBODY_find_ex(st, val) SKM_sk_find_ex(KRB5_TKTBODY, (st), (val))
#define sk_KRB5_TKTBODY_delete(st, i) SKM_sk_delete(KRB5_TKTBODY, (st), (i))
#define sk_KRB5_TKTBODY_delete_ptr(st, ptr) SKM_sk_delete_ptr(KRB5_TKTBODY, (st), (ptr))
#define sk_KRB5_TKTBODY_insert(st, val, i) SKM_sk_insert(KRB5_TKTBODY, (st), (val), (i))
#define sk_KRB5_TKTBODY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(KRB5_TKTBODY, (st), (cmp))
#define sk_KRB5_TKTBODY_dup(st) SKM_sk_dup(KRB5_TKTBODY, st)
#define sk_KRB5_TKTBODY_pop_free(st, free_func) SKM_sk_pop_free(KRB5_TKTBODY, (st), (free_func))
#define sk_KRB5_TKTBODY_shift(st) SKM_sk_shift(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_pop(st) SKM_sk_pop(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_sort(st) SKM_sk_sort(KRB5_TKTBODY, (st))
#define sk_KRB5_TKTBODY_is_sorted(st) SKM_sk_is_sorted(KRB5_TKTBODY, (st))

#define sk_MIME_HEADER_new(st) SKM_sk_new(MIME_HEADER, (st))
#define sk_MIME_HEADER_new_null() SKM_sk_new_null(MIME_HEADER)
#define sk_MIME_HEADER_free(st) SKM_sk_free(MIME_HEADER, (st))
#define sk_MIME_HEADER_num(st) SKM_sk_num(MIME_HEADER, (st))
#define sk_MIME_HEADER_value(st, i) SKM_sk_value(MIME_HEADER, (st), (i))
#define sk_MIME_HEADER_set(st, i, val) SKM_sk_set(MIME_HEADER, (st), (i), (val))
#define sk_MIME_HEADER_zero(st) SKM_sk_zero(MIME_HEADER, (st))
#define sk_MIME_HEADER_push(st, val) SKM_sk_push(MIME_HEADER, (st), (val))
#define sk_MIME_HEADER_unshift(st, val) SKM_sk_unshift(MIME_HEADER, (st), (val))
#define sk_MIME_HEADER_find(st, val) SKM_sk_find(MIME_HEADER, (st), (val))
#define sk_MIME_HEADER_find_ex(st, val) SKM_sk_find_ex(MIME_HEADER, (st), (val))
#define sk_MIME_HEADER_delete(st, i) SKM_sk_delete(MIME_HEADER, (st), (i))
#define sk_MIME_HEADER_delete_ptr(st, ptr) SKM_sk_delete_ptr(MIME_HEADER, (st), (ptr))
#define sk_MIME_HEADER_insert(st, val, i) SKM_sk_insert(MIME_HEADER, (st), (val), (i))
#define sk_MIME_HEADER_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(MIME_HEADER, (st), (cmp))
#define sk_MIME_HEADER_dup(st) SKM_sk_dup(MIME_HEADER, st)
#define sk_MIME_HEADER_pop_free(st, free_func) SKM_sk_pop_free(MIME_HEADER, (st), (free_func))
#define sk_MIME_HEADER_shift(st) SKM_sk_shift(MIME_HEADER, (st))
#define sk_MIME_HEADER_pop(st) SKM_sk_pop(MIME_HEADER, (st))
#define sk_MIME_HEADER_sort(st) SKM_sk_sort(MIME_HEADER, (st))
#define sk_MIME_HEADER_is_sorted(st) SKM_sk_is_sorted(MIME_HEADER, (st))

#define sk_MIME_PARAM_new(st) SKM_sk_new(MIME_PARAM, (st))
#define sk_MIME_PARAM_new_null() SKM_sk_new_null(MIME_PARAM)
#define sk_MIME_PARAM_free(st) SKM_sk_free(MIME_PARAM, (st))
#define sk_MIME_PARAM_num(st) SKM_sk_num(MIME_PARAM, (st))
#define sk_MIME_PARAM_value(st, i) SKM_sk_value(MIME_PARAM, (st), (i))
#define sk_MIME_PARAM_set(st, i, val) SKM_sk_set(MIME_PARAM, (st), (i), (val))
#define sk_MIME_PARAM_zero(st) SKM_sk_zero(MIME_PARAM, (st))
#define sk_MIME_PARAM_push(st, val) SKM_sk_push(MIME_PARAM, (st), (val))
#define sk_MIME_PARAM_unshift(st, val) SKM_sk_unshift(MIME_PARAM, (st), (val))
#define sk_MIME_PARAM_find(st, val) SKM_sk_find(MIME_PARAM, (st), (val))
#define sk_MIME_PARAM_find_ex(st, val) SKM_sk_find_ex(MIME_PARAM, (st), (val))
#define sk_MIME_PARAM_delete(st, i) SKM_sk_delete(MIME_PARAM, (st), (i))
#define sk_MIME_PARAM_delete_ptr(st, ptr) SKM_sk_delete_ptr(MIME_PARAM, (st), (ptr))
#define sk_MIME_PARAM_insert(st, val, i) SKM_sk_insert(MIME_PARAM, (st), (val), (i))
#define sk_MIME_PARAM_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(MIME_PARAM, (st), (cmp))
#define sk_MIME_PARAM_dup(st) SKM_sk_dup(MIME_PARAM, st)
#define sk_MIME_PARAM_pop_free(st, free_func) SKM_sk_pop_free(MIME_PARAM, (st), (free_func))
#define sk_MIME_PARAM_shift(st) SKM_sk_shift(MIME_PARAM, (st))
#define sk_MIME_PARAM_pop(st) SKM_sk_pop(MIME_PARAM, (st))
#define sk_MIME_PARAM_sort(st) SKM_sk_sort(MIME_PARAM, (st))
#define sk_MIME_PARAM_is_sorted(st) SKM_sk_is_sorted(MIME_PARAM, (st))

#define sk_NAME_FUNCS_new(st) SKM_sk_new(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_new_null() SKM_sk_new_null(NAME_FUNCS)
#define sk_NAME_FUNCS_free(st) SKM_sk_free(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_num(st) SKM_sk_num(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_value(st, i) SKM_sk_value(NAME_FUNCS, (st), (i))
#define sk_NAME_FUNCS_set(st, i, val) SKM_sk_set(NAME_FUNCS, (st), (i), (val))
#define sk_NAME_FUNCS_zero(st) SKM_sk_zero(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_push(st, val) SKM_sk_push(NAME_FUNCS, (st), (val))
#define sk_NAME_FUNCS_unshift(st, val) SKM_sk_unshift(NAME_FUNCS, (st), (val))
#define sk_NAME_FUNCS_find(st, val) SKM_sk_find(NAME_FUNCS, (st), (val))
#define sk_NAME_FUNCS_find_ex(st, val) SKM_sk_find_ex(NAME_FUNCS, (st), (val))
#define sk_NAME_FUNCS_delete(st, i) SKM_sk_delete(NAME_FUNCS, (st), (i))
#define sk_NAME_FUNCS_delete_ptr(st, ptr) SKM_sk_delete_ptr(NAME_FUNCS, (st), (ptr))
#define sk_NAME_FUNCS_insert(st, val, i) SKM_sk_insert(NAME_FUNCS, (st), (val), (i))
#define sk_NAME_FUNCS_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(NAME_FUNCS, (st), (cmp))
#define sk_NAME_FUNCS_dup(st) SKM_sk_dup(NAME_FUNCS, st)
#define sk_NAME_FUNCS_pop_free(st, free_func) SKM_sk_pop_free(NAME_FUNCS, (st), (free_func))
#define sk_NAME_FUNCS_shift(st) SKM_sk_shift(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_pop(st) SKM_sk_pop(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_sort(st) SKM_sk_sort(NAME_FUNCS, (st))
#define sk_NAME_FUNCS_is_sorted(st) SKM_sk_is_sorted(NAME_FUNCS, (st))

#define sk_OCSP_CERTID_new(st) SKM_sk_new(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_new_null() SKM_sk_new_null(OCSP_CERTID)
#define sk_OCSP_CERTID_free(st) SKM_sk_free(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_num(st) SKM_sk_num(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_value(st, i) SKM_sk_value(OCSP_CERTID, (st), (i))
#define sk_OCSP_CERTID_set(st, i, val) SKM_sk_set(OCSP_CERTID, (st), (i), (val))
#define sk_OCSP_CERTID_zero(st) SKM_sk_zero(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_push(st, val) SKM_sk_push(OCSP_CERTID, (st), (val))
#define sk_OCSP_CERTID_unshift(st, val) SKM_sk_unshift(OCSP_CERTID, (st), (val))
#define sk_OCSP_CERTID_find(st, val) SKM_sk_find(OCSP_CERTID, (st), (val))
#define sk_OCSP_CERTID_find_ex(st, val) SKM_sk_find_ex(OCSP_CERTID, (st), (val))
#define sk_OCSP_CERTID_delete(st, i) SKM_sk_delete(OCSP_CERTID, (st), (i))
#define sk_OCSP_CERTID_delete_ptr(st, ptr) SKM_sk_delete_ptr(OCSP_CERTID, (st), (ptr))
#define sk_OCSP_CERTID_insert(st, val, i) SKM_sk_insert(OCSP_CERTID, (st), (val), (i))
#define sk_OCSP_CERTID_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(OCSP_CERTID, (st), (cmp))
#define sk_OCSP_CERTID_dup(st) SKM_sk_dup(OCSP_CERTID, st)
#define sk_OCSP_CERTID_pop_free(st, free_func) SKM_sk_pop_free(OCSP_CERTID, (st), (free_func))
#define sk_OCSP_CERTID_shift(st) SKM_sk_shift(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_pop(st) SKM_sk_pop(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_sort(st) SKM_sk_sort(OCSP_CERTID, (st))
#define sk_OCSP_CERTID_is_sorted(st) SKM_sk_is_sorted(OCSP_CERTID, (st))

#define sk_OCSP_ONEREQ_new(st) SKM_sk_new(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_new_null() SKM_sk_new_null(OCSP_ONEREQ)
#define sk_OCSP_ONEREQ_free(st) SKM_sk_free(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_num(st) SKM_sk_num(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_value(st, i) SKM_sk_value(OCSP_ONEREQ, (st), (i))
#define sk_OCSP_ONEREQ_set(st, i, val) SKM_sk_set(OCSP_ONEREQ, (st), (i), (val))
#define sk_OCSP_ONEREQ_zero(st) SKM_sk_zero(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_push(st, val) SKM_sk_push(OCSP_ONEREQ, (st), (val))
#define sk_OCSP_ONEREQ_unshift(st, val) SKM_sk_unshift(OCSP_ONEREQ, (st), (val))
#define sk_OCSP_ONEREQ_find(st, val) SKM_sk_find(OCSP_ONEREQ, (st), (val))
#define sk_OCSP_ONEREQ_find_ex(st, val) SKM_sk_find_ex(OCSP_ONEREQ, (st), (val))
#define sk_OCSP_ONEREQ_delete(st, i) SKM_sk_delete(OCSP_ONEREQ, (st), (i))
#define sk_OCSP_ONEREQ_delete_ptr(st, ptr) SKM_sk_delete_ptr(OCSP_ONEREQ, (st), (ptr))
#define sk_OCSP_ONEREQ_insert(st, val, i) SKM_sk_insert(OCSP_ONEREQ, (st), (val), (i))
#define sk_OCSP_ONEREQ_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(OCSP_ONEREQ, (st), (cmp))
#define sk_OCSP_ONEREQ_dup(st) SKM_sk_dup(OCSP_ONEREQ, st)
#define sk_OCSP_ONEREQ_pop_free(st, free_func) SKM_sk_pop_free(OCSP_ONEREQ, (st), (free_func))
#define sk_OCSP_ONEREQ_shift(st) SKM_sk_shift(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_pop(st) SKM_sk_pop(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_sort(st) SKM_sk_sort(OCSP_ONEREQ, (st))
#define sk_OCSP_ONEREQ_is_sorted(st) SKM_sk_is_sorted(OCSP_ONEREQ, (st))

#define sk_OCSP_RESPID_new(st) SKM_sk_new(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_new_null() SKM_sk_new_null(OCSP_RESPID)
#define sk_OCSP_RESPID_free(st) SKM_sk_free(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_num(st) SKM_sk_num(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_value(st, i) SKM_sk_value(OCSP_RESPID, (st), (i))
#define sk_OCSP_RESPID_set(st, i, val) SKM_sk_set(OCSP_RESPID, (st), (i), (val))
#define sk_OCSP_RESPID_zero(st) SKM_sk_zero(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_push(st, val) SKM_sk_push(OCSP_RESPID, (st), (val))
#define sk_OCSP_RESPID_unshift(st, val) SKM_sk_unshift(OCSP_RESPID, (st), (val))
#define sk_OCSP_RESPID_find(st, val) SKM_sk_find(OCSP_RESPID, (st), (val))
#define sk_OCSP_RESPID_find_ex(st, val) SKM_sk_find_ex(OCSP_RESPID, (st), (val))
#define sk_OCSP_RESPID_delete(st, i) SKM_sk_delete(OCSP_RESPID, (st), (i))
#define sk_OCSP_RESPID_delete_ptr(st, ptr) SKM_sk_delete_ptr(OCSP_RESPID, (st), (ptr))
#define sk_OCSP_RESPID_insert(st, val, i) SKM_sk_insert(OCSP_RESPID, (st), (val), (i))
#define sk_OCSP_RESPID_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(OCSP_RESPID, (st), (cmp))
#define sk_OCSP_RESPID_dup(st) SKM_sk_dup(OCSP_RESPID, st)
#define sk_OCSP_RESPID_pop_free(st, free_func) SKM_sk_pop_free(OCSP_RESPID, (st), (free_func))
#define sk_OCSP_RESPID_shift(st) SKM_sk_shift(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_pop(st) SKM_sk_pop(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_sort(st) SKM_sk_sort(OCSP_RESPID, (st))
#define sk_OCSP_RESPID_is_sorted(st) SKM_sk_is_sorted(OCSP_RESPID, (st))

#define sk_OCSP_SINGLERESP_new(st) SKM_sk_new(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_new_null() SKM_sk_new_null(OCSP_SINGLERESP)
#define sk_OCSP_SINGLERESP_free(st) SKM_sk_free(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_num(st) SKM_sk_num(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_value(st, i) SKM_sk_value(OCSP_SINGLERESP, (st), (i))
#define sk_OCSP_SINGLERESP_set(st, i, val) SKM_sk_set(OCSP_SINGLERESP, (st), (i), (val))
#define sk_OCSP_SINGLERESP_zero(st) SKM_sk_zero(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_push(st, val) SKM_sk_push(OCSP_SINGLERESP, (st), (val))
#define sk_OCSP_SINGLERESP_unshift(st, val) SKM_sk_unshift(OCSP_SINGLERESP, (st), (val))
#define sk_OCSP_SINGLERESP_find(st, val) SKM_sk_find(OCSP_SINGLERESP, (st), (val))
#define sk_OCSP_SINGLERESP_find_ex(st, val) SKM_sk_find_ex(OCSP_SINGLERESP, (st), (val))
#define sk_OCSP_SINGLERESP_delete(st, i) SKM_sk_delete(OCSP_SINGLERESP, (st), (i))
#define sk_OCSP_SINGLERESP_delete_ptr(st, ptr) SKM_sk_delete_ptr(OCSP_SINGLERESP, (st), (ptr))
#define sk_OCSP_SINGLERESP_insert(st, val, i) SKM_sk_insert(OCSP_SINGLERESP, (st), (val), (i))
#define sk_OCSP_SINGLERESP_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(OCSP_SINGLERESP, (st), (cmp))
#define sk_OCSP_SINGLERESP_dup(st) SKM_sk_dup(OCSP_SINGLERESP, st)
#define sk_OCSP_SINGLERESP_pop_free(st, free_func) SKM_sk_pop_free(OCSP_SINGLERESP, (st), (free_func))
#define sk_OCSP_SINGLERESP_shift(st) SKM_sk_shift(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_pop(st) SKM_sk_pop(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_sort(st) SKM_sk_sort(OCSP_SINGLERESP, (st))
#define sk_OCSP_SINGLERESP_is_sorted(st) SKM_sk_is_sorted(OCSP_SINGLERESP, (st))

#define sk_PKCS12_SAFEBAG_new(st) SKM_sk_new(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_new_null() SKM_sk_new_null(PKCS12_SAFEBAG)
#define sk_PKCS12_SAFEBAG_free(st) SKM_sk_free(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_num(st) SKM_sk_num(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_value(st, i) SKM_sk_value(PKCS12_SAFEBAG, (st), (i))
#define sk_PKCS12_SAFEBAG_set(st, i, val) SKM_sk_set(PKCS12_SAFEBAG, (st), (i), (val))
#define sk_PKCS12_SAFEBAG_zero(st) SKM_sk_zero(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_push(st, val) SKM_sk_push(PKCS12_SAFEBAG, (st), (val))
#define sk_PKCS12_SAFEBAG_unshift(st, val) SKM_sk_unshift(PKCS12_SAFEBAG, (st), (val))
#define sk_PKCS12_SAFEBAG_find(st, val) SKM_sk_find(PKCS12_SAFEBAG, (st), (val))
#define sk_PKCS12_SAFEBAG_find_ex(st, val) SKM_sk_find_ex(PKCS12_SAFEBAG, (st), (val))
#define sk_PKCS12_SAFEBAG_delete(st, i) SKM_sk_delete(PKCS12_SAFEBAG, (st), (i))
#define sk_PKCS12_SAFEBAG_delete_ptr(st, ptr) SKM_sk_delete_ptr(PKCS12_SAFEBAG, (st), (ptr))
#define sk_PKCS12_SAFEBAG_insert(st, val, i) SKM_sk_insert(PKCS12_SAFEBAG, (st), (val), (i))
#define sk_PKCS12_SAFEBAG_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(PKCS12_SAFEBAG, (st), (cmp))
#define sk_PKCS12_SAFEBAG_dup(st) SKM_sk_dup(PKCS12_SAFEBAG, st)
#define sk_PKCS12_SAFEBAG_pop_free(st, free_func) SKM_sk_pop_free(PKCS12_SAFEBAG, (st), (free_func))
#define sk_PKCS12_SAFEBAG_shift(st) SKM_sk_shift(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_pop(st) SKM_sk_pop(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_sort(st) SKM_sk_sort(PKCS12_SAFEBAG, (st))
#define sk_PKCS12_SAFEBAG_is_sorted(st) SKM_sk_is_sorted(PKCS12_SAFEBAG, (st))

#define sk_PKCS7_new(st) SKM_sk_new(PKCS7, (st))
#define sk_PKCS7_new_null() SKM_sk_new_null(PKCS7)
#define sk_PKCS7_free(st) SKM_sk_free(PKCS7, (st))
#define sk_PKCS7_num(st) SKM_sk_num(PKCS7, (st))
#define sk_PKCS7_value(st, i) SKM_sk_value(PKCS7, (st), (i))
#define sk_PKCS7_set(st, i, val) SKM_sk_set(PKCS7, (st), (i), (val))
#define sk_PKCS7_zero(st) SKM_sk_zero(PKCS7, (st))
#define sk_PKCS7_push(st, val) SKM_sk_push(PKCS7, (st), (val))
#define sk_PKCS7_unshift(st, val) SKM_sk_unshift(PKCS7, (st), (val))
#define sk_PKCS7_find(st, val) SKM_sk_find(PKCS7, (st), (val))
#define sk_PKCS7_find_ex(st, val) SKM_sk_find_ex(PKCS7, (st), (val))
#define sk_PKCS7_delete(st, i) SKM_sk_delete(PKCS7, (st), (i))
#define sk_PKCS7_delete_ptr(st, ptr) SKM_sk_delete_ptr(PKCS7, (st), (ptr))
#define sk_PKCS7_insert(st, val, i) SKM_sk_insert(PKCS7, (st), (val), (i))
#define sk_PKCS7_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(PKCS7, (st), (cmp))
#define sk_PKCS7_dup(st) SKM_sk_dup(PKCS7, st)
#define sk_PKCS7_pop_free(st, free_func) SKM_sk_pop_free(PKCS7, (st), (free_func))
#define sk_PKCS7_shift(st) SKM_sk_shift(PKCS7, (st))
#define sk_PKCS7_pop(st) SKM_sk_pop(PKCS7, (st))
#define sk_PKCS7_sort(st) SKM_sk_sort(PKCS7, (st))
#define sk_PKCS7_is_sorted(st) SKM_sk_is_sorted(PKCS7, (st))

#define sk_PKCS7_RECIP_INFO_new(st) SKM_sk_new(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_new_null() SKM_sk_new_null(PKCS7_RECIP_INFO)
#define sk_PKCS7_RECIP_INFO_free(st) SKM_sk_free(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_num(st) SKM_sk_num(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_value(st, i) SKM_sk_value(PKCS7_RECIP_INFO, (st), (i))
#define sk_PKCS7_RECIP_INFO_set(st, i, val) SKM_sk_set(PKCS7_RECIP_INFO, (st), (i), (val))
#define sk_PKCS7_RECIP_INFO_zero(st) SKM_sk_zero(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_push(st, val) SKM_sk_push(PKCS7_RECIP_INFO, (st), (val))
#define sk_PKCS7_RECIP_INFO_unshift(st, val) SKM_sk_unshift(PKCS7_RECIP_INFO, (st), (val))
#define sk_PKCS7_RECIP_INFO_find(st, val) SKM_sk_find(PKCS7_RECIP_INFO, (st), (val))
#define sk_PKCS7_RECIP_INFO_find_ex(st, val) SKM_sk_find_ex(PKCS7_RECIP_INFO, (st), (val))
#define sk_PKCS7_RECIP_INFO_delete(st, i) SKM_sk_delete(PKCS7_RECIP_INFO, (st), (i))
#define sk_PKCS7_RECIP_INFO_delete_ptr(st, ptr) SKM_sk_delete_ptr(PKCS7_RECIP_INFO, (st), (ptr))
#define sk_PKCS7_RECIP_INFO_insert(st, val, i) SKM_sk_insert(PKCS7_RECIP_INFO, (st), (val), (i))
#define sk_PKCS7_RECIP_INFO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(PKCS7_RECIP_INFO, (st), (cmp))
#define sk_PKCS7_RECIP_INFO_dup(st) SKM_sk_dup(PKCS7_RECIP_INFO, st)
#define sk_PKCS7_RECIP_INFO_pop_free(st, free_func) SKM_sk_pop_free(PKCS7_RECIP_INFO, (st), (free_func))
#define sk_PKCS7_RECIP_INFO_shift(st) SKM_sk_shift(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_pop(st) SKM_sk_pop(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_sort(st) SKM_sk_sort(PKCS7_RECIP_INFO, (st))
#define sk_PKCS7_RECIP_INFO_is_sorted(st) SKM_sk_is_sorted(PKCS7_RECIP_INFO, (st))

#define sk_PKCS7_SIGNER_INFO_new(st) SKM_sk_new(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_new_null() SKM_sk_new_null(PKCS7_SIGNER_INFO)
#define sk_PKCS7_SIGNER_INFO_free(st) SKM_sk_free(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_num(st) SKM_sk_num(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_value(st, i) SKM_sk_value(PKCS7_SIGNER_INFO, (st), (i))
#define sk_PKCS7_SIGNER_INFO_set(st, i, val) SKM_sk_set(PKCS7_SIGNER_INFO, (st), (i), (val))
#define sk_PKCS7_SIGNER_INFO_zero(st) SKM_sk_zero(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_push(st, val) SKM_sk_push(PKCS7_SIGNER_INFO, (st), (val))
#define sk_PKCS7_SIGNER_INFO_unshift(st, val) SKM_sk_unshift(PKCS7_SIGNER_INFO, (st), (val))
#define sk_PKCS7_SIGNER_INFO_find(st, val) SKM_sk_find(PKCS7_SIGNER_INFO, (st), (val))
#define sk_PKCS7_SIGNER_INFO_find_ex(st, val) SKM_sk_find_ex(PKCS7_SIGNER_INFO, (st), (val))
#define sk_PKCS7_SIGNER_INFO_delete(st, i) SKM_sk_delete(PKCS7_SIGNER_INFO, (st), (i))
#define sk_PKCS7_SIGNER_INFO_delete_ptr(st, ptr) SKM_sk_delete_ptr(PKCS7_SIGNER_INFO, (st), (ptr))
#define sk_PKCS7_SIGNER_INFO_insert(st, val, i) SKM_sk_insert(PKCS7_SIGNER_INFO, (st), (val), (i))
#define sk_PKCS7_SIGNER_INFO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(PKCS7_SIGNER_INFO, (st), (cmp))
#define sk_PKCS7_SIGNER_INFO_dup(st) SKM_sk_dup(PKCS7_SIGNER_INFO, st)
#define sk_PKCS7_SIGNER_INFO_pop_free(st, free_func) SKM_sk_pop_free(PKCS7_SIGNER_INFO, (st), (free_func))
#define sk_PKCS7_SIGNER_INFO_shift(st) SKM_sk_shift(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_pop(st) SKM_sk_pop(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_sort(st) SKM_sk_sort(PKCS7_SIGNER_INFO, (st))
#define sk_PKCS7_SIGNER_INFO_is_sorted(st) SKM_sk_is_sorted(PKCS7_SIGNER_INFO, (st))

#define sk_POLICYINFO_new(st) SKM_sk_new(POLICYINFO, (st))
#define sk_POLICYINFO_new_null() SKM_sk_new_null(POLICYINFO)
#define sk_POLICYINFO_free(st) SKM_sk_free(POLICYINFO, (st))
#define sk_POLICYINFO_num(st) SKM_sk_num(POLICYINFO, (st))
#define sk_POLICYINFO_value(st, i) SKM_sk_value(POLICYINFO, (st), (i))
#define sk_POLICYINFO_set(st, i, val) SKM_sk_set(POLICYINFO, (st), (i), (val))
#define sk_POLICYINFO_zero(st) SKM_sk_zero(POLICYINFO, (st))
#define sk_POLICYINFO_push(st, val) SKM_sk_push(POLICYINFO, (st), (val))
#define sk_POLICYINFO_unshift(st, val) SKM_sk_unshift(POLICYINFO, (st), (val))
#define sk_POLICYINFO_find(st, val) SKM_sk_find(POLICYINFO, (st), (val))
#define sk_POLICYINFO_find_ex(st, val) SKM_sk_find_ex(POLICYINFO, (st), (val))
#define sk_POLICYINFO_delete(st, i) SKM_sk_delete(POLICYINFO, (st), (i))
#define sk_POLICYINFO_delete_ptr(st, ptr) SKM_sk_delete_ptr(POLICYINFO, (st), (ptr))
#define sk_POLICYINFO_insert(st, val, i) SKM_sk_insert(POLICYINFO, (st), (val), (i))
#define sk_POLICYINFO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(POLICYINFO, (st), (cmp))
#define sk_POLICYINFO_dup(st) SKM_sk_dup(POLICYINFO, st)
#define sk_POLICYINFO_pop_free(st, free_func) SKM_sk_pop_free(POLICYINFO, (st), (free_func))
#define sk_POLICYINFO_shift(st) SKM_sk_shift(POLICYINFO, (st))
#define sk_POLICYINFO_pop(st) SKM_sk_pop(POLICYINFO, (st))
#define sk_POLICYINFO_sort(st) SKM_sk_sort(POLICYINFO, (st))
#define sk_POLICYINFO_is_sorted(st) SKM_sk_is_sorted(POLICYINFO, (st))

#define sk_POLICYQUALINFO_new(st) SKM_sk_new(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_new_null() SKM_sk_new_null(POLICYQUALINFO)
#define sk_POLICYQUALINFO_free(st) SKM_sk_free(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_num(st) SKM_sk_num(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_value(st, i) SKM_sk_value(POLICYQUALINFO, (st), (i))
#define sk_POLICYQUALINFO_set(st, i, val) SKM_sk_set(POLICYQUALINFO, (st), (i), (val))
#define sk_POLICYQUALINFO_zero(st) SKM_sk_zero(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_push(st, val) SKM_sk_push(POLICYQUALINFO, (st), (val))
#define sk_POLICYQUALINFO_unshift(st, val) SKM_sk_unshift(POLICYQUALINFO, (st), (val))
#define sk_POLICYQUALINFO_find(st, val) SKM_sk_find(POLICYQUALINFO, (st), (val))
#define sk_POLICYQUALINFO_find_ex(st, val) SKM_sk_find_ex(POLICYQUALINFO, (st), (val))
#define sk_POLICYQUALINFO_delete(st, i) SKM_sk_delete(POLICYQUALINFO, (st), (i))
#define sk_POLICYQUALINFO_delete_ptr(st, ptr) SKM_sk_delete_ptr(POLICYQUALINFO, (st), (ptr))
#define sk_POLICYQUALINFO_insert(st, val, i) SKM_sk_insert(POLICYQUALINFO, (st), (val), (i))
#define sk_POLICYQUALINFO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(POLICYQUALINFO, (st), (cmp))
#define sk_POLICYQUALINFO_dup(st) SKM_sk_dup(POLICYQUALINFO, st)
#define sk_POLICYQUALINFO_pop_free(st, free_func) SKM_sk_pop_free(POLICYQUALINFO, (st), (free_func))
#define sk_POLICYQUALINFO_shift(st) SKM_sk_shift(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_pop(st) SKM_sk_pop(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_sort(st) SKM_sk_sort(POLICYQUALINFO, (st))
#define sk_POLICYQUALINFO_is_sorted(st) SKM_sk_is_sorted(POLICYQUALINFO, (st))

#define sk_POLICY_MAPPING_new(st) SKM_sk_new(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_new_null() SKM_sk_new_null(POLICY_MAPPING)
#define sk_POLICY_MAPPING_free(st) SKM_sk_free(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_num(st) SKM_sk_num(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_value(st, i) SKM_sk_value(POLICY_MAPPING, (st), (i))
#define sk_POLICY_MAPPING_set(st, i, val) SKM_sk_set(POLICY_MAPPING, (st), (i), (val))
#define sk_POLICY_MAPPING_zero(st) SKM_sk_zero(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_push(st, val) SKM_sk_push(POLICY_MAPPING, (st), (val))
#define sk_POLICY_MAPPING_unshift(st, val) SKM_sk_unshift(POLICY_MAPPING, (st), (val))
#define sk_POLICY_MAPPING_find(st, val) SKM_sk_find(POLICY_MAPPING, (st), (val))
#define sk_POLICY_MAPPING_find_ex(st, val) SKM_sk_find_ex(POLICY_MAPPING, (st), (val))
#define sk_POLICY_MAPPING_delete(st, i) SKM_sk_delete(POLICY_MAPPING, (st), (i))
#define sk_POLICY_MAPPING_delete_ptr(st, ptr) SKM_sk_delete_ptr(POLICY_MAPPING, (st), (ptr))
#define sk_POLICY_MAPPING_insert(st, val, i) SKM_sk_insert(POLICY_MAPPING, (st), (val), (i))
#define sk_POLICY_MAPPING_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(POLICY_MAPPING, (st), (cmp))
#define sk_POLICY_MAPPING_dup(st) SKM_sk_dup(POLICY_MAPPING, st)
#define sk_POLICY_MAPPING_pop_free(st, free_func) SKM_sk_pop_free(POLICY_MAPPING, (st), (free_func))
#define sk_POLICY_MAPPING_shift(st) SKM_sk_shift(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_pop(st) SKM_sk_pop(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_sort(st) SKM_sk_sort(POLICY_MAPPING, (st))
#define sk_POLICY_MAPPING_is_sorted(st) SKM_sk_is_sorted(POLICY_MAPPING, (st))

#define sk_SSL_CIPHER_new(st) SKM_sk_new(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_new_null() SKM_sk_new_null(SSL_CIPHER)
#define sk_SSL_CIPHER_free(st) SKM_sk_free(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_num(st) SKM_sk_num(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_value(st, i) SKM_sk_value(SSL_CIPHER, (st), (i))
#define sk_SSL_CIPHER_set(st, i, val) SKM_sk_set(SSL_CIPHER, (st), (i), (val))
#define sk_SSL_CIPHER_zero(st) SKM_sk_zero(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_push(st, val) SKM_sk_push(SSL_CIPHER, (st), (val))
#define sk_SSL_CIPHER_unshift(st, val) SKM_sk_unshift(SSL_CIPHER, (st), (val))
#define sk_SSL_CIPHER_find(st, val) SKM_sk_find(SSL_CIPHER, (st), (val))
#define sk_SSL_CIPHER_find_ex(st, val) SKM_sk_find_ex(SSL_CIPHER, (st), (val))
#define sk_SSL_CIPHER_delete(st, i) SKM_sk_delete(SSL_CIPHER, (st), (i))
#define sk_SSL_CIPHER_delete_ptr(st, ptr) SKM_sk_delete_ptr(SSL_CIPHER, (st), (ptr))
#define sk_SSL_CIPHER_insert(st, val, i) SKM_sk_insert(SSL_CIPHER, (st), (val), (i))
#define sk_SSL_CIPHER_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(SSL_CIPHER, (st), (cmp))
#define sk_SSL_CIPHER_dup(st) SKM_sk_dup(SSL_CIPHER, st)
#define sk_SSL_CIPHER_pop_free(st, free_func) SKM_sk_pop_free(SSL_CIPHER, (st), (free_func))
#define sk_SSL_CIPHER_shift(st) SKM_sk_shift(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_pop(st) SKM_sk_pop(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_sort(st) SKM_sk_sort(SSL_CIPHER, (st))
#define sk_SSL_CIPHER_is_sorted(st) SKM_sk_is_sorted(SSL_CIPHER, (st))

#define sk_SSL_COMP_new(st) SKM_sk_new(SSL_COMP, (st))
#define sk_SSL_COMP_new_null() SKM_sk_new_null(SSL_COMP)
#define sk_SSL_COMP_free(st) SKM_sk_free(SSL_COMP, (st))
#define sk_SSL_COMP_num(st) SKM_sk_num(SSL_COMP, (st))
#define sk_SSL_COMP_value(st, i) SKM_sk_value(SSL_COMP, (st), (i))
#define sk_SSL_COMP_set(st, i, val) SKM_sk_set(SSL_COMP, (st), (i), (val))
#define sk_SSL_COMP_zero(st) SKM_sk_zero(SSL_COMP, (st))
#define sk_SSL_COMP_push(st, val) SKM_sk_push(SSL_COMP, (st), (val))
#define sk_SSL_COMP_unshift(st, val) SKM_sk_unshift(SSL_COMP, (st), (val))
#define sk_SSL_COMP_find(st, val) SKM_sk_find(SSL_COMP, (st), (val))
#define sk_SSL_COMP_find_ex(st, val) SKM_sk_find_ex(SSL_COMP, (st), (val))
#define sk_SSL_COMP_delete(st, i) SKM_sk_delete(SSL_COMP, (st), (i))
#define sk_SSL_COMP_delete_ptr(st, ptr) SKM_sk_delete_ptr(SSL_COMP, (st), (ptr))
#define sk_SSL_COMP_insert(st, val, i) SKM_sk_insert(SSL_COMP, (st), (val), (i))
#define sk_SSL_COMP_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(SSL_COMP, (st), (cmp))
#define sk_SSL_COMP_dup(st) SKM_sk_dup(SSL_COMP, st)
#define sk_SSL_COMP_pop_free(st, free_func) SKM_sk_pop_free(SSL_COMP, (st), (free_func))
#define sk_SSL_COMP_shift(st) SKM_sk_shift(SSL_COMP, (st))
#define sk_SSL_COMP_pop(st) SKM_sk_pop(SSL_COMP, (st))
#define sk_SSL_COMP_sort(st) SKM_sk_sort(SSL_COMP, (st))
#define sk_SSL_COMP_is_sorted(st) SKM_sk_is_sorted(SSL_COMP, (st))

#define sk_STORE_OBJECT_new(st) SKM_sk_new(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_new_null() SKM_sk_new_null(STORE_OBJECT)
#define sk_STORE_OBJECT_free(st) SKM_sk_free(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_num(st) SKM_sk_num(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_value(st, i) SKM_sk_value(STORE_OBJECT, (st), (i))
#define sk_STORE_OBJECT_set(st, i, val) SKM_sk_set(STORE_OBJECT, (st), (i), (val))
#define sk_STORE_OBJECT_zero(st) SKM_sk_zero(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_push(st, val) SKM_sk_push(STORE_OBJECT, (st), (val))
#define sk_STORE_OBJECT_unshift(st, val) SKM_sk_unshift(STORE_OBJECT, (st), (val))
#define sk_STORE_OBJECT_find(st, val) SKM_sk_find(STORE_OBJECT, (st), (val))
#define sk_STORE_OBJECT_find_ex(st, val) SKM_sk_find_ex(STORE_OBJECT, (st), (val))
#define sk_STORE_OBJECT_delete(st, i) SKM_sk_delete(STORE_OBJECT, (st), (i))
#define sk_STORE_OBJECT_delete_ptr(st, ptr) SKM_sk_delete_ptr(STORE_OBJECT, (st), (ptr))
#define sk_STORE_OBJECT_insert(st, val, i) SKM_sk_insert(STORE_OBJECT, (st), (val), (i))
#define sk_STORE_OBJECT_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(STORE_OBJECT, (st), (cmp))
#define sk_STORE_OBJECT_dup(st) SKM_sk_dup(STORE_OBJECT, st)
#define sk_STORE_OBJECT_pop_free(st, free_func) SKM_sk_pop_free(STORE_OBJECT, (st), (free_func))
#define sk_STORE_OBJECT_shift(st) SKM_sk_shift(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_pop(st) SKM_sk_pop(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_sort(st) SKM_sk_sort(STORE_OBJECT, (st))
#define sk_STORE_OBJECT_is_sorted(st) SKM_sk_is_sorted(STORE_OBJECT, (st))

#define sk_SXNETID_new(st) SKM_sk_new(SXNETID, (st))
#define sk_SXNETID_new_null() SKM_sk_new_null(SXNETID)
#define sk_SXNETID_free(st) SKM_sk_free(SXNETID, (st))
#define sk_SXNETID_num(st) SKM_sk_num(SXNETID, (st))
#define sk_SXNETID_value(st, i) SKM_sk_value(SXNETID, (st), (i))
#define sk_SXNETID_set(st, i, val) SKM_sk_set(SXNETID, (st), (i), (val))
#define sk_SXNETID_zero(st) SKM_sk_zero(SXNETID, (st))
#define sk_SXNETID_push(st, val) SKM_sk_push(SXNETID, (st), (val))
#define sk_SXNETID_unshift(st, val) SKM_sk_unshift(SXNETID, (st), (val))
#define sk_SXNETID_find(st, val) SKM_sk_find(SXNETID, (st), (val))
#define sk_SXNETID_find_ex(st, val) SKM_sk_find_ex(SXNETID, (st), (val))
#define sk_SXNETID_delete(st, i) SKM_sk_delete(SXNETID, (st), (i))
#define sk_SXNETID_delete_ptr(st, ptr) SKM_sk_delete_ptr(SXNETID, (st), (ptr))
#define sk_SXNETID_insert(st, val, i) SKM_sk_insert(SXNETID, (st), (val), (i))
#define sk_SXNETID_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(SXNETID, (st), (cmp))
#define sk_SXNETID_dup(st) SKM_sk_dup(SXNETID, st)
#define sk_SXNETID_pop_free(st, free_func) SKM_sk_pop_free(SXNETID, (st), (free_func))
#define sk_SXNETID_shift(st) SKM_sk_shift(SXNETID, (st))
#define sk_SXNETID_pop(st) SKM_sk_pop(SXNETID, (st))
#define sk_SXNETID_sort(st) SKM_sk_sort(SXNETID, (st))
#define sk_SXNETID_is_sorted(st) SKM_sk_is_sorted(SXNETID, (st))

#define sk_UI_STRING_new(st) SKM_sk_new(UI_STRING, (st))
#define sk_UI_STRING_new_null() SKM_sk_new_null(UI_STRING)
#define sk_UI_STRING_free(st) SKM_sk_free(UI_STRING, (st))
#define sk_UI_STRING_num(st) SKM_sk_num(UI_STRING, (st))
#define sk_UI_STRING_value(st, i) SKM_sk_value(UI_STRING, (st), (i))
#define sk_UI_STRING_set(st, i, val) SKM_sk_set(UI_STRING, (st), (i), (val))
#define sk_UI_STRING_zero(st) SKM_sk_zero(UI_STRING, (st))
#define sk_UI_STRING_push(st, val) SKM_sk_push(UI_STRING, (st), (val))
#define sk_UI_STRING_unshift(st, val) SKM_sk_unshift(UI_STRING, (st), (val))
#define sk_UI_STRING_find(st, val) SKM_sk_find(UI_STRING, (st), (val))
#define sk_UI_STRING_find_ex(st, val) SKM_sk_find_ex(UI_STRING, (st), (val))
#define sk_UI_STRING_delete(st, i) SKM_sk_delete(UI_STRING, (st), (i))
#define sk_UI_STRING_delete_ptr(st, ptr) SKM_sk_delete_ptr(UI_STRING, (st), (ptr))
#define sk_UI_STRING_insert(st, val, i) SKM_sk_insert(UI_STRING, (st), (val), (i))
#define sk_UI_STRING_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(UI_STRING, (st), (cmp))
#define sk_UI_STRING_dup(st) SKM_sk_dup(UI_STRING, st)
#define sk_UI_STRING_pop_free(st, free_func) SKM_sk_pop_free(UI_STRING, (st), (free_func))
#define sk_UI_STRING_shift(st) SKM_sk_shift(UI_STRING, (st))
#define sk_UI_STRING_pop(st) SKM_sk_pop(UI_STRING, (st))
#define sk_UI_STRING_sort(st) SKM_sk_sort(UI_STRING, (st))
#define sk_UI_STRING_is_sorted(st) SKM_sk_is_sorted(UI_STRING, (st))

#define sk_X509_new(st) SKM_sk_new(X509, (st))
#define sk_X509_new_null() SKM_sk_new_null(X509)
#define sk_X509_free(st) SKM_sk_free(X509, (st))
#define sk_X509_num(st) SKM_sk_num(X509, (st))
#define sk_X509_value(st, i) SKM_sk_value(X509, (st), (i))
#define sk_X509_set(st, i, val) SKM_sk_set(X509, (st), (i), (val))
#define sk_X509_zero(st) SKM_sk_zero(X509, (st))
#define sk_X509_push(st, val) SKM_sk_push(X509, (st), (val))
#define sk_X509_unshift(st, val) SKM_sk_unshift(X509, (st), (val))
#define sk_X509_find(st, val) SKM_sk_find(X509, (st), (val))
#define sk_X509_find_ex(st, val) SKM_sk_find_ex(X509, (st), (val))
#define sk_X509_delete(st, i) SKM_sk_delete(X509, (st), (i))
#define sk_X509_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509, (st), (ptr))
#define sk_X509_insert(st, val, i) SKM_sk_insert(X509, (st), (val), (i))
#define sk_X509_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509, (st), (cmp))
#define sk_X509_dup(st) SKM_sk_dup(X509, st)
#define sk_X509_pop_free(st, free_func) SKM_sk_pop_free(X509, (st), (free_func))
#define sk_X509_shift(st) SKM_sk_shift(X509, (st))
#define sk_X509_pop(st) SKM_sk_pop(X509, (st))
#define sk_X509_sort(st) SKM_sk_sort(X509, (st))
#define sk_X509_is_sorted(st) SKM_sk_is_sorted(X509, (st))

#define sk_X509V3_EXT_METHOD_new(st) SKM_sk_new(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_new_null() SKM_sk_new_null(X509V3_EXT_METHOD)
#define sk_X509V3_EXT_METHOD_free(st) SKM_sk_free(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_num(st) SKM_sk_num(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_value(st, i) SKM_sk_value(X509V3_EXT_METHOD, (st), (i))
#define sk_X509V3_EXT_METHOD_set(st, i, val) SKM_sk_set(X509V3_EXT_METHOD, (st), (i), (val))
#define sk_X509V3_EXT_METHOD_zero(st) SKM_sk_zero(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_push(st, val) SKM_sk_push(X509V3_EXT_METHOD, (st), (val))
#define sk_X509V3_EXT_METHOD_unshift(st, val) SKM_sk_unshift(X509V3_EXT_METHOD, (st), (val))
#define sk_X509V3_EXT_METHOD_find(st, val) SKM_sk_find(X509V3_EXT_METHOD, (st), (val))
#define sk_X509V3_EXT_METHOD_find_ex(st, val) SKM_sk_find_ex(X509V3_EXT_METHOD, (st), (val))
#define sk_X509V3_EXT_METHOD_delete(st, i) SKM_sk_delete(X509V3_EXT_METHOD, (st), (i))
#define sk_X509V3_EXT_METHOD_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509V3_EXT_METHOD, (st), (ptr))
#define sk_X509V3_EXT_METHOD_insert(st, val, i) SKM_sk_insert(X509V3_EXT_METHOD, (st), (val), (i))
#define sk_X509V3_EXT_METHOD_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509V3_EXT_METHOD, (st), (cmp))
#define sk_X509V3_EXT_METHOD_dup(st) SKM_sk_dup(X509V3_EXT_METHOD, st)
#define sk_X509V3_EXT_METHOD_pop_free(st, free_func) SKM_sk_pop_free(X509V3_EXT_METHOD, (st), (free_func))
#define sk_X509V3_EXT_METHOD_shift(st) SKM_sk_shift(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_pop(st) SKM_sk_pop(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_sort(st) SKM_sk_sort(X509V3_EXT_METHOD, (st))
#define sk_X509V3_EXT_METHOD_is_sorted(st) SKM_sk_is_sorted(X509V3_EXT_METHOD, (st))

#define sk_X509_ALGOR_new(st) SKM_sk_new(X509_ALGOR, (st))
#define sk_X509_ALGOR_new_null() SKM_sk_new_null(X509_ALGOR)
#define sk_X509_ALGOR_free(st) SKM_sk_free(X509_ALGOR, (st))
#define sk_X509_ALGOR_num(st) SKM_sk_num(X509_ALGOR, (st))
#define sk_X509_ALGOR_value(st, i) SKM_sk_value(X509_ALGOR, (st), (i))
#define sk_X509_ALGOR_set(st, i, val) SKM_sk_set(X509_ALGOR, (st), (i), (val))
#define sk_X509_ALGOR_zero(st) SKM_sk_zero(X509_ALGOR, (st))
#define sk_X509_ALGOR_push(st, val) SKM_sk_push(X509_ALGOR, (st), (val))
#define sk_X509_ALGOR_unshift(st, val) SKM_sk_unshift(X509_ALGOR, (st), (val))
#define sk_X509_ALGOR_find(st, val) SKM_sk_find(X509_ALGOR, (st), (val))
#define sk_X509_ALGOR_find_ex(st, val) SKM_sk_find_ex(X509_ALGOR, (st), (val))
#define sk_X509_ALGOR_delete(st, i) SKM_sk_delete(X509_ALGOR, (st), (i))
#define sk_X509_ALGOR_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_ALGOR, (st), (ptr))
#define sk_X509_ALGOR_insert(st, val, i) SKM_sk_insert(X509_ALGOR, (st), (val), (i))
#define sk_X509_ALGOR_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_ALGOR, (st), (cmp))
#define sk_X509_ALGOR_dup(st) SKM_sk_dup(X509_ALGOR, st)
#define sk_X509_ALGOR_pop_free(st, free_func) SKM_sk_pop_free(X509_ALGOR, (st), (free_func))
#define sk_X509_ALGOR_shift(st) SKM_sk_shift(X509_ALGOR, (st))
#define sk_X509_ALGOR_pop(st) SKM_sk_pop(X509_ALGOR, (st))
#define sk_X509_ALGOR_sort(st) SKM_sk_sort(X509_ALGOR, (st))
#define sk_X509_ALGOR_is_sorted(st) SKM_sk_is_sorted(X509_ALGOR, (st))

#define sk_X509_ATTRIBUTE_new(st) SKM_sk_new(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_new_null() SKM_sk_new_null(X509_ATTRIBUTE)
#define sk_X509_ATTRIBUTE_free(st) SKM_sk_free(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_num(st) SKM_sk_num(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_value(st, i) SKM_sk_value(X509_ATTRIBUTE, (st), (i))
#define sk_X509_ATTRIBUTE_set(st, i, val) SKM_sk_set(X509_ATTRIBUTE, (st), (i), (val))
#define sk_X509_ATTRIBUTE_zero(st) SKM_sk_zero(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_push(st, val) SKM_sk_push(X509_ATTRIBUTE, (st), (val))
#define sk_X509_ATTRIBUTE_unshift(st, val) SKM_sk_unshift(X509_ATTRIBUTE, (st), (val))
#define sk_X509_ATTRIBUTE_find(st, val) SKM_sk_find(X509_ATTRIBUTE, (st), (val))
#define sk_X509_ATTRIBUTE_find_ex(st, val) SKM_sk_find_ex(X509_ATTRIBUTE, (st), (val))
#define sk_X509_ATTRIBUTE_delete(st, i) SKM_sk_delete(X509_ATTRIBUTE, (st), (i))
#define sk_X509_ATTRIBUTE_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_ATTRIBUTE, (st), (ptr))
#define sk_X509_ATTRIBUTE_insert(st, val, i) SKM_sk_insert(X509_ATTRIBUTE, (st), (val), (i))
#define sk_X509_ATTRIBUTE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_ATTRIBUTE, (st), (cmp))
#define sk_X509_ATTRIBUTE_dup(st) SKM_sk_dup(X509_ATTRIBUTE, st)
#define sk_X509_ATTRIBUTE_pop_free(st, free_func) SKM_sk_pop_free(X509_ATTRIBUTE, (st), (free_func))
#define sk_X509_ATTRIBUTE_shift(st) SKM_sk_shift(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_pop(st) SKM_sk_pop(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_sort(st) SKM_sk_sort(X509_ATTRIBUTE, (st))
#define sk_X509_ATTRIBUTE_is_sorted(st) SKM_sk_is_sorted(X509_ATTRIBUTE, (st))

#define sk_X509_CRL_new(st) SKM_sk_new(X509_CRL, (st))
#define sk_X509_CRL_new_null() SKM_sk_new_null(X509_CRL)
#define sk_X509_CRL_free(st) SKM_sk_free(X509_CRL, (st))
#define sk_X509_CRL_num(st) SKM_sk_num(X509_CRL, (st))
#define sk_X509_CRL_value(st, i) SKM_sk_value(X509_CRL, (st), (i))
#define sk_X509_CRL_set(st, i, val) SKM_sk_set(X509_CRL, (st), (i), (val))
#define sk_X509_CRL_zero(st) SKM_sk_zero(X509_CRL, (st))
#define sk_X509_CRL_push(st, val) SKM_sk_push(X509_CRL, (st), (val))
#define sk_X509_CRL_unshift(st, val) SKM_sk_unshift(X509_CRL, (st), (val))
#define sk_X509_CRL_find(st, val) SKM_sk_find(X509_CRL, (st), (val))
#define sk_X509_CRL_find_ex(st, val) SKM_sk_find_ex(X509_CRL, (st), (val))
#define sk_X509_CRL_delete(st, i) SKM_sk_delete(X509_CRL, (st), (i))
#define sk_X509_CRL_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_CRL, (st), (ptr))
#define sk_X509_CRL_insert(st, val, i) SKM_sk_insert(X509_CRL, (st), (val), (i))
#define sk_X509_CRL_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_CRL, (st), (cmp))
#define sk_X509_CRL_dup(st) SKM_sk_dup(X509_CRL, st)
#define sk_X509_CRL_pop_free(st, free_func) SKM_sk_pop_free(X509_CRL, (st), (free_func))
#define sk_X509_CRL_shift(st) SKM_sk_shift(X509_CRL, (st))
#define sk_X509_CRL_pop(st) SKM_sk_pop(X509_CRL, (st))
#define sk_X509_CRL_sort(st) SKM_sk_sort(X509_CRL, (st))
#define sk_X509_CRL_is_sorted(st) SKM_sk_is_sorted(X509_CRL, (st))

#define sk_X509_EXTENSION_new(st) SKM_sk_new(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_new_null() SKM_sk_new_null(X509_EXTENSION)
#define sk_X509_EXTENSION_free(st) SKM_sk_free(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_num(st) SKM_sk_num(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_value(st, i) SKM_sk_value(X509_EXTENSION, (st), (i))
#define sk_X509_EXTENSION_set(st, i, val) SKM_sk_set(X509_EXTENSION, (st), (i), (val))
#define sk_X509_EXTENSION_zero(st) SKM_sk_zero(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_push(st, val) SKM_sk_push(X509_EXTENSION, (st), (val))
#define sk_X509_EXTENSION_unshift(st, val) SKM_sk_unshift(X509_EXTENSION, (st), (val))
#define sk_X509_EXTENSION_find(st, val) SKM_sk_find(X509_EXTENSION, (st), (val))
#define sk_X509_EXTENSION_find_ex(st, val) SKM_sk_find_ex(X509_EXTENSION, (st), (val))
#define sk_X509_EXTENSION_delete(st, i) SKM_sk_delete(X509_EXTENSION, (st), (i))
#define sk_X509_EXTENSION_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_EXTENSION, (st), (ptr))
#define sk_X509_EXTENSION_insert(st, val, i) SKM_sk_insert(X509_EXTENSION, (st), (val), (i))
#define sk_X509_EXTENSION_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_EXTENSION, (st), (cmp))
#define sk_X509_EXTENSION_dup(st) SKM_sk_dup(X509_EXTENSION, st)
#define sk_X509_EXTENSION_pop_free(st, free_func) SKM_sk_pop_free(X509_EXTENSION, (st), (free_func))
#define sk_X509_EXTENSION_shift(st) SKM_sk_shift(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_pop(st) SKM_sk_pop(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_sort(st) SKM_sk_sort(X509_EXTENSION, (st))
#define sk_X509_EXTENSION_is_sorted(st) SKM_sk_is_sorted(X509_EXTENSION, (st))

#define sk_X509_INFO_new(st) SKM_sk_new(X509_INFO, (st))
#define sk_X509_INFO_new_null() SKM_sk_new_null(X509_INFO)
#define sk_X509_INFO_free(st) SKM_sk_free(X509_INFO, (st))
#define sk_X509_INFO_num(st) SKM_sk_num(X509_INFO, (st))
#define sk_X509_INFO_value(st, i) SKM_sk_value(X509_INFO, (st), (i))
#define sk_X509_INFO_set(st, i, val) SKM_sk_set(X509_INFO, (st), (i), (val))
#define sk_X509_INFO_zero(st) SKM_sk_zero(X509_INFO, (st))
#define sk_X509_INFO_push(st, val) SKM_sk_push(X509_INFO, (st), (val))
#define sk_X509_INFO_unshift(st, val) SKM_sk_unshift(X509_INFO, (st), (val))
#define sk_X509_INFO_find(st, val) SKM_sk_find(X509_INFO, (st), (val))
#define sk_X509_INFO_find_ex(st, val) SKM_sk_find_ex(X509_INFO, (st), (val))
#define sk_X509_INFO_delete(st, i) SKM_sk_delete(X509_INFO, (st), (i))
#define sk_X509_INFO_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_INFO, (st), (ptr))
#define sk_X509_INFO_insert(st, val, i) SKM_sk_insert(X509_INFO, (st), (val), (i))
#define sk_X509_INFO_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_INFO, (st), (cmp))
#define sk_X509_INFO_dup(st) SKM_sk_dup(X509_INFO, st)
#define sk_X509_INFO_pop_free(st, free_func) SKM_sk_pop_free(X509_INFO, (st), (free_func))
#define sk_X509_INFO_shift(st) SKM_sk_shift(X509_INFO, (st))
#define sk_X509_INFO_pop(st) SKM_sk_pop(X509_INFO, (st))
#define sk_X509_INFO_sort(st) SKM_sk_sort(X509_INFO, (st))
#define sk_X509_INFO_is_sorted(st) SKM_sk_is_sorted(X509_INFO, (st))

#define sk_X509_LOOKUP_new(st) SKM_sk_new(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_new_null() SKM_sk_new_null(X509_LOOKUP)
#define sk_X509_LOOKUP_free(st) SKM_sk_free(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_num(st) SKM_sk_num(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_value(st, i) SKM_sk_value(X509_LOOKUP, (st), (i))
#define sk_X509_LOOKUP_set(st, i, val) SKM_sk_set(X509_LOOKUP, (st), (i), (val))
#define sk_X509_LOOKUP_zero(st) SKM_sk_zero(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_push(st, val) SKM_sk_push(X509_LOOKUP, (st), (val))
#define sk_X509_LOOKUP_unshift(st, val) SKM_sk_unshift(X509_LOOKUP, (st), (val))
#define sk_X509_LOOKUP_find(st, val) SKM_sk_find(X509_LOOKUP, (st), (val))
#define sk_X509_LOOKUP_find_ex(st, val) SKM_sk_find_ex(X509_LOOKUP, (st), (val))
#define sk_X509_LOOKUP_delete(st, i) SKM_sk_delete(X509_LOOKUP, (st), (i))
#define sk_X509_LOOKUP_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_LOOKUP, (st), (ptr))
#define sk_X509_LOOKUP_insert(st, val, i) SKM_sk_insert(X509_LOOKUP, (st), (val), (i))
#define sk_X509_LOOKUP_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_LOOKUP, (st), (cmp))
#define sk_X509_LOOKUP_dup(st) SKM_sk_dup(X509_LOOKUP, st)
#define sk_X509_LOOKUP_pop_free(st, free_func) SKM_sk_pop_free(X509_LOOKUP, (st), (free_func))
#define sk_X509_LOOKUP_shift(st) SKM_sk_shift(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_pop(st) SKM_sk_pop(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_sort(st) SKM_sk_sort(X509_LOOKUP, (st))
#define sk_X509_LOOKUP_is_sorted(st) SKM_sk_is_sorted(X509_LOOKUP, (st))

#define sk_X509_NAME_new(st) SKM_sk_new(X509_NAME, (st))
#define sk_X509_NAME_new_null() SKM_sk_new_null(X509_NAME)
#define sk_X509_NAME_free(st) SKM_sk_free(X509_NAME, (st))
#define sk_X509_NAME_num(st) SKM_sk_num(X509_NAME, (st))
#define sk_X509_NAME_value(st, i) SKM_sk_value(X509_NAME, (st), (i))
#define sk_X509_NAME_set(st, i, val) SKM_sk_set(X509_NAME, (st), (i), (val))
#define sk_X509_NAME_zero(st) SKM_sk_zero(X509_NAME, (st))
#define sk_X509_NAME_push(st, val) SKM_sk_push(X509_NAME, (st), (val))
#define sk_X509_NAME_unshift(st, val) SKM_sk_unshift(X509_NAME, (st), (val))
#define sk_X509_NAME_find(st, val) SKM_sk_find(X509_NAME, (st), (val))
#define sk_X509_NAME_find_ex(st, val) SKM_sk_find_ex(X509_NAME, (st), (val))
#define sk_X509_NAME_delete(st, i) SKM_sk_delete(X509_NAME, (st), (i))
#define sk_X509_NAME_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_NAME, (st), (ptr))
#define sk_X509_NAME_insert(st, val, i) SKM_sk_insert(X509_NAME, (st), (val), (i))
#define sk_X509_NAME_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_NAME, (st), (cmp))
#define sk_X509_NAME_dup(st) SKM_sk_dup(X509_NAME, st)
#define sk_X509_NAME_pop_free(st, free_func) SKM_sk_pop_free(X509_NAME, (st), (free_func))
#define sk_X509_NAME_shift(st) SKM_sk_shift(X509_NAME, (st))
#define sk_X509_NAME_pop(st) SKM_sk_pop(X509_NAME, (st))
#define sk_X509_NAME_sort(st) SKM_sk_sort(X509_NAME, (st))
#define sk_X509_NAME_is_sorted(st) SKM_sk_is_sorted(X509_NAME, (st))

#define sk_X509_NAME_ENTRY_new(st) SKM_sk_new(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_new_null() SKM_sk_new_null(X509_NAME_ENTRY)
#define sk_X509_NAME_ENTRY_free(st) SKM_sk_free(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_num(st) SKM_sk_num(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_value(st, i) SKM_sk_value(X509_NAME_ENTRY, (st), (i))
#define sk_X509_NAME_ENTRY_set(st, i, val) SKM_sk_set(X509_NAME_ENTRY, (st), (i), (val))
#define sk_X509_NAME_ENTRY_zero(st) SKM_sk_zero(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_push(st, val) SKM_sk_push(X509_NAME_ENTRY, (st), (val))
#define sk_X509_NAME_ENTRY_unshift(st, val) SKM_sk_unshift(X509_NAME_ENTRY, (st), (val))
#define sk_X509_NAME_ENTRY_find(st, val) SKM_sk_find(X509_NAME_ENTRY, (st), (val))
#define sk_X509_NAME_ENTRY_find_ex(st, val) SKM_sk_find_ex(X509_NAME_ENTRY, (st), (val))
#define sk_X509_NAME_ENTRY_delete(st, i) SKM_sk_delete(X509_NAME_ENTRY, (st), (i))
#define sk_X509_NAME_ENTRY_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_NAME_ENTRY, (st), (ptr))
#define sk_X509_NAME_ENTRY_insert(st, val, i) SKM_sk_insert(X509_NAME_ENTRY, (st), (val), (i))
#define sk_X509_NAME_ENTRY_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_NAME_ENTRY, (st), (cmp))
#define sk_X509_NAME_ENTRY_dup(st) SKM_sk_dup(X509_NAME_ENTRY, st)
#define sk_X509_NAME_ENTRY_pop_free(st, free_func) SKM_sk_pop_free(X509_NAME_ENTRY, (st), (free_func))
#define sk_X509_NAME_ENTRY_shift(st) SKM_sk_shift(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_pop(st) SKM_sk_pop(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_sort(st) SKM_sk_sort(X509_NAME_ENTRY, (st))
#define sk_X509_NAME_ENTRY_is_sorted(st) SKM_sk_is_sorted(X509_NAME_ENTRY, (st))

#define sk_X509_OBJECT_new(st) SKM_sk_new(X509_OBJECT, (st))
#define sk_X509_OBJECT_new_null() SKM_sk_new_null(X509_OBJECT)
#define sk_X509_OBJECT_free(st) SKM_sk_free(X509_OBJECT, (st))
#define sk_X509_OBJECT_num(st) SKM_sk_num(X509_OBJECT, (st))
#define sk_X509_OBJECT_value(st, i) SKM_sk_value(X509_OBJECT, (st), (i))
#define sk_X509_OBJECT_set(st, i, val) SKM_sk_set(X509_OBJECT, (st), (i), (val))
#define sk_X509_OBJECT_zero(st) SKM_sk_zero(X509_OBJECT, (st))
#define sk_X509_OBJECT_push(st, val) SKM_sk_push(X509_OBJECT, (st), (val))
#define sk_X509_OBJECT_unshift(st, val) SKM_sk_unshift(X509_OBJECT, (st), (val))
#define sk_X509_OBJECT_find(st, val) SKM_sk_find(X509_OBJECT, (st), (val))
#define sk_X509_OBJECT_find_ex(st, val) SKM_sk_find_ex(X509_OBJECT, (st), (val))
#define sk_X509_OBJECT_delete(st, i) SKM_sk_delete(X509_OBJECT, (st), (i))
#define sk_X509_OBJECT_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_OBJECT, (st), (ptr))
#define sk_X509_OBJECT_insert(st, val, i) SKM_sk_insert(X509_OBJECT, (st), (val), (i))
#define sk_X509_OBJECT_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_OBJECT, (st), (cmp))
#define sk_X509_OBJECT_dup(st) SKM_sk_dup(X509_OBJECT, st)
#define sk_X509_OBJECT_pop_free(st, free_func) SKM_sk_pop_free(X509_OBJECT, (st), (free_func))
#define sk_X509_OBJECT_shift(st) SKM_sk_shift(X509_OBJECT, (st))
#define sk_X509_OBJECT_pop(st) SKM_sk_pop(X509_OBJECT, (st))
#define sk_X509_OBJECT_sort(st) SKM_sk_sort(X509_OBJECT, (st))
#define sk_X509_OBJECT_is_sorted(st) SKM_sk_is_sorted(X509_OBJECT, (st))

#define sk_X509_POLICY_DATA_new(st) SKM_sk_new(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_new_null() SKM_sk_new_null(X509_POLICY_DATA)
#define sk_X509_POLICY_DATA_free(st) SKM_sk_free(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_num(st) SKM_sk_num(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_value(st, i) SKM_sk_value(X509_POLICY_DATA, (st), (i))
#define sk_X509_POLICY_DATA_set(st, i, val) SKM_sk_set(X509_POLICY_DATA, (st), (i), (val))
#define sk_X509_POLICY_DATA_zero(st) SKM_sk_zero(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_push(st, val) SKM_sk_push(X509_POLICY_DATA, (st), (val))
#define sk_X509_POLICY_DATA_unshift(st, val) SKM_sk_unshift(X509_POLICY_DATA, (st), (val))
#define sk_X509_POLICY_DATA_find(st, val) SKM_sk_find(X509_POLICY_DATA, (st), (val))
#define sk_X509_POLICY_DATA_find_ex(st, val) SKM_sk_find_ex(X509_POLICY_DATA, (st), (val))
#define sk_X509_POLICY_DATA_delete(st, i) SKM_sk_delete(X509_POLICY_DATA, (st), (i))
#define sk_X509_POLICY_DATA_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_POLICY_DATA, (st), (ptr))
#define sk_X509_POLICY_DATA_insert(st, val, i) SKM_sk_insert(X509_POLICY_DATA, (st), (val), (i))
#define sk_X509_POLICY_DATA_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_POLICY_DATA, (st), (cmp))
#define sk_X509_POLICY_DATA_dup(st) SKM_sk_dup(X509_POLICY_DATA, st)
#define sk_X509_POLICY_DATA_pop_free(st, free_func) SKM_sk_pop_free(X509_POLICY_DATA, (st), (free_func))
#define sk_X509_POLICY_DATA_shift(st) SKM_sk_shift(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_pop(st) SKM_sk_pop(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_sort(st) SKM_sk_sort(X509_POLICY_DATA, (st))
#define sk_X509_POLICY_DATA_is_sorted(st) SKM_sk_is_sorted(X509_POLICY_DATA, (st))

#define sk_X509_POLICY_NODE_new(st) SKM_sk_new(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_new_null() SKM_sk_new_null(X509_POLICY_NODE)
#define sk_X509_POLICY_NODE_free(st) SKM_sk_free(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_num(st) SKM_sk_num(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_value(st, i) SKM_sk_value(X509_POLICY_NODE, (st), (i))
#define sk_X509_POLICY_NODE_set(st, i, val) SKM_sk_set(X509_POLICY_NODE, (st), (i), (val))
#define sk_X509_POLICY_NODE_zero(st) SKM_sk_zero(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_push(st, val) SKM_sk_push(X509_POLICY_NODE, (st), (val))
#define sk_X509_POLICY_NODE_unshift(st, val) SKM_sk_unshift(X509_POLICY_NODE, (st), (val))
#define sk_X509_POLICY_NODE_find(st, val) SKM_sk_find(X509_POLICY_NODE, (st), (val))
#define sk_X509_POLICY_NODE_find_ex(st, val) SKM_sk_find_ex(X509_POLICY_NODE, (st), (val))
#define sk_X509_POLICY_NODE_delete(st, i) SKM_sk_delete(X509_POLICY_NODE, (st), (i))
#define sk_X509_POLICY_NODE_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_POLICY_NODE, (st), (ptr))
#define sk_X509_POLICY_NODE_insert(st, val, i) SKM_sk_insert(X509_POLICY_NODE, (st), (val), (i))
#define sk_X509_POLICY_NODE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_POLICY_NODE, (st), (cmp))
#define sk_X509_POLICY_NODE_dup(st) SKM_sk_dup(X509_POLICY_NODE, st)
#define sk_X509_POLICY_NODE_pop_free(st, free_func) SKM_sk_pop_free(X509_POLICY_NODE, (st), (free_func))
#define sk_X509_POLICY_NODE_shift(st) SKM_sk_shift(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_pop(st) SKM_sk_pop(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_sort(st) SKM_sk_sort(X509_POLICY_NODE, (st))
#define sk_X509_POLICY_NODE_is_sorted(st) SKM_sk_is_sorted(X509_POLICY_NODE, (st))

#define sk_X509_POLICY_REF_new(st) SKM_sk_new(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_new_null() SKM_sk_new_null(X509_POLICY_REF)
#define sk_X509_POLICY_REF_free(st) SKM_sk_free(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_num(st) SKM_sk_num(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_value(st, i) SKM_sk_value(X509_POLICY_REF, (st), (i))
#define sk_X509_POLICY_REF_set(st, i, val) SKM_sk_set(X509_POLICY_REF, (st), (i), (val))
#define sk_X509_POLICY_REF_zero(st) SKM_sk_zero(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_push(st, val) SKM_sk_push(X509_POLICY_REF, (st), (val))
#define sk_X509_POLICY_REF_unshift(st, val) SKM_sk_unshift(X509_POLICY_REF, (st), (val))
#define sk_X509_POLICY_REF_find(st, val) SKM_sk_find(X509_POLICY_REF, (st), (val))
#define sk_X509_POLICY_REF_find_ex(st, val) SKM_sk_find_ex(X509_POLICY_REF, (st), (val))
#define sk_X509_POLICY_REF_delete(st, i) SKM_sk_delete(X509_POLICY_REF, (st), (i))
#define sk_X509_POLICY_REF_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_POLICY_REF, (st), (ptr))
#define sk_X509_POLICY_REF_insert(st, val, i) SKM_sk_insert(X509_POLICY_REF, (st), (val), (i))
#define sk_X509_POLICY_REF_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_POLICY_REF, (st), (cmp))
#define sk_X509_POLICY_REF_dup(st) SKM_sk_dup(X509_POLICY_REF, st)
#define sk_X509_POLICY_REF_pop_free(st, free_func) SKM_sk_pop_free(X509_POLICY_REF, (st), (free_func))
#define sk_X509_POLICY_REF_shift(st) SKM_sk_shift(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_pop(st) SKM_sk_pop(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_sort(st) SKM_sk_sort(X509_POLICY_REF, (st))
#define sk_X509_POLICY_REF_is_sorted(st) SKM_sk_is_sorted(X509_POLICY_REF, (st))

#define sk_X509_PURPOSE_new(st) SKM_sk_new(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_new_null() SKM_sk_new_null(X509_PURPOSE)
#define sk_X509_PURPOSE_free(st) SKM_sk_free(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_num(st) SKM_sk_num(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_value(st, i) SKM_sk_value(X509_PURPOSE, (st), (i))
#define sk_X509_PURPOSE_set(st, i, val) SKM_sk_set(X509_PURPOSE, (st), (i), (val))
#define sk_X509_PURPOSE_zero(st) SKM_sk_zero(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_push(st, val) SKM_sk_push(X509_PURPOSE, (st), (val))
#define sk_X509_PURPOSE_unshift(st, val) SKM_sk_unshift(X509_PURPOSE, (st), (val))
#define sk_X509_PURPOSE_find(st, val) SKM_sk_find(X509_PURPOSE, (st), (val))
#define sk_X509_PURPOSE_find_ex(st, val) SKM_sk_find_ex(X509_PURPOSE, (st), (val))
#define sk_X509_PURPOSE_delete(st, i) SKM_sk_delete(X509_PURPOSE, (st), (i))
#define sk_X509_PURPOSE_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_PURPOSE, (st), (ptr))
#define sk_X509_PURPOSE_insert(st, val, i) SKM_sk_insert(X509_PURPOSE, (st), (val), (i))
#define sk_X509_PURPOSE_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_PURPOSE, (st), (cmp))
#define sk_X509_PURPOSE_dup(st) SKM_sk_dup(X509_PURPOSE, st)
#define sk_X509_PURPOSE_pop_free(st, free_func) SKM_sk_pop_free(X509_PURPOSE, (st), (free_func))
#define sk_X509_PURPOSE_shift(st) SKM_sk_shift(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_pop(st) SKM_sk_pop(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_sort(st) SKM_sk_sort(X509_PURPOSE, (st))
#define sk_X509_PURPOSE_is_sorted(st) SKM_sk_is_sorted(X509_PURPOSE, (st))

#define sk_X509_REVOKED_new(st) SKM_sk_new(X509_REVOKED, (st))
#define sk_X509_REVOKED_new_null() SKM_sk_new_null(X509_REVOKED)
#define sk_X509_REVOKED_free(st) SKM_sk_free(X509_REVOKED, (st))
#define sk_X509_REVOKED_num(st) SKM_sk_num(X509_REVOKED, (st))
#define sk_X509_REVOKED_value(st, i) SKM_sk_value(X509_REVOKED, (st), (i))
#define sk_X509_REVOKED_set(st, i, val) SKM_sk_set(X509_REVOKED, (st), (i), (val))
#define sk_X509_REVOKED_zero(st) SKM_sk_zero(X509_REVOKED, (st))
#define sk_X509_REVOKED_push(st, val) SKM_sk_push(X509_REVOKED, (st), (val))
#define sk_X509_REVOKED_unshift(st, val) SKM_sk_unshift(X509_REVOKED, (st), (val))
#define sk_X509_REVOKED_find(st, val) SKM_sk_find(X509_REVOKED, (st), (val))
#define sk_X509_REVOKED_find_ex(st, val) SKM_sk_find_ex(X509_REVOKED, (st), (val))
#define sk_X509_REVOKED_delete(st, i) SKM_sk_delete(X509_REVOKED, (st), (i))
#define sk_X509_REVOKED_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_REVOKED, (st), (ptr))
#define sk_X509_REVOKED_insert(st, val, i) SKM_sk_insert(X509_REVOKED, (st), (val), (i))
#define sk_X509_REVOKED_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_REVOKED, (st), (cmp))
#define sk_X509_REVOKED_dup(st) SKM_sk_dup(X509_REVOKED, st)
#define sk_X509_REVOKED_pop_free(st, free_func) SKM_sk_pop_free(X509_REVOKED, (st), (free_func))
#define sk_X509_REVOKED_shift(st) SKM_sk_shift(X509_REVOKED, (st))
#define sk_X509_REVOKED_pop(st) SKM_sk_pop(X509_REVOKED, (st))
#define sk_X509_REVOKED_sort(st) SKM_sk_sort(X509_REVOKED, (st))
#define sk_X509_REVOKED_is_sorted(st) SKM_sk_is_sorted(X509_REVOKED, (st))

#define sk_X509_TRUST_new(st) SKM_sk_new(X509_TRUST, (st))
#define sk_X509_TRUST_new_null() SKM_sk_new_null(X509_TRUST)
#define sk_X509_TRUST_free(st) SKM_sk_free(X509_TRUST, (st))
#define sk_X509_TRUST_num(st) SKM_sk_num(X509_TRUST, (st))
#define sk_X509_TRUST_value(st, i) SKM_sk_value(X509_TRUST, (st), (i))
#define sk_X509_TRUST_set(st, i, val) SKM_sk_set(X509_TRUST, (st), (i), (val))
#define sk_X509_TRUST_zero(st) SKM_sk_zero(X509_TRUST, (st))
#define sk_X509_TRUST_push(st, val) SKM_sk_push(X509_TRUST, (st), (val))
#define sk_X509_TRUST_unshift(st, val) SKM_sk_unshift(X509_TRUST, (st), (val))
#define sk_X509_TRUST_find(st, val) SKM_sk_find(X509_TRUST, (st), (val))
#define sk_X509_TRUST_find_ex(st, val) SKM_sk_find_ex(X509_TRUST, (st), (val))
#define sk_X509_TRUST_delete(st, i) SKM_sk_delete(X509_TRUST, (st), (i))
#define sk_X509_TRUST_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_TRUST, (st), (ptr))
#define sk_X509_TRUST_insert(st, val, i) SKM_sk_insert(X509_TRUST, (st), (val), (i))
#define sk_X509_TRUST_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_TRUST, (st), (cmp))
#define sk_X509_TRUST_dup(st) SKM_sk_dup(X509_TRUST, st)
#define sk_X509_TRUST_pop_free(st, free_func) SKM_sk_pop_free(X509_TRUST, (st), (free_func))
#define sk_X509_TRUST_shift(st) SKM_sk_shift(X509_TRUST, (st))
#define sk_X509_TRUST_pop(st) SKM_sk_pop(X509_TRUST, (st))
#define sk_X509_TRUST_sort(st) SKM_sk_sort(X509_TRUST, (st))
#define sk_X509_TRUST_is_sorted(st) SKM_sk_is_sorted(X509_TRUST, (st))

#define sk_X509_VERIFY_PARAM_new(st) SKM_sk_new(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_new_null() SKM_sk_new_null(X509_VERIFY_PARAM)
#define sk_X509_VERIFY_PARAM_free(st) SKM_sk_free(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_num(st) SKM_sk_num(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_value(st, i) SKM_sk_value(X509_VERIFY_PARAM, (st), (i))
#define sk_X509_VERIFY_PARAM_set(st, i, val) SKM_sk_set(X509_VERIFY_PARAM, (st), (i), (val))
#define sk_X509_VERIFY_PARAM_zero(st) SKM_sk_zero(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_push(st, val) SKM_sk_push(X509_VERIFY_PARAM, (st), (val))
#define sk_X509_VERIFY_PARAM_unshift(st, val) SKM_sk_unshift(X509_VERIFY_PARAM, (st), (val))
#define sk_X509_VERIFY_PARAM_find(st, val) SKM_sk_find(X509_VERIFY_PARAM, (st), (val))
#define sk_X509_VERIFY_PARAM_find_ex(st, val) SKM_sk_find_ex(X509_VERIFY_PARAM, (st), (val))
#define sk_X509_VERIFY_PARAM_delete(st, i) SKM_sk_delete(X509_VERIFY_PARAM, (st), (i))
#define sk_X509_VERIFY_PARAM_delete_ptr(st, ptr) SKM_sk_delete_ptr(X509_VERIFY_PARAM, (st), (ptr))
#define sk_X509_VERIFY_PARAM_insert(st, val, i) SKM_sk_insert(X509_VERIFY_PARAM, (st), (val), (i))
#define sk_X509_VERIFY_PARAM_set_cmp_func(st, cmp) SKM_sk_set_cmp_func(X509_VERIFY_PARAM, (st), (cmp))
#define sk_X509_VERIFY_PARAM_dup(st) SKM_sk_dup(X509_VERIFY_PARAM, st)
#define sk_X509_VERIFY_PARAM_pop_free(st, free_func) SKM_sk_pop_free(X509_VERIFY_PARAM, (st), (free_func))
#define sk_X509_VERIFY_PARAM_shift(st) SKM_sk_shift(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_pop(st) SKM_sk_pop(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_sort(st) SKM_sk_sort(X509_VERIFY_PARAM, (st))
#define sk_X509_VERIFY_PARAM_is_sorted(st) SKM_sk_is_sorted(X509_VERIFY_PARAM, (st))

#define d2i_ASN1_SET_OF_ACCESS_DESCRIPTION(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(ACCESS_DESCRIPTION, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_ACCESS_DESCRIPTION(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(ACCESS_DESCRIPTION, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_ACCESS_DESCRIPTION(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(ACCESS_DESCRIPTION, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_ACCESS_DESCRIPTION(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(ACCESS_DESCRIPTION, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_ASN1_INTEGER(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(ASN1_INTEGER, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_ASN1_INTEGER(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(ASN1_INTEGER, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_ASN1_INTEGER(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(ASN1_INTEGER, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_ASN1_INTEGER(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(ASN1_INTEGER, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_ASN1_OBJECT(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(ASN1_OBJECT, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_ASN1_OBJECT(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(ASN1_OBJECT, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_ASN1_OBJECT(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(ASN1_OBJECT, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_ASN1_OBJECT(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(ASN1_OBJECT, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_ASN1_TYPE(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(ASN1_TYPE, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_ASN1_TYPE(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(ASN1_TYPE, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_ASN1_TYPE(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(ASN1_TYPE, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_ASN1_TYPE(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(ASN1_TYPE, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_DIST_POINT(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(DIST_POINT, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_DIST_POINT(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(DIST_POINT, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_DIST_POINT(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(DIST_POINT, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_DIST_POINT(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(DIST_POINT, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_GENERAL_NAME(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(GENERAL_NAME, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_GENERAL_NAME(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(GENERAL_NAME, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_GENERAL_NAME(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(GENERAL_NAME, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_GENERAL_NAME(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(GENERAL_NAME, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_OCSP_ONEREQ(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(OCSP_ONEREQ, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_OCSP_ONEREQ(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(OCSP_ONEREQ, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_OCSP_ONEREQ(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(OCSP_ONEREQ, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_OCSP_ONEREQ(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(OCSP_ONEREQ, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_OCSP_SINGLERESP(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(OCSP_SINGLERESP, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_OCSP_SINGLERESP(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(OCSP_SINGLERESP, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_OCSP_SINGLERESP(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(OCSP_SINGLERESP, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_OCSP_SINGLERESP(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(OCSP_SINGLERESP, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_PKCS12_SAFEBAG(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(PKCS12_SAFEBAG, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_PKCS12_SAFEBAG(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(PKCS12_SAFEBAG, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_PKCS12_SAFEBAG(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(PKCS12_SAFEBAG, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_PKCS12_SAFEBAG(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(PKCS12_SAFEBAG, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_PKCS7(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(PKCS7, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_PKCS7(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(PKCS7, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_PKCS7(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(PKCS7, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_PKCS7(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(PKCS7, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_PKCS7_RECIP_INFO(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(PKCS7_RECIP_INFO, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_PKCS7_RECIP_INFO(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(PKCS7_RECIP_INFO, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_PKCS7_RECIP_INFO(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(PKCS7_RECIP_INFO, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_PKCS7_RECIP_INFO(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(PKCS7_RECIP_INFO, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(PKCS7_SIGNER_INFO, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(PKCS7_SIGNER_INFO, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_PKCS7_SIGNER_INFO(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(PKCS7_SIGNER_INFO, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_PKCS7_SIGNER_INFO(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(PKCS7_SIGNER_INFO, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_POLICYINFO(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(POLICYINFO, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_POLICYINFO(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(POLICYINFO, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_POLICYINFO(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(POLICYINFO, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_POLICYINFO(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(POLICYINFO, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_POLICYQUALINFO(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(POLICYQUALINFO, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_POLICYQUALINFO(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(POLICYQUALINFO, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_POLICYQUALINFO(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(POLICYQUALINFO, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_POLICYQUALINFO(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(POLICYQUALINFO, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_SXNETID(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(SXNETID, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_SXNETID(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(SXNETID, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_SXNETID(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(SXNETID, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_SXNETID(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(SXNETID, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_ALGOR(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_ALGOR, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_ALGOR(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_ALGOR, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_ALGOR(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_ALGOR, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_ALGOR(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_ALGOR, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_ATTRIBUTE(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_ATTRIBUTE, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_ATTRIBUTE(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_ATTRIBUTE, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_ATTRIBUTE(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_ATTRIBUTE, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_ATTRIBUTE(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_ATTRIBUTE, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_CRL(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_CRL, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_CRL(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_CRL, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_CRL(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_CRL, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_CRL(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_CRL, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_EXTENSION(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_EXTENSION, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_EXTENSION(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_EXTENSION, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_EXTENSION(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_EXTENSION, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_EXTENSION(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_EXTENSION, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_NAME_ENTRY(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_NAME_ENTRY, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_NAME_ENTRY(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_NAME_ENTRY, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_NAME_ENTRY(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_NAME_ENTRY, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_NAME_ENTRY(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_NAME_ENTRY, (buf), (len), (d2i_func), (free_func))

#define d2i_ASN1_SET_OF_X509_REVOKED(st, pp, length, d2i_func, free_func, ex_tag, ex_class) \
	SKM_ASN1_SET_OF_d2i(X509_REVOKED, (st), (pp), (length), (d2i_func), (free_func), (ex_tag), (ex_class))
#define i2d_ASN1_SET_OF_X509_REVOKED(st, pp, i2d_func, ex_tag, ex_class, is_set) \
	SKM_ASN1_SET_OF_i2d(X509_REVOKED, (st), (pp), (i2d_func), (ex_tag), (ex_class), (is_set))
#define ASN1_seq_pack_X509_REVOKED(st, i2d_func, buf, len) \
	SKM_ASN1_seq_pack(X509_REVOKED, (st), (i2d_func), (buf), (len))
#define ASN1_seq_unpack_X509_REVOKED(buf, len, d2i_func, free_func) \
	SKM_ASN1_seq_unpack(X509_REVOKED, (buf), (len), (d2i_func), (free_func))

#define PKCS12_decrypt_d2i_PKCS12_SAFEBAG(algor, d2i_func, free_func, pass, passlen, oct, seq) \
	SKM_PKCS12_decrypt_d2i(PKCS12_SAFEBAG, (algor), (d2i_func), (free_func), (pass), (passlen), (oct), (seq))

#define PKCS12_decrypt_d2i_PKCS7(algor, d2i_func, free_func, pass, passlen, oct, seq) \
	SKM_PKCS12_decrypt_d2i(PKCS7, (algor), (d2i_func), (free_func), (pass), (passlen), (oct), (seq))
/* End of util/mkstack.pl block, you may now edit :-) */

#define OPENSSL_VERSION_NUMBER	0x0090812fL
#ifdef OPENSSL_FIPS
#define OPENSSL_VERSION_TEXT	"OpenSSL 0.9.8r-fips 8 Feb 2011"
#else
#define OPENSSL_VERSION_TEXT	"OpenSSL 0.9.8r 8 Feb 2011"
#endif
#define OPENSSL_VERSION_PTEXT	" part of " OPENSSL_VERSION_TEXT



#define SHLIB_VERSION_HISTORY ""
#define SHLIB_VERSION_NUMBER "0.9.8"

#ifdef NO_ASN1_TYPEDEFS
#define ASN1_INTEGER		ASN1_STRING
#define ASN1_ENUMERATED		ASN1_STRING
#define ASN1_BIT_STRING		ASN1_STRING
#define ASN1_OCTET_STRING	ASN1_STRING
#define ASN1_PRINTABLESTRING	ASN1_STRING
#define ASN1_T61STRING		ASN1_STRING
#define ASN1_IA5STRING		ASN1_STRING
#define ASN1_UTCTIME		ASN1_STRING
#define ASN1_GENERALIZEDTIME	ASN1_STRING
#define ASN1_TIME		ASN1_STRING
#define ASN1_GENERALSTRING	ASN1_STRING
#define ASN1_UNIVERSALSTRING	ASN1_STRING
#define ASN1_BMPSTRING		ASN1_STRING
#define ASN1_VISIBLESTRING	ASN1_STRING
#define ASN1_UTF8STRING		ASN1_STRING
#define ASN1_BOOLEAN		int
#define ASN1_NULL		int
#else
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
#endif

#ifdef OPENSSL_SYS_WIN32
#undef X509_NAME
#undef X509_EXTENSIONS
#undef X509_CERT_PAIR
#undef PKCS7_ISSUER_AND_SERIAL
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#ifdef BIGNUM
#undef BIGNUM
#endif
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;

typedef struct buf_mem_st BUF_MEM;

typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;

typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;

typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;

typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;

typedef struct rand_meth_st RAND_METHOD;

typedef struct ecdh_method ECDH_METHOD;
typedef struct ecdsa_method ECDSA_METHOD;

typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct X509_name_st X509_NAME;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

typedef struct v3_ext_ctx X509V3_CTX;
typedef struct conf_st CONF;

typedef struct store_st STORE;
typedef struct store_method_st STORE_METHOD;

typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;

typedef struct st_ERR_FNS ERR_FNS;

typedef struct engine_st ENGINE;

typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;

/* If placed in pkcs12.h, we end up with a circular depency with pkcs7.h */
#define DECLARE_PKCS12_STACK_OF(type) /* Nothing */
#define IMPLEMENT_PKCS12_STACK_OF(type) /* Nothing */

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
/* Callback types for crypto.h */
typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                          int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
                          int idx, long argl, void *argp);

typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;


/* Hack a long name in crypto/cryptlib.c */
#undef int_CRYPTO_set_do_dynlock_callback
#define int_CRYPTO_set_do_dynlock_callback	int_CRYPTO_set_do_dynlock_cb

/* Hack a long name in crypto/ex_data.c */
#undef CRYPTO_get_ex_data_implementation
#define CRYPTO_get_ex_data_implementation	CRYPTO_get_ex_data_impl
#undef CRYPTO_set_ex_data_implementation
#define CRYPTO_set_ex_data_implementation	CRYPTO_set_ex_data_impl

/* Hack a long name in crypto/asn1/a_mbstr.c */
#undef ASN1_STRING_set_default_mask_asc
#define ASN1_STRING_set_default_mask_asc	ASN1_STRING_set_def_mask_asc

#if 0 /* No longer needed, since safestack macro magic does the job */
/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_SIGNER_INFO) */
#undef i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO
#define i2d_ASN1_SET_OF_PKCS7_SIGNER_INFO	i2d_ASN1_SET_OF_PKCS7_SIGINF
#undef d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO
#define d2i_ASN1_SET_OF_PKCS7_SIGNER_INFO	d2i_ASN1_SET_OF_PKCS7_SIGINF
#endif

#if 0 /* No longer needed, since safestack macro magic does the job */
/* Hack the names created with DECLARE_ASN1_SET_OF(PKCS7_RECIP_INFO) */
#undef i2d_ASN1_SET_OF_PKCS7_RECIP_INFO
#define i2d_ASN1_SET_OF_PKCS7_RECIP_INFO	i2d_ASN1_SET_OF_PKCS7_RECINF
#undef d2i_ASN1_SET_OF_PKCS7_RECIP_INFO
#define d2i_ASN1_SET_OF_PKCS7_RECIP_INFO	d2i_ASN1_SET_OF_PKCS7_RECINF
#endif

#if 0 /* No longer needed, since safestack macro magic does the job */
/* Hack the names created with DECLARE_ASN1_SET_OF(ACCESS_DESCRIPTION) */
#undef i2d_ASN1_SET_OF_ACCESS_DESCRIPTION
#define i2d_ASN1_SET_OF_ACCESS_DESCRIPTION	i2d_ASN1_SET_OF_ACC_DESC
#undef d2i_ASN1_SET_OF_ACCESS_DESCRIPTION
#define d2i_ASN1_SET_OF_ACCESS_DESCRIPTION	d2i_ASN1_SET_OF_ACC_DESC
#endif

/* Hack the names created with DECLARE_PEM_rw(NETSCAPE_CERT_SEQUENCE) */
#undef PEM_read_NETSCAPE_CERT_SEQUENCE
#define PEM_read_NETSCAPE_CERT_SEQUENCE		PEM_read_NS_CERT_SEQ
#undef PEM_write_NETSCAPE_CERT_SEQUENCE
#define PEM_write_NETSCAPE_CERT_SEQUENCE	PEM_write_NS_CERT_SEQ
#undef PEM_read_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_read_bio_NETSCAPE_CERT_SEQUENCE	PEM_read_bio_NS_CERT_SEQ
#undef PEM_write_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_write_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_bio_NS_CERT_SEQ
#undef PEM_write_cb_bio_NETSCAPE_CERT_SEQUENCE
#define PEM_write_cb_bio_NETSCAPE_CERT_SEQUENCE	PEM_write_cb_bio_NS_CERT_SEQ

/* Hack the names created with DECLARE_PEM_rw(PKCS8_PRIV_KEY_INFO) */
#undef PEM_read_PKCS8_PRIV_KEY_INFO
#define PEM_read_PKCS8_PRIV_KEY_INFO		PEM_read_P8_PRIV_KEY_INFO
#undef PEM_write_PKCS8_PRIV_KEY_INFO
#define PEM_write_PKCS8_PRIV_KEY_INFO		PEM_write_P8_PRIV_KEY_INFO
#undef PEM_read_bio_PKCS8_PRIV_KEY_INFO
#define PEM_read_bio_PKCS8_PRIV_KEY_INFO	PEM_read_bio_P8_PRIV_KEY_INFO
#undef PEM_write_bio_PKCS8_PRIV_KEY_INFO
#define PEM_write_bio_PKCS8_PRIV_KEY_INFO	PEM_write_bio_P8_PRIV_KEY_INFO
#undef PEM_write_cb_bio_PKCS8_PRIV_KEY_INFO
#define PEM_write_cb_bio_PKCS8_PRIV_KEY_INFO	PEM_wrt_cb_bio_P8_PRIV_KEY_INFO

/* Hack other PEM names */
#undef PEM_write_bio_PKCS8PrivateKey_nid
#define PEM_write_bio_PKCS8PrivateKey_nid	PEM_write_bio_PKCS8PrivKey_nid

/* Hack some long X509 names */
#undef X509_REVOKED_get_ext_by_critical
#define X509_REVOKED_get_ext_by_critical	X509_REVOKED_get_ext_by_critic
#undef X509_policy_tree_get0_user_policies
#define X509_policy_tree_get0_user_policies	X509_pcy_tree_get0_usr_policies
#undef X509_policy_node_get0_qualifiers
#define X509_policy_node_get0_qualifiers	X509_pcy_node_get0_qualifiers
#undef X509_STORE_CTX_get_explicit_policy
#define X509_STORE_CTX_get_explicit_policy	X509_STORE_CTX_get_expl_policy
#undef X509_STORE_CTX_get0_current_issuer
#define X509_STORE_CTX_get0_current_issuer	X509_STORE_CTX_get0_cur_issuer

/* Hack some long CRYPTO names */
#undef CRYPTO_set_dynlock_destroy_callback
#define CRYPTO_set_dynlock_destroy_callback     CRYPTO_set_dynlock_destroy_cb
#undef CRYPTO_set_dynlock_create_callback
#define CRYPTO_set_dynlock_create_callback      CRYPTO_set_dynlock_create_cb
#undef CRYPTO_set_dynlock_lock_callback
#define CRYPTO_set_dynlock_lock_callback        CRYPTO_set_dynlock_lock_cb
#undef CRYPTO_get_dynlock_lock_callback
#define CRYPTO_get_dynlock_lock_callback        CRYPTO_get_dynlock_lock_cb
#undef CRYPTO_get_dynlock_destroy_callback
#define CRYPTO_get_dynlock_destroy_callback     CRYPTO_get_dynlock_destroy_cb
#undef CRYPTO_get_dynlock_create_callback
#define CRYPTO_get_dynlock_create_callback      CRYPTO_get_dynlock_create_cb
#undef CRYPTO_set_locked_mem_ex_functions
#define CRYPTO_set_locked_mem_ex_functions      CRYPTO_set_locked_mem_ex_funcs
#undef CRYPTO_get_locked_mem_ex_functions
#define CRYPTO_get_locked_mem_ex_functions      CRYPTO_get_locked_mem_ex_funcs

/* Hack some long SSL names */
#undef SSL_CTX_set_default_verify_paths
#define SSL_CTX_set_default_verify_paths        SSL_CTX_set_def_verify_paths
#undef SSL_get_ex_data_X509_STORE_CTX_idx
#define SSL_get_ex_data_X509_STORE_CTX_idx      SSL_get_ex_d_X509_STORE_CTX_idx
#undef SSL_add_file_cert_subjects_to_stack
#define SSL_add_file_cert_subjects_to_stack     SSL_add_file_cert_subjs_to_stk
#undef SSL_add_dir_cert_subjects_to_stack
#define SSL_add_dir_cert_subjects_to_stack      SSL_add_dir_cert_subjs_to_stk
#undef SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_certificate_chain_file      SSL_CTX_use_cert_chain_file
#undef SSL_CTX_set_cert_verify_callback
#define SSL_CTX_set_cert_verify_callback        SSL_CTX_set_cert_verify_cb
#undef SSL_CTX_set_default_passwd_cb_userdata
#define SSL_CTX_set_default_passwd_cb_userdata  SSL_CTX_set_def_passwd_cb_ud
#undef SSL_COMP_get_compression_methods
#define SSL_COMP_get_compression_methods	SSL_COMP_get_compress_methods

#undef ssl_add_clienthello_renegotiate_ext
#define ssl_add_clienthello_renegotiate_ext	ssl_add_clienthello_reneg_ext
#undef ssl_add_serverhello_renegotiate_ext
#define ssl_add_serverhello_renegotiate_ext	ssl_add_serverhello_reneg_ext
#undef ssl_parse_clienthello_renegotiate_ext
#define ssl_parse_clienthello_renegotiate_ext	ssl_parse_clienthello_reneg_ext
#undef ssl_parse_serverhello_renegotiate_ext
#define ssl_parse_serverhello_renegotiate_ext	ssl_parse_serverhello_reneg_ext

/* Hack some long ENGINE names */
#undef ENGINE_get_default_BN_mod_exp_crt
#define ENGINE_get_default_BN_mod_exp_crt	ENGINE_get_def_BN_mod_exp_crt
#undef ENGINE_set_default_BN_mod_exp_crt
#define ENGINE_set_default_BN_mod_exp_crt	ENGINE_set_def_BN_mod_exp_crt
#undef ENGINE_set_load_privkey_function
#define ENGINE_set_load_privkey_function        ENGINE_set_load_privkey_fn
#undef ENGINE_get_load_privkey_function
#define ENGINE_get_load_privkey_function        ENGINE_get_load_privkey_fn
#undef ENGINE_set_load_ssl_client_cert_function
#define ENGINE_set_load_ssl_client_cert_function \
						ENGINE_set_ld_ssl_clnt_cert_fn
#undef ENGINE_get_ssl_client_cert_function
#define ENGINE_get_ssl_client_cert_function	ENGINE_get_ssl_client_cert_fn

/* Hack some long OCSP names */
#undef OCSP_REQUEST_get_ext_by_critical
#define OCSP_REQUEST_get_ext_by_critical        OCSP_REQUEST_get_ext_by_crit
#undef OCSP_BASICRESP_get_ext_by_critical
#define OCSP_BASICRESP_get_ext_by_critical      OCSP_BASICRESP_get_ext_by_crit
#undef OCSP_SINGLERESP_get_ext_by_critical
#define OCSP_SINGLERESP_get_ext_by_critical     OCSP_SINGLERESP_get_ext_by_crit

/* Hack some long DES names */
#undef _ossl_old_des_ede3_cfb64_encrypt
#define _ossl_old_des_ede3_cfb64_encrypt	_ossl_odes_ede3_cfb64_encrypt
#undef _ossl_old_des_ede3_ofb64_encrypt
#define _ossl_old_des_ede3_ofb64_encrypt	_ossl_odes_ede3_ofb64_encrypt

/* Hack some long EVP names */
#undef OPENSSL_add_all_algorithms_noconf
#define OPENSSL_add_all_algorithms_noconf	OPENSSL_add_all_algo_noconf
#undef OPENSSL_add_all_algorithms_conf
#define OPENSSL_add_all_algorithms_conf		OPENSSL_add_all_algo_conf

/* Hack some long EC names */
#undef EC_GROUP_set_point_conversion_form
#define EC_GROUP_set_point_conversion_form	EC_GROUP_set_point_conv_form
#undef EC_GROUP_get_point_conversion_form
#define EC_GROUP_get_point_conversion_form	EC_GROUP_get_point_conv_form
#undef EC_GROUP_clear_free_all_extra_data
#define EC_GROUP_clear_free_all_extra_data	EC_GROUP_clr_free_all_xtra_data
#undef EC_POINT_set_Jprojective_coordinates_GFp
#define EC_POINT_set_Jprojective_coordinates_GFp \
                                                EC_POINT_set_Jproj_coords_GFp
#undef EC_POINT_get_Jprojective_coordinates_GFp
#define EC_POINT_get_Jprojective_coordinates_GFp \
                                                EC_POINT_get_Jproj_coords_GFp
#undef EC_POINT_set_affine_coordinates_GFp
#define EC_POINT_set_affine_coordinates_GFp     EC_POINT_set_affine_coords_GFp
#undef EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_get_affine_coordinates_GFp     EC_POINT_get_affine_coords_GFp
#undef EC_POINT_set_compressed_coordinates_GFp
#define EC_POINT_set_compressed_coordinates_GFp EC_POINT_set_compr_coords_GFp
#undef EC_POINT_set_affine_coordinates_GF2m
#define EC_POINT_set_affine_coordinates_GF2m    EC_POINT_set_affine_coords_GF2m
#undef EC_POINT_get_affine_coordinates_GF2m
#define EC_POINT_get_affine_coordinates_GF2m    EC_POINT_get_affine_coords_GF2m
#undef EC_POINT_set_compressed_coordinates_GF2m
#define EC_POINT_set_compressed_coordinates_GF2m \
                                                EC_POINT_set_compr_coords_GF2m
#undef ec_GF2m_simple_group_clear_finish
#define ec_GF2m_simple_group_clear_finish        ec_GF2m_simple_grp_clr_finish
#undef ec_GF2m_simple_group_check_discriminant
#define ec_GF2m_simple_group_check_discriminant	ec_GF2m_simple_grp_chk_discrim
#undef ec_GF2m_simple_point_clear_finish
#define ec_GF2m_simple_point_clear_finish        ec_GF2m_simple_pt_clr_finish
#undef ec_GF2m_simple_point_set_to_infinity
#define ec_GF2m_simple_point_set_to_infinity     ec_GF2m_simple_pt_set_to_inf
#undef ec_GF2m_simple_points_make_affine
#define ec_GF2m_simple_points_make_affine        ec_GF2m_simple_pts_make_affine
#undef ec_GF2m_simple_point_set_affine_coordinates
#define ec_GF2m_simple_point_set_affine_coordinates \
                                                ec_GF2m_smp_pt_set_af_coords
#undef ec_GF2m_simple_point_get_affine_coordinates
#define ec_GF2m_simple_point_get_affine_coordinates \
                                                ec_GF2m_smp_pt_get_af_coords
#undef ec_GF2m_simple_set_compressed_coordinates
#define ec_GF2m_simple_set_compressed_coordinates \
                                                ec_GF2m_smp_set_compr_coords
#undef ec_GFp_simple_group_set_curve_GFp
#define ec_GFp_simple_group_set_curve_GFp       ec_GFp_simple_grp_set_curve_GFp
#undef ec_GFp_simple_group_get_curve_GFp
#define ec_GFp_simple_group_get_curve_GFp       ec_GFp_simple_grp_get_curve_GFp
#undef ec_GFp_simple_group_clear_finish
#define ec_GFp_simple_group_clear_finish        ec_GFp_simple_grp_clear_finish
#undef ec_GFp_simple_group_set_generator
#define ec_GFp_simple_group_set_generator       ec_GFp_simple_grp_set_generator
#undef ec_GFp_simple_group_get0_generator
#define ec_GFp_simple_group_get0_generator      ec_GFp_simple_grp_gt0_generator
#undef ec_GFp_simple_group_get_cofactor
#define ec_GFp_simple_group_get_cofactor        ec_GFp_simple_grp_get_cofactor
#undef ec_GFp_simple_point_clear_finish
#define ec_GFp_simple_point_clear_finish        ec_GFp_simple_pt_clear_finish
#undef ec_GFp_simple_point_set_to_infinity
#define ec_GFp_simple_point_set_to_infinity     ec_GFp_simple_pt_set_to_inf
#undef ec_GFp_simple_points_make_affine
#define ec_GFp_simple_points_make_affine        ec_GFp_simple_pts_make_affine
#undef ec_GFp_simple_group_get_curve_GFp
#define ec_GFp_simple_group_get_curve_GFp       ec_GFp_simple_grp_get_curve_GFp
#undef ec_GFp_simple_set_Jprojective_coordinates_GFp
#define ec_GFp_simple_set_Jprojective_coordinates_GFp \
                                                ec_GFp_smp_set_Jproj_coords_GFp
#undef ec_GFp_simple_get_Jprojective_coordinates_GFp
#define ec_GFp_simple_get_Jprojective_coordinates_GFp \
                                                ec_GFp_smp_get_Jproj_coords_GFp
#undef ec_GFp_simple_point_set_affine_coordinates_GFp
#define ec_GFp_simple_point_set_affine_coordinates_GFp \
                                                ec_GFp_smp_pt_set_af_coords_GFp
#undef ec_GFp_simple_point_get_affine_coordinates_GFp
#define ec_GFp_simple_point_get_affine_coordinates_GFp \
                                                ec_GFp_smp_pt_get_af_coords_GFp
#undef ec_GFp_simple_set_compressed_coordinates_GFp
#define ec_GFp_simple_set_compressed_coordinates_GFp \
                                                ec_GFp_smp_set_compr_coords_GFp
#undef ec_GFp_simple_point_set_affine_coordinates
#define ec_GFp_simple_point_set_affine_coordinates \
                                                ec_GFp_smp_pt_set_af_coords
#undef ec_GFp_simple_point_get_affine_coordinates
#define ec_GFp_simple_point_get_affine_coordinates \
                                                ec_GFp_smp_pt_get_af_coords
#undef ec_GFp_simple_set_compressed_coordinates
#define ec_GFp_simple_set_compressed_coordinates \
                                                ec_GFp_smp_set_compr_coords
#undef ec_GFp_simple_group_check_discriminant
#define ec_GFp_simple_group_check_discriminant	ec_GFp_simple_grp_chk_discrim

/* Hack som long STORE names */
#undef STORE_method_set_initialise_function
#define STORE_method_set_initialise_function	STORE_meth_set_initialise_fn
#undef STORE_method_set_cleanup_function
#define STORE_method_set_cleanup_function	STORE_meth_set_cleanup_fn
#undef STORE_method_set_generate_function
#define STORE_method_set_generate_function	STORE_meth_set_generate_fn
#undef STORE_method_set_modify_function
#define STORE_method_set_modify_function	STORE_meth_set_modify_fn
#undef STORE_method_set_revoke_function
#define STORE_method_set_revoke_function	STORE_meth_set_revoke_fn
#undef STORE_method_set_delete_function
#define STORE_method_set_delete_function	STORE_meth_set_delete_fn
#undef STORE_method_set_list_start_function
#define STORE_method_set_list_start_function	STORE_meth_set_list_start_fn
#undef STORE_method_set_list_next_function
#define STORE_method_set_list_next_function	STORE_meth_set_list_next_fn
#undef STORE_method_set_list_end_function
#define STORE_method_set_list_end_function	STORE_meth_set_list_end_fn
#undef STORE_method_set_update_store_function
#define STORE_method_set_update_store_function	STORE_meth_set_update_store_fn
#undef STORE_method_set_lock_store_function
#define STORE_method_set_lock_store_function	STORE_meth_set_lock_store_fn
#undef STORE_method_set_unlock_store_function
#define STORE_method_set_unlock_store_function	STORE_meth_set_unlock_store_fn
#undef STORE_method_get_initialise_function
#define STORE_method_get_initialise_function	STORE_meth_get_initialise_fn
#undef STORE_method_get_cleanup_function
#define STORE_method_get_cleanup_function	STORE_meth_get_cleanup_fn
#undef STORE_method_get_generate_function
#define STORE_method_get_generate_function	STORE_meth_get_generate_fn
#undef STORE_method_get_modify_function
#define STORE_method_get_modify_function	STORE_meth_get_modify_fn
#undef STORE_method_get_revoke_function
#define STORE_method_get_revoke_function	STORE_meth_get_revoke_fn
#undef STORE_method_get_delete_function
#define STORE_method_get_delete_function	STORE_meth_get_delete_fn
#undef STORE_method_get_list_start_function
#define STORE_method_get_list_start_function	STORE_meth_get_list_start_fn
#undef STORE_method_get_list_next_function
#define STORE_method_get_list_next_function	STORE_meth_get_list_next_fn
#undef STORE_method_get_list_end_function
#define STORE_method_get_list_end_function	STORE_meth_get_list_end_fn
#undef STORE_method_get_update_store_function
#define STORE_method_get_update_store_function	STORE_meth_get_update_store_fn
#undef STORE_method_get_lock_store_function
#define STORE_method_get_lock_store_function	STORE_meth_get_lock_store_fn
#undef STORE_method_get_unlock_store_function
#define STORE_method_get_unlock_store_function	STORE_meth_get_unlock_store_fn

/* Hack some long CMS names */
#undef CMS_RecipientInfo_ktri_get0_algs
#define CMS_RecipientInfo_ktri_get0_algs	CMS_RecipInfo_ktri_get0_algs
#undef CMS_RecipientInfo_ktri_get0_signer_id
#define CMS_RecipientInfo_ktri_get0_signer_id	CMS_RecipInfo_ktri_get0_sigr_id
#undef CMS_OtherRevocationInfoFormat_it
#define CMS_OtherRevocationInfoFormat_it	CMS_OtherRevocInfoFormat_it
#undef CMS_KeyAgreeRecipientIdentifier_it
#define CMS_KeyAgreeRecipientIdentifier_it	CMS_KeyAgreeRecipIdentifier_it
#undef CMS_OriginatorIdentifierOrKey_it
#define CMS_OriginatorIdentifierOrKey_it	CMS_OriginatorIdOrKey_it
#undef cms_SignerIdentifier_get0_signer_id
#define cms_SignerIdentifier_get0_signer_id	cms_SignerId_get0_signer_id

/* Hack some long DTLS1 names */
#undef dtls1_retransmit_buffered_messages
#define dtls1_retransmit_buffered_messages	dtls1_retransmit_buffered_msgs

/* Case insensiteve linking causes problems.... */
#if defined(OPENSSL_SYS_WIN16) || defined(OPENSSL_SYS_VMS) || defined(OPENSSL_SYS_OS2)
#undef ERR_load_CRYPTO_strings
#define ERR_load_CRYPTO_strings			ERR_load_CRYPTOlib_strings
#undef OCSP_crlID_new
#define OCSP_crlID_new                          OCSP_crlID2_new

#undef d2i_ECPARAMETERS
#define d2i_ECPARAMETERS                        d2i_UC_ECPARAMETERS
#undef i2d_ECPARAMETERS
#define i2d_ECPARAMETERS                        i2d_UC_ECPARAMETERS
#undef d2i_ECPKPARAMETERS
#define d2i_ECPKPARAMETERS                      d2i_UC_ECPKPARAMETERS
#undef i2d_ECPKPARAMETERS
#define i2d_ECPKPARAMETERS                      i2d_UC_ECPKPARAMETERS

/* These functions do not seem to exist!  However, I'm paranoid...
   Original command in x509v3.h:
   These functions are being redefined in another directory,
   and clash when the linker is case-insensitive, so let's
   hide them a little, by giving them an extra 'o' at the
   beginning of the name... */
#undef X509v3_cleanup_extensions
#define X509v3_cleanup_extensions               oX509v3_cleanup_extensions
#undef X509v3_add_extension
#define X509v3_add_extension                    oX509v3_add_extension
#undef X509v3_add_netscape_extensions
#define X509v3_add_netscape_extensions          oX509v3_add_netscape_extensions
#undef X509v3_add_standard_extensions
#define X509v3_add_standard_extensions          oX509v3_add_standard_extensions
#endif


#ifdef CHARSET_EBCDIC
#include <openssl/ebcdic.h>
#endif

/* Backward compatibility to SSLeay */
/* This is more to be used to check the correct DLL is being used
 * in the MS world. */
#define SSLEAY_VERSION_NUMBER	OPENSSL_VERSION_NUMBER
#define SSLEAY_VERSION		0
/* #define SSLEAY_OPTIONS	1 no longer supported */
#define SSLEAY_CFLAGS		2
#define SSLEAY_BUILT_ON		3
#define SSLEAY_PLATFORM		4
#define SSLEAY_DIR		5

/* Already declared in ossl_typ.h */
#if 0
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
/* Called when a new object is created */
typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
					int idx, long argl, void *argp);
/* Called when an object is free()ed */
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
					int idx, long argl, void *argp);
/* Called when we need to dup an object */
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
					int idx, long argl, void *argp);
#endif

/* A generic structure to pass assorted data in a expandable way */
typedef struct openssl_item_st
{
    int code;
    void *value;		/* Not used for flag attributes */
    size_t value_size;	/* Max size of value for output, length for input */
    size_t *value_length;	/* Returned length of value for output */
} OPENSSL_ITEM;


/* When changing the CRYPTO_LOCK_* list, be sure to maintin the text lock
 * names in cryptlib.c
 */

#define	CRYPTO_LOCK_ERR			1
#define	CRYPTO_LOCK_EX_DATA		2
#define	CRYPTO_LOCK_X509		3
#define	CRYPTO_LOCK_X509_INFO		4
#define	CRYPTO_LOCK_X509_PKEY		5
#define CRYPTO_LOCK_X509_CRL		6
#define CRYPTO_LOCK_X509_REQ		7
#define CRYPTO_LOCK_DSA			8
#define CRYPTO_LOCK_RSA			9
#define CRYPTO_LOCK_EVP_PKEY		10
#define CRYPTO_LOCK_X509_STORE		11
#define CRYPTO_LOCK_SSL_CTX		12
#define CRYPTO_LOCK_SSL_CERT		13
#define CRYPTO_LOCK_SSL_SESSION		14
#define CRYPTO_LOCK_SSL_SESS_CERT	15
#define CRYPTO_LOCK_SSL			16
#define CRYPTO_LOCK_SSL_METHOD		17
#define CRYPTO_LOCK_RAND		18
#define CRYPTO_LOCK_RAND2		19
#define CRYPTO_LOCK_MALLOC		20
#define CRYPTO_LOCK_BIO			21
#define CRYPTO_LOCK_GETHOSTBYNAME	22
#define CRYPTO_LOCK_GETSERVBYNAME	23
#define CRYPTO_LOCK_READDIR		24
#define CRYPTO_LOCK_RSA_BLINDING	25
#define CRYPTO_LOCK_DH			26
#define CRYPTO_LOCK_MALLOC2		27
#define CRYPTO_LOCK_DSO			28
#define CRYPTO_LOCK_DYNLOCK		29
#define CRYPTO_LOCK_ENGINE		30
#define CRYPTO_LOCK_UI			31
#define CRYPTO_LOCK_ECDSA               32
#define CRYPTO_LOCK_EC			33
#define CRYPTO_LOCK_ECDH		34
#define CRYPTO_LOCK_BN  		35
#define CRYPTO_LOCK_EC_PRE_COMP		36
#define CRYPTO_LOCK_STORE		37
#define CRYPTO_LOCK_COMP		38
#ifndef OPENSSL_FIPS
#define CRYPTO_NUM_LOCKS		39
#else
#define CRYPTO_LOCK_FIPS		39
#define CRYPTO_LOCK_FIPS2		40
#define CRYPTO_NUM_LOCKS		41
#endif

#define CRYPTO_LOCK		1
#define CRYPTO_UNLOCK		2
#define CRYPTO_READ		4
#define CRYPTO_WRITE		8


#define	OPENSSL_NO_LOCKING	//samyang close

#ifndef OPENSSL_NO_LOCKING
#ifndef CRYPTO_w_lock

#define CRYPTO_w_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_w_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
#define CRYPTO_r_lock(type)	\
	CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
#define CRYPTO_r_unlock(type)	\
	CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)

#define CRYPTO_add(addr,amount,type)	\
	CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
#endif
#else
#define CRYPTO_w_lock(a)
#define CRYPTO_w_unlock(a)
#define CRYPTO_r_lock(a)
#define CRYPTO_r_unlock(a)
#define CRYPTO_add(a,b,c)	((*(a))+=(b))
#endif

/* Some applications as well as some parts of OpenSSL need to allocate
   and deallocate locks in a dynamic fashion.  The following typedef
   makes this possible in a type-safe manner.  */
/* struct CRYPTO_dynlock_value has to be defined by the application. */
typedef struct
{
    int references;
    struct CRYPTO_dynlock_value *data;
} CRYPTO_dynlock;


/* The following can be used to detect memory leaks in the SSLeay library.
 * It used, it turns on malloc checking */

#define CRYPTO_MEM_CHECK_OFF	0x0	/* an enume */
#define CRYPTO_MEM_CHECK_ON	0x1	/* a bit */
#define CRYPTO_MEM_CHECK_ENABLE	0x2	/* a bit */
#define CRYPTO_MEM_CHECK_DISABLE 0x3	/* an enume */

/* The following are bit values to turn on or off options connected to the
 * malloc checking functionality */

/* Adds time to the memory checking information */
#define V_CRYPTO_MDEBUG_TIME	0x1 /* a bit */
/* Adds thread number to the memory checking information */
#define V_CRYPTO_MDEBUG_THREAD	0x2 /* a bit */

#define V_CRYPTO_MDEBUG_ALL (V_CRYPTO_MDEBUG_TIME | V_CRYPTO_MDEBUG_THREAD)


/* predec of the BIO type */
typedef struct bio_st BIO_dummy;

struct crypto_ex_data_st
{
    STACK *sk;
    int dummy; /* gcc is screwing up this data structure :-( */
};

/* This stuff is basically class callback functions
 * The current classes are SSL_CTX, SSL, SSL_SESSION, and a few more */

typedef struct crypto_ex_data_func_st
{
    long argl;	/* Arbitary long */
    void *argp;	/* Arbitary void * */
    CRYPTO_EX_new *new_func;
    CRYPTO_EX_free *free_func;
    CRYPTO_EX_dup *dup_func;
} CRYPTO_EX_DATA_FUNCS;

DECLARE_STACK_OF(CRYPTO_EX_DATA_FUNCS)

/* Per class, we have a STACK of CRYPTO_EX_DATA_FUNCS for each CRYPTO_EX_DATA
 * entry.
 */

#define CRYPTO_EX_INDEX_BIO		0
#define CRYPTO_EX_INDEX_SSL		1
#define CRYPTO_EX_INDEX_SSL_CTX		2
#define CRYPTO_EX_INDEX_SSL_SESSION	3
#define CRYPTO_EX_INDEX_X509_STORE	4
#define CRYPTO_EX_INDEX_X509_STORE_CTX	5
#define CRYPTO_EX_INDEX_RSA		6
#define CRYPTO_EX_INDEX_DSA		7
#define CRYPTO_EX_INDEX_DH		8
#define CRYPTO_EX_INDEX_ENGINE		9
#define CRYPTO_EX_INDEX_X509		10
#define CRYPTO_EX_INDEX_UI		11
#define CRYPTO_EX_INDEX_ECDSA		12
#define CRYPTO_EX_INDEX_ECDH		13
#define CRYPTO_EX_INDEX_COMP		14
#define CRYPTO_EX_INDEX_STORE		15

/* Dynamically assigned indexes start from this value (don't use directly, use
 * via CRYPTO_ex_data_new_class). */
#define CRYPTO_EX_INDEX_USER		100


/* This is the default callbacks, but we can have others as well:
 * this is needed in Win32 where the application malloc and the
 * library malloc may not be the same.
 */
#define CRYPTO_malloc_init()	CRYPTO_set_mem_functions(\
	malloc, realloc, free)

#if defined CRYPTO_MDEBUG_ALL || defined CRYPTO_MDEBUG_TIME || defined CRYPTO_MDEBUG_THREAD
# ifndef CRYPTO_MDEBUG /* avoid duplicate #define */
#  define CRYPTO_MDEBUG
# endif
#endif

/* Set standard debugging functions (not done by default
 * unless CRYPTO_MDEBUG is defined) */
void CRYPTO_malloc_debug_init(void);

int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);

/* for applications */
#define MemCheck_start() CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON)
#define MemCheck_stop()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_OFF)

/* for library-internal use */
#define MemCheck_on()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ENABLE)
#define MemCheck_off()	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE)
#define is_MemCheck_on() CRYPTO_is_mem_check_on()

#define OPENSSL_malloc(num)	CRYPTO_malloc((int)num,__FILE__,__LINE__)
#define OPENSSL_strdup(str)	CRYPTO_strdup((str),__FILE__,__LINE__)
#define OPENSSL_realloc(addr,num) \
	CRYPTO_realloc((char *)addr,(int)num,__FILE__,__LINE__)
#define OPENSSL_realloc_clean(addr,old_num,num) \
	CRYPTO_realloc_clean(addr,old_num,num,__FILE__,__LINE__)
#define OPENSSL_remalloc(addr,num) \
	CRYPTO_remalloc((char **)addr,(int)num,__FILE__,__LINE__)
#define OPENSSL_freeFunc	CRYPTO_free
#define OPENSSL_free(addr)	CRYPTO_free(addr)

#define OPENSSL_malloc_locked(num) \
	CRYPTO_malloc_locked((int)num,__FILE__,__LINE__)
#define OPENSSL_free_locked(addr) CRYPTO_free_locked(addr)


const char *SSLeay_version(int type);
unsigned long SSLeay(void);

int OPENSSL_issetugid(void);

/* An opaque type representing an implementation of "ex_data" support */
typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;
/* Return an opaque pointer to the current "ex_data" implementation */
const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void);
/* Sets the "ex_data" implementation to be used (if it's not too late) */
int CRYPTO_set_ex_data_implementation(const CRYPTO_EX_DATA_IMPL *i);
/* Get a new "ex_data" class, and return the corresponding "class_index" */
int CRYPTO_ex_data_new_class(void);
/* Within a given class, get/register a new index */
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                            CRYPTO_EX_free *free_func);
/* Initialise/duplicate/free CRYPTO_EX_DATA variables corresponding to a given
 * class (invokes whatever per-class callbacks are applicable) */
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
                       CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
/* Get/set data in a CRYPTO_EX_DATA variable corresponding to a particular index
 * (relative to the class type involved) */
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad,int idx);
/* This function cleans up all "ex_data" state. It mustn't be called under
 * potential race-conditions. */
void CRYPTO_cleanup_all_ex_data(void);

int CRYPTO_get_new_lockid(char *name);

int CRYPTO_num_locks(void); /* return CRYPTO_NUM_LOCKS (shared libs!) */
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
                                              const char *file,int line));
void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
                                          int line);
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
                                              const char *file, int line));
int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
                                          const char *file,int line);
void CRYPTO_set_id_callback(unsigned long (*func)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
unsigned long CRYPTO_thread_id(void);
const char *CRYPTO_get_lock_name(int type);
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
                    int line);

void int_CRYPTO_set_do_dynlock_callback(
        void (*do_dynlock_cb)(int mode, int type, const char *file, int line));

int CRYPTO_get_new_dynlockid(void);
void CRYPTO_destroy_dynlockid(int i);
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l, const char *file, int line));
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);

/* CRYPTO_set_mem_functions includes CRYPTO_set_locked_mem_functions --
 * call the latter last if you need different functions */
int CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                void *(*r)(void *,size_t,const char *,int),
                                void (*f)(void *));
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                       void (*free_func)(void *));
int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
                                   void (*r)(void *,void *,int,const char *,int,int),
                                   void (*f)(void *,int),
                                   void (*so)(long),
                                   long (*go)(void));
void CRYPTO_set_mem_info_functions(
        int  (*push_info_fn)(const char *info, const char *file, int line),
        int  (*pop_info_fn)(void),
        int (*remove_all_info_fn)(void));
void CRYPTO_get_mem_functions(void *(**m)(size_t),void *(**r)(void *, size_t), void (**f)(void *));
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *));
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                 void *(**r)(void *, size_t,const char *,int),
                                 void (**f)(void *));
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                        void (**f)(void *));
void CRYPTO_get_mem_debug_functions(void (**m)(void *,int,const char *,int,int),
                                    void (**r)(void *,void *,int,const char *,int,int),
                                    void (**f)(void *,int),
                                    void (**so)(long),
                                    long (**go)(void));

void *CRYPTO_malloc_locked(int num, const char *file, int line);
void CRYPTO_free_locked(void *);
void *CRYPTO_malloc(int num, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *);
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
void *CRYPTO_realloc_clean(void *addr,int old_num,int num,const char *file,
                           int line);
void *CRYPTO_remalloc(void *addr,int num, const char *file, int line);

void OPENSSL_cleanse(void *ptr, size_t len);

void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);

#define CRYPTO_push_info(info) \
        CRYPTO_push_info_(info, __FILE__, __LINE__);
int CRYPTO_push_info_(const char *info, const char *file, int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);


/* Default debugging functions (enabled by CRYPTO_malloc_debug_init() macro;
 * used as default in CRYPTO_MDEBUG compilations): */
/* The last argument has the following significance:
 *
 * 0:	called before the actual memory allocation has taken place
 * 1:	called after the actual memory allocation has taken place
 */
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_free(void *addr,int before_p);
/* Tell the debugging code about options.  By default, the following values
 * apply:
 *
 * 0:                           Clear all options.
 * V_CRYPTO_MDEBUG_TIME (1):    Set the "Show Time" option.
 * V_CRYPTO_MDEBUG_THREAD (2):  Set the "Show Thread Number" option.
 * V_CRYPTO_MDEBUG_ALL (3):     1 + 2
 */
void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);

int CRYPTO_dbg_push_info(const char *info, const char *file, int line);
int CRYPTO_dbg_pop_info(void);
int CRYPTO_dbg_remove_all_info(void);

#ifdef OPENSSL_NO_FP_API
void CRYPTO_mem_leaks_fp(FILE *);
#endif
void CRYPTO_mem_leaks(struct bio_st *bio);
/* unsigned long order, char *file, int line, int num_bytes, char *addr */
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);

/* die if we have to */
void OpenSSLDie(const char *file,int line,const char *assertion);
#define OPENSSL_assert(e)       (void)((e) ? 0 : (OpenSSLDie(__FILE__, __LINE__, #e),1))

unsigned long *OPENSSL_ia32cap_loc(void);
#define OPENSSL_ia32cap (*(OPENSSL_ia32cap_loc()))
int OPENSSL_isservice(void);

#ifdef OPENSSL_FIPS
#define FIPS_ERROR_IGNORED(alg) OpenSSLDie(__FILE__, __LINE__, \
		alg " previous FIPS forbidden algorithm error ignored");

#define FIPS_BAD_ABORT(alg) OpenSSLDie(__FILE__, __LINE__, \
		#alg " Algorithm forbidden in FIPS mode");

#ifdef OPENSSL_FIPS_STRICT
#define FIPS_BAD_ALGORITHM(alg) FIPS_BAD_ABORT(alg)
#else
#define FIPS_BAD_ALGORITHM(alg) \
	{ \
	FIPSerr(FIPS_F_HASH_FINAL,FIPS_R_NON_FIPS_METHOD); \
	ERR_add_error_data(2, "Algorithm=", #alg); \
	return 0; \
	}
#endif

/* Low level digest API blocking macro */

#define FIPS_NON_FIPS_MD_Init(alg) \
	int alg##_Init(alg##_CTX *c) \
		{ \
		if (FIPS_mode()) \
			FIPS_BAD_ALGORITHM(alg) \
		return private_##alg##_Init(c); \
		} \
	int private_##alg##_Init(alg##_CTX *c)

/* For ciphers the API often varies from cipher to cipher and each needs to
 * be treated as a special case. Variable key length ciphers (Blowfish, RC4,
 * CAST) however are very similar and can use a blocking macro.
 */

#define FIPS_NON_FIPS_VCIPHER_Init(alg) \
	void alg##_set_key(alg##_KEY *key, int len, const unsigned char *data) \
		{ \
		if (FIPS_mode()) \
			FIPS_BAD_ABORT(alg) \
		private_##alg##_set_key(key, len, data); \
		} \
	void private_##alg##_set_key(alg##_KEY *key, int len, \
					const unsigned char *data)

#else

#define FIPS_NON_FIPS_VCIPHER_Init(alg) \
	void alg##_set_key(alg##_KEY *key, int len, const unsigned char *data)

#define FIPS_NON_FIPS_MD_Init(alg) \
	int alg##_Init(alg##_CTX *c)

#endif /* def OPENSSL_FIPS */

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CRYPTO_strings(void);

#define OPENSSL_HAVE_INIT	1
void OPENSSL_init(void);

/* Error codes for the CRYPTO functions. */

/* Function codes. */
#define CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX		 100
#define CRYPTO_F_CRYPTO_GET_NEW_DYNLOCKID		 103
#define CRYPTO_F_CRYPTO_GET_NEW_LOCKID			 101
#define CRYPTO_F_CRYPTO_SET_EX_DATA			 102
#define CRYPTO_F_DEF_ADD_INDEX				 104
#define CRYPTO_F_DEF_GET_CLASS				 105
#define CRYPTO_F_INT_DUP_EX_DATA			 106
#define CRYPTO_F_INT_FREE_EX_DATA			 107
#define CRYPTO_F_INT_NEW_EX_DATA			 108

/* Reason codes. */
#define CRYPTO_R_NO_DYNLOCK_CREATE_CALLBACK		 100


/* These are the 'types' of BIOs */
#define BIO_TYPE_NONE		0
#define BIO_TYPE_MEM		(1|0x0400)
#define BIO_TYPE_FILE		(2|0x0400)

#define BIO_TYPE_FD		(4|0x0400|0x0100)
#define BIO_TYPE_SOCKET		(5|0x0400|0x0100)
#define BIO_TYPE_NULL		(6|0x0400)
#define BIO_TYPE_SSL		(7|0x0200)
#define BIO_TYPE_MD		(8|0x0200)		/* passive filter */
#define BIO_TYPE_BUFFER		(9|0x0200)		/* filter */
#define BIO_TYPE_CIPHER		(10|0x0200)		/* filter */
#define BIO_TYPE_BASE64		(11|0x0200)		/* filter */
#define BIO_TYPE_CONNECT	(12|0x0400|0x0100)	/* socket - connect */
#define BIO_TYPE_ACCEPT		(13|0x0400|0x0100)	/* socket for accept */
#define BIO_TYPE_PROXY_CLIENT	(14|0x0200)		/* client proxy BIO */
#define BIO_TYPE_PROXY_SERVER	(15|0x0200)		/* server proxy BIO */
#define BIO_TYPE_NBIO_TEST	(16|0x0200)		/* server proxy BIO */
#define BIO_TYPE_NULL_FILTER	(17|0x0200)
#define BIO_TYPE_BER		(18|0x0200)		/* BER -> bin filter */
#define BIO_TYPE_BIO		(19|0x0400)		/* (half a) BIO pair */
#define BIO_TYPE_LINEBUFFER	(20|0x0200)		/* filter */
#define BIO_TYPE_DGRAM		(21|0x0400|0x0100)
#define BIO_TYPE_COMP 		(23|0x0200)		/* filter */

#define BIO_TYPE_DESCRIPTOR	0x0100	/* socket, fd, connect or accept */
#define BIO_TYPE_FILTER		0x0200
#define BIO_TYPE_SOURCE_SINK	0x0400

/* BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
 * BIO_set_fp(in,stdin,BIO_NOCLOSE); */
#define BIO_NOCLOSE		0x00
#define BIO_CLOSE		0x01

/* These are used in the following macros and are passed to
 * BIO_ctrl() */
#define BIO_CTRL_RESET		1  /* opt - rewind/zero etc */
#define BIO_CTRL_EOF		2  /* opt - are we at the eof */
#define BIO_CTRL_INFO		3  /* opt - extra tit-bits */
#define BIO_CTRL_SET		4  /* man - set the 'IO' type */
#define BIO_CTRL_GET		5  /* man - get the 'IO' type */
#define BIO_CTRL_PUSH		6  /* opt - internal, used to signify change */
#define BIO_CTRL_POP		7  /* opt - internal, used to signify change */
#define BIO_CTRL_GET_CLOSE	8  /* man - set the 'close' on free */
#define BIO_CTRL_SET_CLOSE	9  /* man - set the 'close' on free */
#define BIO_CTRL_PENDING	10  /* opt - is their more data buffered */
#define BIO_CTRL_FLUSH		11  /* opt - 'flush' buffered output */
#define BIO_CTRL_DUP		12  /* man - extra stuff for 'duped' BIO */
#define BIO_CTRL_WPENDING	13  /* opt - number of bytes still to write */
/* callback is int cb(BIO *bio,state,ret); */
#define BIO_CTRL_SET_CALLBACK	14  /* opt - set callback function */
#define BIO_CTRL_GET_CALLBACK	15  /* opt - set callback function */

#define BIO_CTRL_SET_FILENAME	30	/* BIO_s_file special */

/* dgram BIO stuff */
#define BIO_CTRL_DGRAM_CONNECT       31  /* BIO dgram special */
#define BIO_CTRL_DGRAM_SET_CONNECTED 32  /* allow for an externally
					  * connected socket to be
					  * passed in */
#define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33 /* setsockopt, essentially */
#define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34 /* getsockopt, essentially */
#define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35 /* setsockopt, essentially */
#define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36 /* getsockopt, essentially */

#define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37 /* flag whether the last */
#define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38 /* I/O operation tiemd out */

/* #ifdef IP_MTU_DISCOVER */
#define BIO_CTRL_DGRAM_MTU_DISCOVER       39 /* set DF bit on egress packets */
/* #endif */

#define BIO_CTRL_DGRAM_QUERY_MTU          40 /* as kernel for current MTU */
#define BIO_CTRL_DGRAM_GET_MTU            41 /* get cached value for MTU */
#define BIO_CTRL_DGRAM_SET_MTU            42 /* set cached value for
					      * MTU. want to use this
					      * if asking the kernel
					      * fails */

#define BIO_CTRL_DGRAM_MTU_EXCEEDED       43 /* check whether the MTU
					      * was exceed in the
					      * previous write
					      * operation */

#define BIO_CTRL_DGRAM_GET_PEER           46
#define BIO_CTRL_DGRAM_SET_PEER           44 /* Destination for the data */

#define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45 /* Next DTLS handshake timeout to
											  * adjust socket timeouts */

/* modifiers */
#define BIO_FP_READ		0x02
#define BIO_FP_WRITE		0x04
#define BIO_FP_APPEND		0x08
#define BIO_FP_TEXT		0x10

#define BIO_FLAGS_READ		0x01
#define BIO_FLAGS_WRITE		0x02
#define BIO_FLAGS_IO_SPECIAL	0x04
#define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
#define BIO_FLAGS_SHOULD_RETRY	0x08
#ifndef	BIO_FLAGS_UPLINK
/* "UPLINK" flag denotes file descriptors provided by application.
   It defaults to 0, as most platforms don't require UPLINK interface. */
#define	BIO_FLAGS_UPLINK	0
#endif

/* Used in BIO_gethostbyname() */
#define BIO_GHBN_CTRL_HITS		1
#define BIO_GHBN_CTRL_MISSES		2
#define BIO_GHBN_CTRL_CACHE_SIZE	3
#define BIO_GHBN_CTRL_GET_ENTRY		4
#define BIO_GHBN_CTRL_FLUSH		5

/* Mostly used in the SSL BIO */
/* Not used anymore
 * #define BIO_FLAGS_PROTOCOL_DELAYED_READ 0x10
 * #define BIO_FLAGS_PROTOCOL_DELAYED_WRITE 0x20
 * #define BIO_FLAGS_PROTOCOL_STARTUP	0x40
 */

#define BIO_FLAGS_BASE64_NO_NL	0x100

/* This is used with memory BIOs: it means we shouldn't free up or change the
 * data in any way.
 */
#define BIO_FLAGS_MEM_RDONLY	0x200

typedef struct bio_st BIO;

void BIO_set_flags(BIO *b, int flags);
int  BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);

#define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
#define BIO_set_retry_special(b) \
		BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
#define BIO_set_retry_read(b) \
		BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
#define BIO_set_retry_write(b) \
		BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))

/* These are normally used internally in BIOs */
#define BIO_clear_retry_flags(b) \
		BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
#define BIO_get_retry_flags(b) \
		BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))

/* These should be used by the application to tell why we should retry */
#define BIO_should_read(a)		BIO_test_flags(a, BIO_FLAGS_READ)
#define BIO_should_write(a)		BIO_test_flags(a, BIO_FLAGS_WRITE)
#define BIO_should_io_special(a)	BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
#define BIO_retry_type(a)		BIO_test_flags(a, BIO_FLAGS_RWS)
#define BIO_should_retry(a)		BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)

/* The next three are used in conjunction with the
 * BIO_should_io_special() condition.  After this returns true,
 * BIO *BIO_get_retry_BIO(BIO *bio, int *reason); will walk the BIO
 * stack and return the 'reason' for the special and the offending BIO.
 * Given a BIO, BIO_get_retry_reason(bio) will return the code. */
/* Returned from the SSL bio when the certificate retrieval code had an error */
#define BIO_RR_SSL_X509_LOOKUP		0x01
/* Returned from the connect BIO when a connect would have blocked */
#define BIO_RR_CONNECT			0x02
/* Returned from the accept BIO when an accept would have blocked */
#define BIO_RR_ACCEPT			0x03

/* These are passed by the BIO callback */
#define BIO_CB_FREE	0x01
#define BIO_CB_READ	0x02
#define BIO_CB_WRITE	0x03
#define BIO_CB_PUTS	0x04
#define BIO_CB_GETS	0x05
#define BIO_CB_CTRL	0x06

/* The callback is called before and after the underling operation,
 * The BIO_CB_RETURN flag indicates if it is after the call */
#define BIO_CB_RETURN	0x80
#define BIO_CB_return(a) ((a)|BIO_CB_RETURN))
#define BIO_cb_pre(a)	(!((a)&BIO_CB_RETURN))
#define BIO_cb_post(a)	((a)&BIO_CB_RETURN)

long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);
void BIO_set_callback(BIO *b,
                      long (*callback)(struct bio_st *,int,const char *,int, long,long));
char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);

const char * BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);

typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);

#ifndef OPENSSL_SYS_WIN16
typedef struct bio_method_st
{
    int type;
    const char *name;
    int (*bwrite)(BIO *, const char *, int);
    int (*bread)(BIO *, char *, int);
    int (*bputs)(BIO *, const char *);
    int (*bgets)(BIO *, char *, int);
    long (*ctrl)(BIO *, int, long, void *);
    int (*create)(BIO *);
    int (*destroy)(BIO *);
    long (*callback_ctrl)(BIO *, int, bio_info_cb *);
} BIO_METHOD;
#else
typedef struct bio_method_st
	{
	int type;
	const char *name;
	int (_far *bwrite)();
	int (_far *bread)();
	int (_far *bputs)();
	int (_far *bgets)();
	long (_far *ctrl)();
	int (_far *create)();
	int (_far *destroy)();
	long (_far *callback_ctrl)();
	} BIO_METHOD;
#endif

struct bio_st
{
    BIO_METHOD *method;
    /* bio, mode, argp, argi, argl, ret */
    long (*callback)(struct bio_st *,int,const char *,int, long,long);
    char *cb_arg; /* first argument for the callback */

    int init;
    int shutdown;
    int flags;	/* extra storage */
    int retry_reason;
    int num;
    void *ptr;
    struct bio_st *next_bio;	/* used by filter BIOs */
    struct bio_st *prev_bio;	/* used by filter BIOs */
    int references;
    unsigned long num_read;
    unsigned long num_write;

    CRYPTO_EX_DATA ex_data;
};

DECLARE_STACK_OF(BIO)

typedef struct bio_f_buffer_ctx_struct
{
    /* BIO *bio; */ /* this is now in the BIO struct */
    int ibuf_size;	/* how big is the input buffer */
    int obuf_size;	/* how big is the output buffer */

    char *ibuf;		/* the char array */
    int ibuf_len;		/* how many bytes are in it */
    int ibuf_off;		/* write/read offset */

    char *obuf;		/* the char array */
    int obuf_len;		/* how many bytes are in it */
    int obuf_off;		/* write/read offset */
} BIO_F_BUFFER_CTX;

/* connect BIO stuff */
#define BIO_CONN_S_BEFORE		1
#define BIO_CONN_S_GET_IP		2
#define BIO_CONN_S_GET_PORT		3
#define BIO_CONN_S_CREATE_SOCKET	4
#define BIO_CONN_S_CONNECT		5
#define BIO_CONN_S_OK			6
#define BIO_CONN_S_BLOCKED_CONNECT	7
#define BIO_CONN_S_NBIO			8
/*#define BIO_CONN_get_param_hostname	BIO_ctrl */

#define BIO_C_SET_CONNECT			100
#define BIO_C_DO_STATE_MACHINE			101
#define BIO_C_SET_NBIO				102
#define BIO_C_SET_PROXY_PARAM			103
#define BIO_C_SET_FD				104
#define BIO_C_GET_FD				105
#define BIO_C_SET_FILE_PTR			106
#define BIO_C_GET_FILE_PTR			107
#define BIO_C_SET_FILENAME			108
#define BIO_C_SET_SSL				109
#define BIO_C_GET_SSL				110
#define BIO_C_SET_MD				111
#define BIO_C_GET_MD				112
#define BIO_C_GET_CIPHER_STATUS			113
#define BIO_C_SET_BUF_MEM			114
#define BIO_C_GET_BUF_MEM_PTR			115
#define BIO_C_GET_BUFF_NUM_LINES		116
#define BIO_C_SET_BUFF_SIZE			117
#define BIO_C_SET_ACCEPT			118
#define BIO_C_SSL_MODE				119
#define BIO_C_GET_MD_CTX			120
#define BIO_C_GET_PROXY_PARAM			121
#define BIO_C_SET_BUFF_READ_DATA		122 /* data to read first */
#define BIO_C_GET_CONNECT			123
#define BIO_C_GET_ACCEPT			124
#define BIO_C_SET_SSL_RENEGOTIATE_BYTES		125
#define BIO_C_GET_SSL_NUM_RENEGOTIATES		126
#define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT	127
#define BIO_C_FILE_SEEK				128
#define BIO_C_GET_CIPHER_CTX			129
#define BIO_C_SET_BUF_MEM_EOF_RETURN		130/*return end of input value*/
#define BIO_C_SET_BIND_MODE			131
#define BIO_C_GET_BIND_MODE			132
#define BIO_C_FILE_TELL				133
#define BIO_C_GET_SOCKS				134
#define BIO_C_SET_SOCKS				135

#define BIO_C_SET_WRITE_BUF_SIZE		136/* for BIO_s_bio */
#define BIO_C_GET_WRITE_BUF_SIZE		137
#define BIO_C_MAKE_BIO_PAIR			138
#define BIO_C_DESTROY_BIO_PAIR			139
#define BIO_C_GET_WRITE_GUARANTEE		140
#define BIO_C_GET_READ_REQUEST			141
#define BIO_C_SHUTDOWN_WR			142
#define BIO_C_NREAD0				143
#define BIO_C_NREAD				144
#define BIO_C_NWRITE0				145
#define BIO_C_NWRITE				146
#define BIO_C_RESET_READ_REQUEST		147
#define BIO_C_SET_MD_CTX			148


#define BIO_set_app_data(s,arg)		BIO_set_ex_data(s,0,arg)
#define BIO_get_app_data(s)		BIO_get_ex_data(s,0)

/* BIO_s_connect() and BIO_s_socks4a_connect() */
#define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,(char *)name)
#define BIO_set_conn_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,1,(char *)port)
#define BIO_set_conn_ip(b,ip)	  BIO_ctrl(b,BIO_C_SET_CONNECT,2,(char *)ip)
#define BIO_set_conn_int_port(b,port) BIO_ctrl(b,BIO_C_SET_CONNECT,3,(char *)port)
#define BIO_get_conn_hostname(b)  BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0)
#define BIO_get_conn_port(b)      BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1)
#define BIO_get_conn_ip(b) 		 BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2)
#define BIO_get_conn_int_port(b) BIO_int_ctrl(b,BIO_C_GET_CONNECT,3,0)


#define BIO_set_nbio(b,n)	BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)

/* BIO_s_accept_socket() */
#define BIO_set_accept_port(b,name) BIO_ctrl(b,BIO_C_SET_ACCEPT,0,(char *)name)
#define BIO_get_accept_port(b)	BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0)
/* #define BIO_set_nbio(b,n)	BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL) */
#define BIO_set_nbio_accept(b,n) BIO_ctrl(b,BIO_C_SET_ACCEPT,1,(n)?(void *)"a":NULL)
#define BIO_set_accept_bios(b,bio) BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(char *)bio)

#define BIO_BIND_NORMAL			0
#define BIO_BIND_REUSEADDR_IF_UNUSED	1
#define BIO_BIND_REUSEADDR		2
#define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
#define BIO_get_bind_mode(b,mode) BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)

#define BIO_do_connect(b)	BIO_do_handshake(b)
#define BIO_do_accept(b)	BIO_do_handshake(b)
#define BIO_do_handshake(b)	BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)

/* BIO_s_proxy_client() */
#define BIO_set_url(b,url)	BIO_ctrl(b,BIO_C_SET_PROXY_PARAM,0,(char *)(url))
#define BIO_set_proxies(b,p)	BIO_ctrl(b,BIO_C_SET_PROXY_PARAM,1,(char *)(p))
/* BIO_set_nbio(b,n) */
#define BIO_set_filter_bio(b,s) BIO_ctrl(b,BIO_C_SET_PROXY_PARAM,2,(char *)(s))
/* BIO *BIO_get_filter_bio(BIO *bio); */
#define BIO_set_proxy_cb(b,cb) BIO_callback_ctrl(b,BIO_C_SET_PROXY_PARAM,3,(void *(*cb)()))
#define BIO_set_proxy_header(b,sk) BIO_ctrl(b,BIO_C_SET_PROXY_PARAM,4,(char *)sk)
#define BIO_set_no_connect_return(b,bool) BIO_int_ctrl(b,BIO_C_SET_PROXY_PARAM,5,bool)

#define BIO_get_proxy_header(b,skp) BIO_ctrl(b,BIO_C_GET_PROXY_PARAM,0,(char *)skp)
#define BIO_get_proxies(b,pxy_p) BIO_ctrl(b,BIO_C_GET_PROXY_PARAM,1,(char *)(pxy_p))
#define BIO_get_url(b,url)	BIO_ctrl(b,BIO_C_GET_PROXY_PARAM,2,(char *)(url))
#define BIO_get_no_connect_return(b)	BIO_ctrl(b,BIO_C_GET_PROXY_PARAM,5,NULL)

#define BIO_set_fd(b,fd,c)	BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)
#define BIO_get_fd(b,c)		BIO_ctrl(b,BIO_C_GET_FD,0,(char *)c)

#define BIO_set_fp(b,fp,c)	BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char *)fp)
#define BIO_get_fp(b,fpp)	BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char *)fpp)

#define BIO_seek(b,ofs)	(int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)
#define BIO_tell(b)	(int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)

/* name is cast to lose const, but might be better to route through a function
   so we can do it safely */
#ifdef CONST_STRICT
/* If you are wondering why this isn't defined, its because CONST_STRICT is
 * purely a compile-time kludge to allow const to be checked.
 */
int BIO_read_filename(BIO *b,const char *name);
#else
#define BIO_read_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
		BIO_CLOSE|BIO_FP_READ,(char *)name)
#endif
#define BIO_write_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
		BIO_CLOSE|BIO_FP_WRITE,name)
#define BIO_append_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
		BIO_CLOSE|BIO_FP_APPEND,name)
#define BIO_rw_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
		BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)

/* WARNING WARNING, this ups the reference count on the read bio of the
 * SSL structure.  This is because the ssl read BIO is now pointed to by
 * the next_bio field in the bio.  So when you free the BIO, make sure
 * you are doing a BIO_free_all() to catch the underlying BIO. */
#define BIO_set_ssl(b,ssl,c)	BIO_ctrl(b,BIO_C_SET_SSL,c,(char *)ssl)
#define BIO_get_ssl(b,sslp)	BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)sslp)
#define BIO_set_ssl_mode(b,client)	BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)
#define BIO_set_ssl_renegotiate_bytes(b,num) \
	BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,NULL);
#define BIO_get_num_renegotiates(b) \
	BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,NULL);
#define BIO_set_ssl_renegotiate_timeout(b,seconds) \
	BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,NULL);

/* defined in evp.h */
/* #define BIO_set_md(b,md)	BIO_ctrl(b,BIO_C_SET_MD,1,(char *)md) */

#define BIO_get_mem_data(b,pp)	BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)pp)
#define BIO_set_mem_buf(b,bm,c)	BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char *)bm)
#define BIO_get_mem_ptr(b,pp)	BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char *)pp)
#define BIO_set_mem_eof_return(b,v) \
				BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,NULL)

/* For the BIO_f_buffer() type */
#define BIO_get_buffer_num_lines(b)	BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)
#define BIO_set_buffer_size(b,size)	BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)
#define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)
#define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)
#define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)

/* Don't use the next one unless you know what you are doing :-) */
#define BIO_dup_state(b,ret)	BIO_ctrl(b,BIO_CTRL_DUP,0,(char *)(ret))

#define BIO_reset(b)		(int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)
#define BIO_eof(b)		(int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)
#define BIO_set_close(b,c)	(int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
#define BIO_get_close(b)	(int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)
#define BIO_pending(b)		(int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
#define BIO_wpending(b)		(int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)
/* ...pending macros have inappropriate return type */
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);
#define BIO_flush(b)		(int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
#define BIO_get_info_callback(b,cbp) (int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0, \
						   cbp)
#define BIO_set_info_callback(b,cb) (int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)

/* For the BIO_f_buffer() type */
#define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)

/* For BIO_s_bio() */
#define BIO_set_write_buf_size(b,size) (int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)
#define BIO_get_write_buf_size(b,size) (size_t)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)
#define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)
#define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)
#define BIO_shutdown_wr(b) (int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)
/* macros with inappropriate type -- but ...pending macros use int too: */
#define BIO_get_write_guarantee(b) (int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)
#define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)
size_t BIO_ctrl_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);

/* ctrl macros for dgram */
#define BIO_ctrl_dgram_connect(b,peer)  \
                     (int)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char *)peer)
#define BIO_ctrl_set_connected(b, state, peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, state, (char *)peer)
#define BIO_dgram_recv_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)
#define BIO_dgram_send_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)
#define BIO_dgram_get_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)peer)
#define BIO_dgram_set_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)peer)

/* These two aren't currently implemented */
/* int BIO_get_ex_num(BIO *bio); */
/* void BIO_set_ex_free_func(BIO *bio,int idx,void (*cb)()); */
int BIO_set_ex_data(BIO *bio,int idx,void *data);
void *BIO_get_ex_data(BIO *bio,int idx);
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
unsigned long BIO_number_read(BIO *bio);
unsigned long BIO_number_written(BIO *bio);

# ifndef OPENSSL_NO_FP_API
#  if defined(OPENSSL_SYS_WIN16) && defined(_WINDLL)
BIO_METHOD *BIO_s_file_internal(void);
BIO *BIO_new_file_internal(char *filename, char *mode);
BIO *BIO_new_fp_internal(FILE *stream, int close_flag);
#    define BIO_s_file	BIO_s_file_internal
#    define BIO_new_file	BIO_new_file_internal
#    define BIO_new_fp	BIO_new_fp_internal
#  else /* FP_API */
BIO_METHOD *BIO_s_file(void );
BIO *BIO_new_file(const char *filename, const char *mode);
//BIO *BIO_new_fp(FILE *stream, int close_flag);
#    define BIO_s_file_internal		BIO_s_file
#    define BIO_new_file_internal	BIO_new_file
#    define BIO_new_fp_internal		BIO_s_file
#  endif /* FP_API */
# endif
BIO *	BIO_new(BIO_METHOD *type);
int	BIO_set(BIO *a,BIO_METHOD *type);
int	BIO_free(BIO *a);
void	BIO_vfree(BIO *a);
int	BIO_read(BIO *b, void *data, int len);
int	BIO_gets(BIO *bp,char *buf, int size);
int	BIO_write(BIO *b, const void *data, int len);
int	BIO_puts(BIO *bp,const char *buf);
int	BIO_indent(BIO *b,int indent,int max);
long	BIO_ctrl(BIO *bp,int cmd,long larg,void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));
char *	BIO_ptr_ctrl(BIO *bp,int cmd,long larg);
long	BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg);
BIO *	BIO_push(BIO *b,BIO *append);
BIO *	BIO_pop(BIO *b);
void	BIO_free_all(BIO *a);
BIO *	BIO_find_type(BIO *b,int bio_type);
BIO *	BIO_next(BIO *b);
BIO *	BIO_get_retry_BIO(BIO *bio, int *reason);
int	BIO_get_retry_reason(BIO *bio);
BIO *	BIO_dup_chain(BIO *in);

int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);

#ifndef OPENSSL_SYS_WIN16
long BIO_debug_callback(BIO *bio,int cmd,const char *argp,int argi,
                        long argl,long ret);
#else
long _far _loadds BIO_debug_callback(BIO *bio,int cmd,const char *argp,int argi,
	long argl,long ret);
#endif

BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(void *buf, int len);
BIO_METHOD *BIO_s_socket(void);
BIO_METHOD *BIO_s_connect(void);
BIO_METHOD *BIO_s_accept(void);
BIO_METHOD *BIO_s_fd(void);
#ifndef OPENSSL_SYS_OS2
BIO_METHOD *BIO_s_log(void);
#endif
BIO_METHOD *BIO_s_bio(void);
BIO_METHOD *BIO_s_null(void);
BIO_METHOD *BIO_f_null(void);
BIO_METHOD *BIO_f_buffer(void);
#ifdef OPENSSL_SYS_VMS
BIO_METHOD *BIO_f_linebuffer(void);
#endif
BIO_METHOD *BIO_f_nbio_test(void);
#ifndef OPENSSL_NO_DGRAM
BIO_METHOD *BIO_s_datagram(void);
#endif

/* BIO_METHOD *BIO_f_ber(void); */

int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
int BIO_dgram_non_fatal_error(int error);

int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
                void *u, const char *s, int len);
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
                       void *u, const char *s, int len, int indent);
int BIO_dump(BIO *b,const char *bytes,int len);
int BIO_dump_indent(BIO *b,const char *bytes,int len,int indent);
#ifdef OPENSSL_NO_FP_API
int BIO_dump_fp(FILE *fp, const char *s, int len);
int BIO_dump_indent_fp(FILE *fp, const char *s, int len, int indent);
#endif
struct hostent *BIO_gethostbyname(const char *name);
/* We might want a thread-safe interface too:
 * struct hostent *BIO_gethostbyname_r(const char *name,
 *     struct hostent *result, void *buffer, size_t buflen);
 * or something similar (caller allocates a struct hostent,
 * pointed to by "result", and additional buffer space for the various
 * substructures; if the buffer does not suffice, NULL is returned
 * and an appropriate error code is set).
 */
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);
int BIO_accept(int sock,char **ip_port);
int BIO_sock_init(void );
void BIO_sock_cleanup(void);
int BIO_set_tcp_ndelay(int sock,int turn_on);

BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_dgram(int fd, int close_flag);
BIO *BIO_new_fd(int fd, int close_flag);
BIO *BIO_new_connect(char *host_port);
BIO *BIO_new_accept(char *host_port);

int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
                     BIO **bio2, size_t writebuf2);
/* If successful, returns 1 and in *bio1, *bio2 two BIO pair endpoints.
 * Otherwise returns 0 and sets *bio1 and *bio2 to NULL.
 * Size 0 uses default value.
 */

void BIO_copy_next_retry(BIO *b);

/*long BIO_ghbn_ctrl(int cmd,int iarg,char *parg);*/

#ifdef __GNUC__
#  define __bio_h__attr__ __attribute__
#else
#  define __bio_h__attr__(x)
#endif
int BIO_printf(BIO *bio, const char *format, ...)
__bio_h__attr__((__format__(__printf__,2,3)));
//int BIO_vprintf(BIO *bio, const char *format, va_list args)
//	__bio_h__attr__((__format__(__printf__,2,0)));
//int BIO_snprintf(char *buf, size_t n, const char *format, ...)
//	__bio_h__attr__((__format__(__printf__,3,4)));
//int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
//	__bio_h__attr__((__format__(__printf__,3,0)));
#undef __bio_h__attr__

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_BIO_strings(void);

/* Error codes for the BIO functions. */

/* Function codes. */
#define BIO_F_ACPT_STATE				 100
#define BIO_F_BIO_ACCEPT				 101
#define BIO_F_BIO_BER_GET_HEADER			 102
#define BIO_F_BIO_CALLBACK_CTRL				 131
#define BIO_F_BIO_CTRL					 103
#define BIO_F_BIO_GETHOSTBYNAME				 120
#define BIO_F_BIO_GETS					 104
#define BIO_F_BIO_GET_ACCEPT_SOCKET			 105
#define BIO_F_BIO_GET_HOST_IP				 106
#define BIO_F_BIO_GET_PORT				 107
#define BIO_F_BIO_MAKE_PAIR				 121
#define BIO_F_BIO_NEW					 108
#define BIO_F_BIO_NEW_FILE				 109
#define BIO_F_BIO_NEW_MEM_BUF				 126
#define BIO_F_BIO_NREAD					 123
#define BIO_F_BIO_NREAD0				 124
#define BIO_F_BIO_NWRITE				 125
#define BIO_F_BIO_NWRITE0				 122
#define BIO_F_BIO_PUTS					 110
#define BIO_F_BIO_READ					 111
#define BIO_F_BIO_SOCK_INIT				 112
#define BIO_F_BIO_WRITE					 113
#define BIO_F_BUFFER_CTRL				 114
#define BIO_F_CONN_CTRL					 127
#define BIO_F_CONN_STATE				 115
#define BIO_F_FILE_CTRL					 116
#define BIO_F_FILE_READ					 130
#define BIO_F_LINEBUFFER_CTRL				 129
#define BIO_F_MEM_READ					 128
#define BIO_F_MEM_WRITE					 117
#define BIO_F_SSL_NEW					 118
#define BIO_F_WSASTARTUP				 119

/* Reason codes. */
#define BIO_R_ACCEPT_ERROR				 100
#define BIO_R_BAD_FOPEN_MODE				 101
#define BIO_R_BAD_HOSTNAME_LOOKUP			 102
#define BIO_R_BROKEN_PIPE				 124
#define BIO_R_CONNECT_ERROR				 103
#define BIO_R_EOF_ON_MEMORY_BIO				 127
#define BIO_R_ERROR_SETTING_NBIO			 104
#define BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET	 105
#define BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET	 106
#define BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET		 107
#define BIO_R_INVALID_ARGUMENT				 125
#define BIO_R_INVALID_IP_ADDRESS			 108
#define BIO_R_IN_USE					 123
#define BIO_R_KEEPALIVE					 109
#define BIO_R_NBIO_CONNECT_ERROR			 110
#define BIO_R_NO_ACCEPT_PORT_SPECIFIED			 111
#define BIO_R_NO_HOSTNAME_SPECIFIED			 112
#define BIO_R_NO_PORT_DEFINED				 113
#define BIO_R_NO_PORT_SPECIFIED				 114
#define BIO_R_NO_SUCH_FILE				 128
#define BIO_R_NULL_PARAMETER				 115
#define BIO_R_TAG_MISMATCH				 116
#define BIO_R_UNABLE_TO_BIND_SOCKET			 117
#define BIO_R_UNABLE_TO_CREATE_SOCKET			 118
#define BIO_R_UNABLE_TO_LISTEN_SOCKET			 119
#define BIO_R_UNINITIALIZED				 120
#define BIO_R_UNSUPPORTED_METHOD			 121
#define BIO_R_WRITE_TO_READ_ONLY_BIO			 126
#define BIO_R_WSASTARTUP				 122

struct asn1_pctx_st
{
    unsigned long flags;
    unsigned long nm_flags;
    unsigned long cert_flags;
    unsigned long oid_flags;
    unsigned long str_flags;
} /* ASN1_PCTX */;

/* ASN1 public key method structure */

struct evp_pkey_asn1_method_st
{
    int pkey_id;
    int pkey_base_id;
    unsigned long pkey_flags;

    char *pem_str;
    char *info;

    int (*pub_decode)(int *pk, int *pub);
    int (*pub_encode)(int *pub, const int *pk);
    int (*pub_cmp)(const int *a, const int *b);
    int (*pub_print)(BIO *out, const int *pkey, int indent,
                     int *pctx);

    int (*priv_decode)(int *pk, int *p8inf);
    int (*priv_encode)(int *p8, const int *pk);
    int (*priv_print)(BIO *out, const int *pkey, int indent,
                      int *pctx);

    int (*pkey_size)(const int *pk);
    int (*pkey_bits)(const int *pk);

    int (*param_decode)(int *pkey,
                        const unsigned char **pder, int derlen);
    int (*param_encode)(const int *pkey, unsigned char **pder);
    int (*param_missing)(const int *pk);
    int (*param_copy)(int *to, const int *from);
    int (*param_cmp)(const int *a, const int *b);
    int (*param_print)(BIO *out, const int *pkey, int indent,
                       int *pctx);
    int (*sig_print)(BIO *out,
                     const int *sigalg, const int *sig,
                     int indent, int *pctx);


    void (*pkey_free)(int *pkey);
    int (*pkey_ctrl)(int *pkey, int op, long arg1, void *arg2);

    /* Legacy functions for old PEM */

    int (*old_priv_decode)(int *pkey,
                           const unsigned char **pder, int derlen);
    int (*old_priv_encode)(const int *pkey, unsigned char **pder);
    /* Custom ASN1 signature verification */
    int (*item_verify)(int *ctx, const int *it, void *asn,
                       int *a, int *sig,
                       int *pkey);
    int (*item_sign)(int *ctx, const int *it, void *asn,
                     int *alg1, int *alg2,
                     int *sig);

} /* EVP_PKEY_ASN1_METHOD */;

/* Method to handle CRL access.
 * In general a CRL could be very large (several Mb) and can consume large
 * amounts of resources if stored in memory by multiple processes.
 * This method allows general CRL operations to be redirected to more
 * efficient callbacks: for example a CRL entry database.
 */

#define X509_CRL_METHOD_DYNAMIC		1



#define BN_MUL_COMBA
#define BN_SQR_COMBA
#define BN_RECURSION


#if defined(OPENSSL_SYS_MSDOS) || defined(OPENSSL_SYS_WINDOWS) || \
    defined(OPENSSL_SYS_WIN32) || defined(linux)
# ifndef BN_DIV2W
#  define BN_DIV2W
# endif
#endif

#define BN_ULONG	unsigned long//samyang add depend on openssl sys32
#define BN_BITS2	32			  //samyang add
#define BN_BYTES	4			  //samyang add

/* assuming long is 64bit - this is the DEC Alpha
 * unsigned long long is only 64 bits :-(, don't define
 * BN_LLONG for the DEC Alpha */
#ifdef SIXTY_FOUR_BIT_LONG
#define BN_ULLONG	unsigned long long
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK		(0xffffffffffffffffffffffffffffffffLL)
#define BN_MASK2	(0xffffffffffffffffL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000L)
#define BN_MASK2h1	(0xffffffff80000000L)
#define BN_TBIT		(0x8000000000000000L)
#define BN_DEC_CONV	(10000000000000000000UL)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%019lu"
#define BN_DEC_NUM	19
#endif

/* This is where the long long data type is 64 bits, but long is 32.
 * For machines where there are 64bit registers, this is the mode to use.
 * IRIX, on R4000 and above should use this mode, along with the relevant
 * assembler code :-).  Do NOT define BN_LLONG.
 */
#ifdef SIXTY_FOUR_BIT
#undef BN_LLONG
#undef BN_ULLONG
#define BN_ULONG	unsigned long long
#define BN_LONG		long long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffLL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000LL)
#define BN_MASK2h1	(0xffffffff80000000LL)
#define BN_TBIT		(0x8000000000000000LL)
#define BN_DEC_CONV	(10000000000000000000ULL)
#define BN_DEC_FMT1	"%llu"
#define BN_DEC_FMT2	"%019llu"
#define BN_DEC_NUM	19
#endif

#ifdef THIRTY_TWO_BIT
#ifdef BN_LLONG
# if defined(OPENSSL_SYS_WIN32) && !defined(__GNUC__)
#  define BN_ULLONG	unsigned __int64
# else
#  define BN_ULLONG	unsigned long long
# endif
#endif
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BN_BITS		64
#define BN_BYTES	4
#define BN_BITS2	32
#define BN_BITS4	16
#ifdef OPENSSL_SYS_WIN32
/* VC++ doesn't like the LL suffix */
#define BN_MASK		(0xffffffffffffffffL)
#else
#define BN_MASK		(0xffffffffffffffffLL)
#endif
#define BN_MASK2	(0xffffffffL)
#define BN_MASK2l	(0xffff)
#define BN_MASK2h1	(0xffff8000L)
#define BN_MASK2h	(0xffff0000L)
#define BN_TBIT		(0x80000000L)
#define BN_DEC_CONV	(1000000000L)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%09lu"
#define BN_DEC_NUM	9
#endif

#ifdef SIXTEEN_BIT
#ifndef BN_DIV2W
#define BN_DIV2W
#endif
#define BN_ULLONG	unsigned long
#define BN_ULONG	unsigned short
#define BN_LONG		short
#define BN_BITS		32
#define BN_BYTES	2
#define BN_BITS2	16
#define BN_BITS4	8
#define BN_MASK		(0xffffffff)
#define BN_MASK2	(0xffff)
#define BN_MASK2l	(0xff)
#define BN_MASK2h1	(0xff80)
#define BN_MASK2h	(0xff00)
#define BN_TBIT		(0x8000)
#define BN_DEC_CONV	(100000)
#define BN_DEC_FMT1	"%u"
#define BN_DEC_FMT2	"%05u"
#define BN_DEC_NUM	5
#endif

#ifdef EIGHT_BIT
#ifndef BN_DIV2W
#define BN_DIV2W
#endif
#define BN_ULLONG	unsigned short
#define BN_ULONG	unsigned char
#define BN_LONG		char
#define BN_BITS		16
#define BN_BYTES	1
#define BN_BITS2	8
#define BN_BITS4	4
#define BN_MASK		(0xffff)
#define BN_MASK2	(0xff)
#define BN_MASK2l	(0xf)
#define BN_MASK2h1	(0xf8)
#define BN_MASK2h	(0xf0)
#define BN_TBIT		(0x80)
#define BN_DEC_CONV	(100)
#define BN_DEC_FMT1	"%u"
#define BN_DEC_FMT2	"%02u"
#define BN_DEC_NUM	2
#endif

#define BN_DEFAULT_BITS	1280

#define BN_FLG_MALLOCED		0x01
#define BN_FLG_STATIC_DATA	0x02
#define BN_FLG_CONSTTIME	0x04 /* avoid leaking exponent information through timing,
                                      * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
                                      * BN_div() will call BN_div_no_branch,
                                      * BN_mod_inverse() will call BN_mod_inverse_no_branch.
                                      */

#ifndef OPENSSL_NO_DEPRECATED
#define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME /* deprecated name for the flag */
/* avoid leaking exponent information through timings
* (BN_mod_exp_mont() will call BN_mod_exp_mont_consttime) */
#endif

#ifndef OPENSSL_NO_DEPRECATED
#define BN_FLG_FREE		0x8000	/* used for debuging */
#endif
#define BN_set_flags(b,n)	((b)->flags|=(n))
#define BN_get_flags(b,n)	((b)->flags&(n))

/* get a clone of a BIGNUM with changed flags, for *temporary* use only
 * (the two BIGNUMs cannot not be used in parallel!) */
#define BN_with_flags(dest,b,n)  ((dest)->d=(b)->d, \
                                  (dest)->top=(b)->top, \
                                  (dest)->dmax=(b)->dmax, \
                                  (dest)->neg=(b)->neg, \
                                  (dest)->flags=(((dest)->flags & BN_FLG_MALLOCED) \
                                                 |  ((b)->flags & ~BN_FLG_MALLOCED) \
                                                 |  BN_FLG_STATIC_DATA \
                                                 |  (n)))

/* Already declared in ossl_typ.h */
#if 0
typedef struct bignum_st BIGNUM;
/* Used for temp variables (declaration hidden in bn_lcl.h) */
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;
#endif

struct bignum_st
{
    BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
    int top;	/* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;	/* Size of the d array. */
    int neg;	/* one if the number is negative */
    int flags;
};

/* Used for montgomery multiplication */
struct bn_mont_ctx_st
{
    int ri;        /* number of bits in R */
    BIGNUM RR;     /* used to convert to montgomery form */
    BIGNUM N;      /* The modulus */
    BIGNUM Ni;     /* R*(1/R mod N) - N*Ni = 1
	                * (Ni is only stored for bignum algorithm) */
#if 0
    /* OpenSSL 0.9.9 preview: */
	BN_ULONG n0[2];/* least significant word(s) of Ni */
#else
    BN_ULONG n0;   /* least significant word of Ni */
#endif
    int flags;
};

/* Used for reciprocal division/mod functions
 * It cannot be shared between threads
 */
struct bn_recp_ctx_st
{
    BIGNUM N;	/* the divisor */
    BIGNUM Nr;	/* the reciprocal */
    int num_bits;
    int shift;
    int flags;
};

/* Used for slow "generation" functions. */
struct bn_gencb_st
{
    unsigned int ver;	/* To handle binary (in)compatibility */
    void *arg;		/* callback-specific data */
    union
    {
        /* if(ver==1) - handles old style callbacks */
        void (*cb_1)(int, int, void *);
        /* if(ver==2) - new callback style */
        int (*cb_2)(int, int, BN_GENCB *);
    } cb;
};
/* Wrapper function to make using BN_GENCB easier,  */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);
/* Macro to populate a BN_GENCB structure with an "old"-style callback */
#define BN_GENCB_set_old(gencb, callback, cb_arg) { \
		BN_GENCB *tmp_gencb = (gencb); \
		tmp_gencb->ver = 1; \
		tmp_gencb->arg = (cb_arg); \
		tmp_gencb->cb.cb_1 = (callback); }
/* Macro to populate a BN_GENCB structure with a "new"-style callback */
#define BN_GENCB_set(gencb, callback, cb_arg) { \
		BN_GENCB *tmp_gencb = (gencb); \
		tmp_gencb->ver = 2; \
		tmp_gencb->arg = (cb_arg); \
		tmp_gencb->cb.cb_2 = (callback); }

#define BN_prime_checks 0 /* default: select number of iterations
			     based on the size of the number */

#define BN_prime_checks_for_size(b) ((b) >= 1300 ?  2 : \
                                (b) >=  850 ?  3 : \
                                (b) >=  650 ?  4 : \
                                (b) >=  550 ?  5 : \
                                (b) >=  450 ?  6 : \
                                (b) >=  400 ?  7 : \
                                (b) >=  350 ?  8 : \
                                (b) >=  300 ?  9 : \
                                (b) >=  250 ? 12 : \
                                (b) >=  200 ? 15 : \
                                (b) >=  150 ? 18 : \
                                /* b >= 100 */ 27)

#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)

/* Note that BN_abs_is_word didn't work reliably for w == 0 until 0.9.8 */
#define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))
#define BN_is_zero(a)       ((a)->top == 0)
#define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)
#define BN_is_word(a,w)     (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
#define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))

#define BN_one(a)	(BN_set_word((a),1))
#define BN_zero_ex(a) \
	do { \
		BIGNUM *_tmp_bn = (a); \
		_tmp_bn->top = 0; \
		_tmp_bn->neg = 0; \
	} while(0)
#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)
#else
#define BN_zero(a)	(BN_set_word((a),0))
#endif

const BIGNUM *BN_value_one(void);
char *	BN_options(void);
BN_CTX *BN_CTX_new(void);
#ifndef OPENSSL_NO_DEPRECATED
void	BN_CTX_init(BN_CTX *c);
#endif
void	BN_CTX_free(BN_CTX *c);
void	BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void	BN_CTX_end(BN_CTX *ctx);
int     BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
int     BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
int	BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int	BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int	BN_num_bits(const BIGNUM *a);
int	BN_num_bits_word(BN_ULONG);
BIGNUM *BN_new(void);
void	BN_init(BIGNUM *);
void	BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void	BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int	BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
int	BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int	BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void	BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  a  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
#define BN_is_negative(a) ((a)->neg != 0)

int	BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
              BN_CTX *ctx);
#define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
int	BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int	BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int	BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int	BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                  const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int	BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
int	BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int	BN_mul_word(BIGNUM *a, BN_ULONG w);
int	BN_add_word(BIGNUM *a, BN_ULONG w);
int	BN_sub_word(BIGNUM *a, BN_ULONG w);
int	BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUM *a);

int	BN_cmp(const BIGNUM *a, const BIGNUM *b);
void	BN_free(BIGNUM *a);
int	BN_is_bit_set(const BIGNUM *a, int n);
int	BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int	BN_lshift1(BIGNUM *r, const BIGNUM *a);
int	BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);

int	BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                  const BIGNUM *m,BN_CTX *ctx);
int	BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
int	BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int	BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
                        const BIGNUM *a2, const BIGNUM *p2,const BIGNUM *m,
                        BN_CTX *ctx,BN_MONT_CTX *m_ctx);
int	BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                         const BIGNUM *m,BN_CTX *ctx);

int	BN_mask_bits(BIGNUM *a,int n);
#ifdef OPENSSL_NO_FP_API
int	BN_print_fp(FILE *fp, const BIGNUM *a);
#endif
#ifdef HEADER_BIO_H
int	BN_print(BIO *fp, const BIGNUM *a);
#else
int	BN_print(void *fp, const BIGNUM *a);
#endif
int	BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int	BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int	BN_rshift1(BIGNUM *r, const BIGNUM *a);
void	BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int	BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int	BN_set_bit(BIGNUM *a, int n);
int	BN_clear_bit(BIGNUM *a, int n);
char *	BN_bn2hex(const BIGNUM *a);
char *	BN_bn2dec(const BIGNUM *a);
int 	BN_hex2bn(BIGNUM **a, const char *str);
int 	BN_dec2bn(BIGNUM **a, const char *str);
int	BN_gcd(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
int	BN_kronecker(const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx); /* returns -2 for error */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
                       const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
                    const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

/* Deprecated versions */
#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe,
                          const BIGNUM *add, const BIGNUM *rem,
                          void (*callback)(int,int,void *),void *cb_arg);
int	BN_is_prime(const BIGNUM *p,int nchecks,
                   void (*callback)(int,int,void *),
                   BN_CTX *ctx,void *cb_arg);
int	BN_is_prime_fasttest(const BIGNUM *p,int nchecks,
                            void (*callback)(int,int,void *),BN_CTX *ctx,void *cb_arg,
                            int do_trial_division);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* Newer versions */
int	BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add,
                            const BIGNUM *rem, BN_GENCB *cb);
int	BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int	BN_is_prime_fasttest_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx,
                               int do_trial_division, BN_GENCB *cb);

int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);

int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                            const BIGNUM *Xp, const BIGNUM *Xp1, const BIGNUM *Xp2,
                            const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
                              BIGNUM *Xp1, BIGNUM *Xp2,
                              const BIGNUM *Xp,
                              const BIGNUM *e, BN_CTX *ctx,
                              BN_GENCB *cb);

BN_MONT_CTX *BN_MONT_CTX_new(void );
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
int BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
                          BN_MONT_CTX *mont, BN_CTX *ctx);
#define BN_to_montgomery(r,a,mont,ctx)	BN_mod_mul_montgomery(\
	(r),(a),&((mont)->RR),(mont),(ctx))
int BN_from_montgomery(BIGNUM *r,const BIGNUM *a,
                       BN_MONT_CTX *mont, BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
                                    const BIGNUM *mod, BN_CTX *ctx);

/* BN_BLINDING flags */
#define	BN_BLINDING_NO_UPDATE	0x00000001
#define	BN_BLINDING_NO_RECREATE	0x00000002

BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, /* const */ BIGNUM *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b, BN_CTX *);
unsigned long BN_BLINDING_get_thread_id(const BN_BLINDING *);
void BN_BLINDING_set_thread_id(BN_BLINDING *, unsigned long);
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
                                      const BIGNUM *e, /* const */ BIGNUM *m, BN_CTX *ctx,
                                      int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                                                        const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
                                      BN_MONT_CTX *m_ctx);

#ifndef OPENSSL_NO_DEPRECATED
void BN_set_params(int mul,int high,int low,int mont);
int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
#endif

void	BN_RECP_CTX_init(BN_RECP_CTX *recp);
BN_RECP_CTX *BN_RECP_CTX_new(void);
void	BN_RECP_CTX_free(BN_RECP_CTX *recp);
int	BN_RECP_CTX_set(BN_RECP_CTX *recp,const BIGNUM *rdiv,BN_CTX *ctx);
int	BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                             BN_RECP_CTX *recp,BN_CTX *ctx);
int	BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx);
int	BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                   BN_RECP_CTX *recp, BN_CTX *ctx);



int	BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b); /*r = a + b*/
#define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
int	BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p); /*r=a mod p*/
int	BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                       const BIGNUM *p, BN_CTX *ctx); /* r = (a * b) mod p */
int	BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       BN_CTX *ctx); /* r = (a * a) mod p */
int	BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p,
                       BN_CTX *ctx); /* r = (1 / b) mod p */
int	BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                       const BIGNUM *p, BN_CTX *ctx); /* r = (a / b) mod p */
int	BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                       const BIGNUM *p, BN_CTX *ctx); /* r = (a ^ b) mod p */
int	BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                        BN_CTX *ctx); /* r = sqrt(a) mod p */
int	BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                              BN_CTX *ctx); /* r^2 + r = a mod p */
#define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
/* Some functions allow for representation of the irreducible polynomials
 * as an unsigned int[], say p.  The irreducible f(t) is then of the form:
 *     t^p[0] + t^p[1] + ... + t^p[k]
 * where m = p[0] > p[1] > ... > p[k] = 0.
 */
int	BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[]);
/* r = a mod p */
int	BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                           const unsigned int p[], BN_CTX *ctx); /* r = (a * b) mod p */
int	BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[],
                           BN_CTX *ctx); /* r = (a * a) mod p */
int	BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const unsigned int p[],
                           BN_CTX *ctx); /* r = (1 / b) mod p */
int	BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                           const unsigned int p[], BN_CTX *ctx); /* r = (a / b) mod p */
int	BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                           const unsigned int p[], BN_CTX *ctx); /* r = (a ^ b) mod p */
int	BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
                            const unsigned int p[], BN_CTX *ctx); /* r = sqrt(a) mod p */
int	BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a,
                                  const unsigned int p[], BN_CTX *ctx); /* r^2 + r = a mod p */
int	BN_GF2m_poly2arr(const BIGNUM *a, unsigned int p[], int max);
int	BN_GF2m_arr2poly(const unsigned int p[], BIGNUM *a);

/* faster mod functions for the 'NIST primes'
 * 0 <= a < p^2 */
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);

/* library internal functions */

#define bn_expand(a,bits) ((((((bits+BN_BITS2-1))/BN_BITS2)) <= (a)->dmax)?\
	(a):bn_expand2((a),(bits+BN_BITS2-1)/BN_BITS2))
#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))
BIGNUM *bn_expand2(BIGNUM *a, int words);
#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *bn_dup_expand(const BIGNUM *a, int words); /* unused */
#endif



#ifdef BN_DEBUG

/* We only need assert() when debugging */
#include <assert.h>

#ifdef BN_DEBUG_RAND
/* To avoid "make update" cvs wars due to BN_DEBUG, use some tricks */
#ifndef RAND_pseudo_bytes
int RAND_pseudo_bytes(unsigned char *buf,int num);
#define BN_DEBUG_TRIX
#endif
#define bn_pollute(a) \
	do { \
		const BIGNUM *_bnum1 = (a); \
		if(_bnum1->top < _bnum1->dmax) { \
			unsigned char _tmp_char; \
			/* We cast away const without the compiler knowing, any \
			 * *genuinely* constant variables that aren't mutable \
			 * wouldn't be constructed with top!=dmax. */ \
			BN_ULONG *_not_const; \
			memcpy(&_not_const, &_bnum1->d, sizeof(BN_ULONG*)); \
			RAND_pseudo_bytes(&_tmp_char, 1); \
			memset((unsigned char *)(_not_const + _bnum1->top), _tmp_char, \
				(_bnum1->dmax - _bnum1->top) * sizeof(BN_ULONG)); \
		} \
	} while(0)
#ifdef BN_DEBUG_TRIX
#undef RAND_pseudo_bytes
#endif
#else
#define bn_pollute(a)
#endif
#define bn_check_top(a) \
	do { \
		const BIGNUM *_bnum2 = (a); \
		if (_bnum2 != NULL) { \
			assert((_bnum2->top == 0) || \
				(_bnum2->d[_bnum2->top - 1] != 0)); \
			bn_pollute(_bnum2); \
		} \
	} while(0)

#define bn_fix_top(a)		bn_check_top(a)

#else /* !BN_DEBUG */

#define bn_pollute(a)
#define bn_check_top(a)
#define bn_fix_top(a)		bn_correct_top(a)

#endif

#define bn_correct_top(a) \
        { \
        BN_ULONG *ftl; \
	if ((a)->top > 0) \
		{ \
		for (ftl= &((a)->d[(a)->top-1]); (a)->top > 0; (a)->top--) \
		if (*(ftl--)) break; \
		} \
	bn_pollute(a); \
	}

BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w);
void     bn_sqr_words(BN_ULONG *rp, const BN_ULONG *ap, int num);
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d);
BN_ULONG bn_add_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);
BN_ULONG bn_sub_words(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,int num);

/* Primes from RFC 2409 */
BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);

/* Primes from RFC 3526 */
BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);

int BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_BN_strings(void);

/* Error codes for the BN functions. */

/* Function codes. */
#define BN_F_BNRAND					 127
#define BN_F_BN_BLINDING_CONVERT_EX			 100
#define BN_F_BN_BLINDING_CREATE_PARAM			 128
#define BN_F_BN_BLINDING_INVERT_EX			 101
#define BN_F_BN_BLINDING_NEW				 102
#define BN_F_BN_BLINDING_UPDATE				 103
#define BN_F_BN_BN2DEC					 104
#define BN_F_BN_BN2HEX					 105
#define BN_F_BN_CTX_GET					 116
#define BN_F_BN_CTX_NEW					 106
#define BN_F_BN_CTX_START				 129
#define BN_F_BN_DIV					 107
#define BN_F_BN_DIV_NO_BRANCH				 138
#define BN_F_BN_DIV_RECP				 130
#define BN_F_BN_EXP					 123
#define BN_F_BN_EXPAND2					 108
#define BN_F_BN_EXPAND_INTERNAL				 120
#define BN_F_BN_GF2M_MOD				 131
#define BN_F_BN_GF2M_MOD_EXP				 132
#define BN_F_BN_GF2M_MOD_MUL				 133
#define BN_F_BN_GF2M_MOD_SOLVE_QUAD			 134
#define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR			 135
#define BN_F_BN_GF2M_MOD_SQR				 136
#define BN_F_BN_GF2M_MOD_SQRT				 137
#define BN_F_BN_MOD_EXP2_MONT				 118
#define BN_F_BN_MOD_EXP_MONT				 109
#define BN_F_BN_MOD_EXP_MONT_CONSTTIME			 124
#define BN_F_BN_MOD_EXP_MONT_WORD			 117
#define BN_F_BN_MOD_EXP_RECP				 125
#define BN_F_BN_MOD_EXP_SIMPLE				 126
#define BN_F_BN_MOD_INVERSE				 110
#define BN_F_BN_MOD_INVERSE_NO_BRANCH			 139
#define BN_F_BN_MOD_LSHIFT_QUICK			 119
#define BN_F_BN_MOD_MUL_RECIPROCAL			 111
#define BN_F_BN_MOD_SQRT				 121
#define BN_F_BN_MPI2BN					 112
#define BN_F_BN_NEW					 113
#define BN_F_BN_RAND					 114
#define BN_F_BN_RAND_RANGE				 122
#define BN_F_BN_USUB					 115

/* Reason codes. */
#define BN_R_ARG2_LT_ARG3				 100
#define BN_R_BAD_RECIPROCAL				 101
#define BN_R_BIGNUM_TOO_LONG				 114
#define BN_R_CALLED_WITH_EVEN_MODULUS			 102
#define BN_R_DIV_BY_ZERO				 103
#define BN_R_ENCODING_ERROR				 104
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA		 105
#define BN_R_INPUT_NOT_REDUCED				 110
#define BN_R_INVALID_LENGTH				 106
#define BN_R_INVALID_RANGE				 115
#define BN_R_NOT_A_SQUARE				 111
#define BN_R_NOT_INITIALIZED				 107
#define BN_R_NO_INVERSE					 108
#define BN_R_NO_SOLUTION				 116
#define BN_R_P_IS_NOT_PRIME				 112
#define BN_R_TOO_MANY_ITERATIONS			 113
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES		 109


#ifdef OPENSSL_BUILD_SHLIBCRYPTO
# undef OPENSSL_EXTERN
# define OPENSSL_EXTERN OPENSSL_EXPORT
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define V_ASN1_UNIVERSAL		0x00
#define	V_ASN1_APPLICATION		0x40
#define V_ASN1_CONTEXT_SPECIFIC		0x80
#define V_ASN1_PRIVATE			0xc0

#define V_ASN1_CONSTRUCTED		0x20
#define V_ASN1_PRIMITIVE_TAG		0x1f
#define V_ASN1_PRIMATIVE_TAG		0x1f

#define V_ASN1_APP_CHOOSE		-2	/* let the recipient choose */
#define V_ASN1_OTHER			-3	/* used in ASN1_TYPE */
#define V_ASN1_ANY			-4	/* used in ASN1 template code */

#define V_ASN1_NEG			0x100	/* negative flag */

#define V_ASN1_UNDEF			-1
#define V_ASN1_EOC			0
#define V_ASN1_BOOLEAN			1	/**/
#define V_ASN1_INTEGER			2
#define V_ASN1_NEG_INTEGER		(2 | V_ASN1_NEG)
#define V_ASN1_BIT_STRING		3
#define V_ASN1_OCTET_STRING		4
#define V_ASN1_NULL			5
#define V_ASN1_OBJECT			6
#define V_ASN1_OBJECT_DESCRIPTOR	7
#define V_ASN1_EXTERNAL			8
#define V_ASN1_REAL			9
#define V_ASN1_ENUMERATED		10
#define V_ASN1_NEG_ENUMERATED		(10 | V_ASN1_NEG)
#define V_ASN1_UTF8STRING		12
#define V_ASN1_SEQUENCE			16
#define V_ASN1_SET			17
#define V_ASN1_NUMERICSTRING		18	/**/
#define V_ASN1_PRINTABLESTRING		19
#define V_ASN1_T61STRING		20
#define V_ASN1_TELETEXSTRING		20	/* alias */
#define V_ASN1_VIDEOTEXSTRING		21	/**/
#define V_ASN1_IA5STRING		22
#define V_ASN1_UTCTIME			23
#define V_ASN1_GENERALIZEDTIME		24	/**/
#define V_ASN1_GRAPHICSTRING		25	/**/
#define V_ASN1_ISO64STRING		26	/**/
#define V_ASN1_VISIBLESTRING		26	/* alias */
#define V_ASN1_GENERALSTRING		27	/**/
#define V_ASN1_UNIVERSALSTRING		28	/**/
#define V_ASN1_BMPSTRING		30

/* For use with d2i_ASN1_type_bytes() */
#define B_ASN1_NUMERICSTRING	0x0001
#define B_ASN1_PRINTABLESTRING	0x0002
#define B_ASN1_T61STRING	0x0004
#define B_ASN1_TELETEXSTRING	0x0004
#define B_ASN1_VIDEOTEXSTRING	0x0008
#define B_ASN1_IA5STRING	0x0010
#define B_ASN1_GRAPHICSTRING	0x0020
#define B_ASN1_ISO64STRING	0x0040
#define B_ASN1_VISIBLESTRING	0x0040
#define B_ASN1_GENERALSTRING	0x0080
#define B_ASN1_UNIVERSALSTRING	0x0100
#define B_ASN1_OCTET_STRING	0x0200
#define B_ASN1_BIT_STRING	0x0400
#define B_ASN1_BMPSTRING	0x0800
#define B_ASN1_UNKNOWN		0x1000
#define B_ASN1_UTF8STRING	0x2000
#define B_ASN1_UTCTIME		0x4000
#define B_ASN1_GENERALIZEDTIME	0x8000
#define B_ASN1_SEQUENCE		0x10000

/* For use with ASN1_mbstring_copy() */
#define MBSTRING_FLAG		0x1000
#define MBSTRING_UTF8		(MBSTRING_FLAG)
#define MBSTRING_ASC		(MBSTRING_FLAG|1)
#define MBSTRING_BMP		(MBSTRING_FLAG|2)
#define MBSTRING_UNIV		(MBSTRING_FLAG|4)

#define SMIME_OLDMIME		0x400
#define SMIME_CRLFEOL		0x800
#define SMIME_STREAM		0x1000

struct X509_algor_st;
DECLARE_STACK_OF(X509_ALGOR)

#define DECLARE_ASN1_SET_OF(type) /* filled in by mkstack.pl */
#define IMPLEMENT_ASN1_SET_OF(type) /* nothing, no longer needed */

/* We MUST make sure that, except for constness, asn1_ctx_st and
   asn1_const_ctx are exactly the same.  Fortunately, as soon as
   the old ASN1 parsing macros are gone, we can throw this away
   as well... */
typedef struct asn1_ctx_st
{
    unsigned char *p;/* work char pointer */
    int eos;	/* end of sequence read for indefinite encoding */
    int error;	/* error code to use when returning an error */
    int inf;	/* constructed if 0x20, indefinite is 0x21 */
    int tag;	/* tag from last 'get object' */
    int xclass;	/* class from last 'get object' */
    long slen;	/* length of last 'get object' */
    unsigned char *max; /* largest value of p allowed */
    unsigned char *q;/* temporary variable */
    unsigned char **pp;/* variable */
    int line;	/* used in error processing */
} ASN1_CTX;

typedef struct asn1_const_ctx_st
{
    const unsigned char *p;/* work char pointer */
    int eos;	/* end of sequence read for indefinite encoding */
    int error;	/* error code to use when returning an error */
    int inf;	/* constructed if 0x20, indefinite is 0x21 */
    int tag;	/* tag from last 'get object' */
    int xclass;	/* class from last 'get object' */
    long slen;	/* length of last 'get object' */
    const unsigned char *max; /* largest value of p allowed */
    const unsigned char *q;/* temporary variable */
    const unsigned char **pp;/* variable */
    int line;	/* used in error processing */
} ASN1_const_CTX;

/* These are used internally in the ASN1_OBJECT to keep track of
 * whether the names and data need to be free()ed */
#define ASN1_OBJECT_FLAG_DYNAMIC	 0x01	/* internal use */
#define ASN1_OBJECT_FLAG_CRITICAL	 0x02	/* critical x509v3 object id */
#define ASN1_OBJECT_FLAG_DYNAMIC_STRINGS 0x04	/* internal use */
#define ASN1_OBJECT_FLAG_DYNAMIC_DATA 	 0x08	/* internal use */
typedef struct asn1_object_st
{
    const char *sn,*ln;
    int nid;
    int length;
    unsigned char *data;				//--hgl--20140403--two_certif test
    int flags;	/* Should we free this one */
} ASN1_OBJECT;

#define ASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */
/* This indicates that the ASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should
 * be inserted in the memory buffer
 */
#define ASN1_STRING_FLAG_NDEF 0x010

/* This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been
 * accessed. The flag will be reset when content has been written to it.
 */
#define ASN1_STRING_FLAG_CONT 0x020

/* This is the base type that holds just about everything :-) */
typedef struct asn1_string_st
{
    int length;
    int type;
    unsigned char *data;
    /* The value of the following field depends on the type being
     * held.  It is mostly being used for BIT_STRING so if the
     * input data has a non-zero 'unused bits' value, it will be
     * handled correctly */
    long flags;
} ASN1_STRING;

/* ASN1_ENCODING structure: this is used to save the received
 * encoding of an ASN1 type. This is useful to get round
 * problems with invalid encodings which can break signatures.
 */

typedef struct ASN1_ENCODING_st
{
    unsigned char *enc;	/* DER encoding */
    long len;		/* Length of encoding */
    int modified;		 /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

/* Used with ASN1 LONG type: if a long is set to this it is omitted */
#define ASN1_LONG_UNDEF	0x7fffffffL

#define STABLE_FLAGS_MALLOC	0x01
#define STABLE_NO_MASK		0x02
#define DIRSTRING_TYPE	\
 (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)
#define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)

typedef struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
} ASN1_STRING_TABLE;

DECLARE_STACK_OF(ASN1_STRING_TABLE)

/* size limits: this stuff is taken straight from RFC2459 */

#define ub_name				32768
#define ub_common_name			64
#define ub_locality_name		128
#define ub_state_name			128
#define ub_organization_name		64
#define ub_organization_unit_name	64
#define ub_title			64
#define ub_email_address		128

/* Declarations for template structures: for full definitions
 * see asn1t.h
 */
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_ITEM_st ASN1_ITEM ;
typedef struct ASN1_TLC_st ASN1_TLC;
/* This is just an opaque pointer */
typedef struct ASN1_VALUE_st ASN1_VALUE;

/* Declare ASN1 functions: the implement macro in in asn1t.h */

#define DECLARE_ASN1_FUNCTIONS(type) DECLARE_ASN1_FUNCTIONS_name(type, type)

#define DECLARE_ASN1_ALLOC_FUNCTIONS(type) \
	DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, type)

#define DECLARE_ASN1_FUNCTIONS_name(type, name) \
	DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
	DECLARE_ASN1_ENCODE_FUNCTIONS(type, name, name)

#define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
	DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
	DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)

#define	DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name) \
	type *d2i_##name(type **a, const unsigned char **in, long len); \
	int i2d_##name(type *a, unsigned char **out); \
	DECLARE_ASN1_ITEM(itname)

#define	DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
	type *d2i_##name(type **a, const unsigned char **in, long len); \
	int i2d_##name(const type *a, unsigned char **out); \
	DECLARE_ASN1_ITEM(name)

#define	DECLARE_ASN1_NDEF_FUNCTION(name) \
	int i2d_##name##_NDEF(name *a, unsigned char **out);

#define DECLARE_ASN1_FUNCTIONS_const(name) \
	DECLARE_ASN1_ALLOC_FUNCTIONS(name) \
	DECLARE_ASN1_ENCODE_FUNCTIONS_const(name, name)

#define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
	type *name##_new(void); \
	void name##_free(type *a);

#define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
#define I2D_OF(type) int (*)(type *,unsigned char **)
#define I2D_OF_const(type) int (*)(const type *,unsigned char **)

#define CHECKED_D2I_OF(type, d2i) \
    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
#define CHECKED_I2D_OF(type, i2d) \
    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
#define CHECKED_NEW_OF(type, xnew) \
    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
#define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
#define CHECKED_PPTR_OF(type, p) \
    ((void**) (1 ? p : (type**)0))
#define CHECKED_PTR_OF_TO_CHAR(type, p) \
    ((char*) (1 ? p : (type*)0))

#define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
#define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
#define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

TYPEDEF_D2I2D_OF(void);

/* The following macros and typedefs allow an ASN1_ITEM
 * to be embedded in a structure and referenced. Since
 * the ASN1_ITEM pointers need to be globally accessible
 * (possibly from shared libraries) they may exist in
 * different forms. On platforms that support it the
 * ASN1_ITEM structure itself will be globally exported.
 * Other platforms will export a function that returns
 * an ASN1_ITEM pointer.
 *
 * To handle both cases transparently the macros below
 * should be used instead of hard coding an ASN1_ITEM
 * pointer in a structure.
 *
 * The structure will look like this:
 *
 * typedef struct SOMETHING_st {
 *      ...
 *      ASN1_ITEM_EXP *iptr;
 *      ...
 * } SOMETHING;
 *
 * It would be initialised as e.g.:
 *
 * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
 *
 * and the actual pointer extracted with:
 *
 * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
 *
 * Finally an ASN1_ITEM pointer can be extracted from an
 * appropriate reference with: ASN1_ITEM_rptr(X509). This
 * would be used when a function takes an ASN1_ITEM * argument.
 *
 */

#ifndef OPENSSL_EXPORT_VAR_AS_FUNCTION

/* ASN1_ITEM pointer exported type */
typedef const ASN1_ITEM ASN1_ITEM_EXP;

/* Macro to obtain ASN1_ITEM pointer from exported type */
#define ASN1_ITEM_ptr(iptr) (iptr)

/* Macro to include ASN1_ITEM pointer from base type */
#define ASN1_ITEM_ref(iptr) (&(iptr##_it))

#define ASN1_ITEM_rptr(ref) (&(ref##_it))

#define DECLARE_ASN1_ITEM(name) \
	OPENSSL_EXTERN const ASN1_ITEM name##_it;

#else

/* Platforms that can't easily handle shared global variables are declared
 * as functions returning ASN1_ITEM pointers.
 */

/* ASN1_ITEM pointer exported type */
typedef const ASN1_ITEM * ASN1_ITEM_EXP(void);

/* Macro to obtain ASN1_ITEM pointer from exported type */
#define ASN1_ITEM_ptr(iptr) (iptr())

/* Macro to include ASN1_ITEM pointer from base type */
#define ASN1_ITEM_ref(iptr) (iptr##_it)

#define ASN1_ITEM_rptr(ref) (ref##_it())

#define DECLARE_ASN1_ITEM(name) \
	const ASN1_ITEM * name##_it(void);

#endif

/* Parameters used by ASN1_STRING_print_ex() */

/* These determine which characters to escape:
 * RFC2253 special characters, control characters and
 * MSB set characters
 */

#define ASN1_STRFLGS_ESC_2253		1
#define ASN1_STRFLGS_ESC_CTRL		2
#define ASN1_STRFLGS_ESC_MSB		4


/* This flag determines how we do escaping: normally
 * RC2253 backslash only, set this to use backslash and
 * quote.
 */

#define ASN1_STRFLGS_ESC_QUOTE		8


/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
#define CHARTYPE_PRINTABLESTRING	0x10
/* Character needs escaping if it is the first character */
#define CHARTYPE_FIRST_ESC_2253		0x20
/* Character needs escaping if it is the last character */
#define CHARTYPE_LAST_ESC_2253		0x40

/* NB the internal flags are safely reused below by flags
 * handled at the top level.
 */

/* If this is set we convert all character strings
 * to UTF8 first
 */

#define ASN1_STRFLGS_UTF8_CONVERT	0x10

/* If this is set we don't attempt to interpret content:
 * just assume all strings are 1 byte per character. This
 * will produce some pretty odd looking output!
 */

#define ASN1_STRFLGS_IGNORE_TYPE	0x20

/* If this is set we include the string type in the output */
#define ASN1_STRFLGS_SHOW_TYPE		0x40

/* This determines which strings to display and which to
 * 'dump' (hex dump of content octets or DER encoding). We can
 * only dump non character strings or everything. If we
 * don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to
 * the usual escaping options.
 */

#define ASN1_STRFLGS_DUMP_ALL		0x80
#define ASN1_STRFLGS_DUMP_UNKNOWN	0x100

/* These determine what 'dumping' does, we can dump the
 * content octets or the DER encoding: both use the
 * RFC2253 #XXXXX notation.
 */

#define ASN1_STRFLGS_DUMP_DER		0x200

/* All the string flags consistent with RFC2253,
 * escaping control characters isn't essential in
 * RFC2253 but it is advisable anyway.
 */

#define ASN1_STRFLGS_RFC2253	(ASN1_STRFLGS_ESC_2253 | \
				ASN1_STRFLGS_ESC_CTRL | \
				ASN1_STRFLGS_ESC_MSB | \
				ASN1_STRFLGS_UTF8_CONVERT | \
				ASN1_STRFLGS_DUMP_UNKNOWN | \
				ASN1_STRFLGS_DUMP_DER)

DECLARE_STACK_OF(ASN1_INTEGER)
DECLARE_ASN1_SET_OF(ASN1_INTEGER)

DECLARE_STACK_OF(ASN1_GENERALSTRING)

typedef struct asn1_type_st
{
    int type;
    union	{
        char *ptr;
        ASN1_BOOLEAN		boolean;
        ASN1_STRING *		asn1_string;
        ASN1_OBJECT *		object;
        ASN1_INTEGER *		integer;
        ASN1_ENUMERATED *	enumerated;
        ASN1_BIT_STRING *	bit_string;
        ASN1_OCTET_STRING *	octet_string;
        ASN1_PRINTABLESTRING *	printablestring;
        ASN1_T61STRING *	t61string;
        ASN1_IA5STRING *	ia5string;
        ASN1_GENERALSTRING *	generalstring;
        ASN1_BMPSTRING *	bmpstring;
        ASN1_UNIVERSALSTRING *	universalstring;
        ASN1_UTCTIME *		utctime;
        ASN1_GENERALIZEDTIME *	generalizedtime;
        ASN1_VISIBLESTRING *	visiblestring;
        ASN1_UTF8STRING *	utf8string;
        /* set and sequence are left complete and still
         * contain the set or sequence bytes */
        ASN1_STRING *		set;
        ASN1_STRING *		sequence;
        ASN1_VALUE  *		asn1_value;
    } value;
} ASN1_TYPE;

DECLARE_STACK_OF(ASN1_TYPE)
DECLARE_ASN1_SET_OF(ASN1_TYPE)

typedef struct asn1_method_st
{
    i2d_of_void *i2d;
    d2i_of_void *d2i;
    void *(*create)(void);
    void (*destroy)(void *);
} ASN1_METHOD;

/* This is used when parsing some Netscape objects */
typedef struct asn1_header_st
{
    ASN1_OCTET_STRING *header;
    void *data;
    ASN1_METHOD *meth;
} ASN1_HEADER;

/* This is used to contain a list of bit names */
typedef struct BIT_STRING_BITNAME_st {
    int bitnum;
    const char *lname;
    const char *sname;
} BIT_STRING_BITNAME;


#define M_ASN1_STRING_length(x)	((x)->length)
#define M_ASN1_STRING_length_set(x, n)	((x)->length = (n))
#define M_ASN1_STRING_type(x)	((x)->type)
#define M_ASN1_STRING_data(x)	((x)->data)

/* Macros for string operations */
#define M_ASN1_BIT_STRING_new()	(ASN1_BIT_STRING *)\
		ASN1_STRING_type_new(V_ASN1_BIT_STRING)
#define M_ASN1_BIT_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_BIT_STRING_dup(a) (ASN1_BIT_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_BIT_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define M_ASN1_BIT_STRING_set(a,b,c) ASN1_STRING_set((ASN1_STRING *)a,b,c)

#define M_ASN1_INTEGER_new()	(ASN1_INTEGER *)\
		ASN1_STRING_type_new(V_ASN1_INTEGER)
#define M_ASN1_INTEGER_free(a)		ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_INTEGER_dup(a) (ASN1_INTEGER *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_INTEGER_cmp(a,b)	ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)

#define M_ASN1_ENUMERATED_new()	(ASN1_ENUMERATED *)\
		ASN1_STRING_type_new(V_ASN1_ENUMERATED)
#define M_ASN1_ENUMERATED_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_ENUMERATED_dup(a) (ASN1_ENUMERATED *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_ENUMERATED_cmp(a,b)	ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)

#define M_ASN1_OCTET_STRING_new()	(ASN1_OCTET_STRING *)\
		ASN1_STRING_type_new(V_ASN1_OCTET_STRING)
#define M_ASN1_OCTET_STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_OCTET_STRING_dup(a) (ASN1_OCTET_STRING *)\
		ASN1_STRING_dup((ASN1_STRING *)a)
#define M_ASN1_OCTET_STRING_cmp(a,b) ASN1_STRING_cmp(\
		(ASN1_STRING *)a,(ASN1_STRING *)b)
#define M_ASN1_OCTET_STRING_set(a,b,c)	ASN1_STRING_set((ASN1_STRING *)a,b,c)
#define M_ASN1_OCTET_STRING_print(a,b)	ASN1_STRING_print(a,(ASN1_STRING *)b)
#define M_i2d_ASN1_OCTET_STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_OCTET_STRING,\
		V_ASN1_UNIVERSAL)

#define B_ASN1_TIME \
			B_ASN1_UTCTIME | \
			B_ASN1_GENERALIZEDTIME

#define B_ASN1_PRINTABLE \
			B_ASN1_NUMERICSTRING| \
			B_ASN1_PRINTABLESTRING| \
			B_ASN1_T61STRING| \
			B_ASN1_IA5STRING| \
			B_ASN1_BIT_STRING| \
			B_ASN1_UNIVERSALSTRING|\
			B_ASN1_BMPSTRING|\
			B_ASN1_UTF8STRING|\
			B_ASN1_SEQUENCE|\
			B_ASN1_UNKNOWN

#define B_ASN1_DIRECTORYSTRING \
			B_ASN1_PRINTABLESTRING| \
			B_ASN1_TELETEXSTRING|\
			B_ASN1_BMPSTRING|\
			B_ASN1_UNIVERSALSTRING|\
			B_ASN1_UTF8STRING

#define B_ASN1_DISPLAYTEXT \
			B_ASN1_IA5STRING| \
			B_ASN1_VISIBLESTRING| \
			B_ASN1_BMPSTRING|\
			B_ASN1_UTF8STRING

#define M_ASN1_PRINTABLE_new()	ASN1_STRING_type_new(V_ASN1_T61STRING)
#define M_ASN1_PRINTABLE_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_PRINTABLE(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
		pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_PRINTABLE(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_PRINTABLE)

#define M_DIRECTORYSTRING_new() ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
#define M_DIRECTORYSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_DIRECTORYSTRING(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
						pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_DIRECTORYSTRING(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_DIRECTORYSTRING)

#define M_DISPLAYTEXT_new() ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define M_DISPLAYTEXT_free(a) ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_DISPLAYTEXT(a,pp) i2d_ASN1_bytes((ASN1_STRING *)a,\
						pp,a->type,V_ASN1_UNIVERSAL)
#define M_d2i_DISPLAYTEXT(a,pp,l) \
		d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l, \
			B_ASN1_DISPLAYTEXT)

#define M_ASN1_PRINTABLESTRING_new() (ASN1_PRINTABLESTRING *)\
		ASN1_STRING_type_new(V_ASN1_PRINTABLESTRING)
#define M_ASN1_PRINTABLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_PRINTABLESTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_PRINTABLESTRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_PRINTABLESTRING(a,pp,l) \
		(ASN1_PRINTABLESTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_PRINTABLESTRING)

#define M_ASN1_T61STRING_new()	(ASN1_T61STRING *)\
		ASN1_STRING_type_new(V_ASN1_T61STRING)
#define M_ASN1_T61STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_T61STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_T61STRING,\
		V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_T61STRING(a,pp,l) \
		(ASN1_T61STRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_T61STRING)

#define M_ASN1_IA5STRING_new()	(ASN1_IA5STRING *)\
		ASN1_STRING_type_new(V_ASN1_IA5STRING)
#define M_ASN1_IA5STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_IA5STRING_dup(a)	\
			(ASN1_IA5STRING *)ASN1_STRING_dup((ASN1_STRING *)a)
#define M_i2d_ASN1_IA5STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_IA5STRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_IA5STRING(a,pp,l) \
		(ASN1_IA5STRING *)d2i_ASN1_type_bytes((ASN1_STRING **)a,pp,l,\
			B_ASN1_IA5STRING)

#define M_ASN1_UTCTIME_new()	(ASN1_UTCTIME *)\
		ASN1_STRING_type_new(V_ASN1_UTCTIME)
#define M_ASN1_UTCTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_UTCTIME_dup(a) (ASN1_UTCTIME *)ASN1_STRING_dup((ASN1_STRING *)a)

#define M_ASN1_GENERALIZEDTIME_new()	(ASN1_GENERALIZEDTIME *)\
		ASN1_STRING_type_new(V_ASN1_GENERALIZEDTIME)
#define M_ASN1_GENERALIZEDTIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_GENERALIZEDTIME_dup(a) (ASN1_GENERALIZEDTIME *)ASN1_STRING_dup(\
	(ASN1_STRING *)a)

#define M_ASN1_TIME_new()	(ASN1_TIME *)\
		ASN1_STRING_type_new(V_ASN1_UTCTIME)
#define M_ASN1_TIME_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_ASN1_TIME_dup(a) (ASN1_TIME *)ASN1_STRING_dup((ASN1_STRING *)a)

#define M_ASN1_GENERALSTRING_new()	(ASN1_GENERALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_GENERALSTRING)
#define M_ASN1_GENERALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_GENERALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_GENERALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_GENERALSTRING(a,pp,l) \
		(ASN1_GENERALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_GENERALSTRING)

#define M_ASN1_UNIVERSALSTRING_new()	(ASN1_UNIVERSALSTRING *)\
		ASN1_STRING_type_new(V_ASN1_UNIVERSALSTRING)
#define M_ASN1_UNIVERSALSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_UNIVERSALSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_UNIVERSALSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_UNIVERSALSTRING(a,pp,l) \
		(ASN1_UNIVERSALSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_UNIVERSALSTRING)

#define M_ASN1_BMPSTRING_new()	(ASN1_BMPSTRING *)\
		ASN1_STRING_type_new(V_ASN1_BMPSTRING)
#define M_ASN1_BMPSTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_BMPSTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_BMPSTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_BMPSTRING(a,pp,l) \
		(ASN1_BMPSTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_BMPSTRING)

#define M_ASN1_VISIBLESTRING_new()	(ASN1_VISIBLESTRING *)\
		ASN1_STRING_type_new(V_ASN1_VISIBLESTRING)
#define M_ASN1_VISIBLESTRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_VISIBLESTRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_VISIBLESTRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_VISIBLESTRING(a,pp,l) \
		(ASN1_VISIBLESTRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_VISIBLESTRING)

#define M_ASN1_UTF8STRING_new()	(ASN1_UTF8STRING *)\
		ASN1_STRING_type_new(V_ASN1_UTF8STRING)
#define M_ASN1_UTF8STRING_free(a)	ASN1_STRING_free((ASN1_STRING *)a)
#define M_i2d_ASN1_UTF8STRING(a,pp) \
		i2d_ASN1_bytes((ASN1_STRING *)a,pp,V_ASN1_UTF8STRING,\
			V_ASN1_UNIVERSAL)
#define M_d2i_ASN1_UTF8STRING(a,pp,l) \
		(ASN1_UTF8STRING *)d2i_ASN1_type_bytes\
		((ASN1_STRING **)a,pp,l,B_ASN1_UTF8STRING)

/* for the is_set parameter to i2d_ASN1_SET */
#define IS_SEQUENCE	0
#define IS_SET		1

DECLARE_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)

int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);

ASN1_OBJECT *	ASN1_OBJECT_new(void );
void		ASN1_OBJECT_free(ASN1_OBJECT *a);
int		i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT *	c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
                                 long length);
ASN1_OBJECT *	d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
                                 long length);

DECLARE_ASN1_ITEM(ASN1_OBJECT)

DECLARE_STACK_OF(ASN1_OBJECT)
DECLARE_ASN1_SET_OF(ASN1_OBJECT)

ASN1_STRING *	ASN1_STRING_new(void);
void		ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_dup(ASN1_STRING *a);
ASN1_STRING *	ASN1_STRING_type_new(int type );
int 		ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b);
/* Since this is used to store all sorts of things, via macros, for now, make
   its data void * */
int 		ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void		ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(ASN1_STRING *x);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);

DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
int		i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,const unsigned char **pp,
                                     long length);
int		ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d,
                               int length );
int		ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int		ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);

#ifndef OPENSSL_NO_BIO
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
                               BIT_STRING_BITNAME *tbl, int indent);
#endif
int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
                            BIT_STRING_BITNAME *tbl);

int		i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int 		d2i_ASN1_BOOLEAN(int *a,const unsigned char **pp,long length);

DECLARE_ASN1_FUNCTIONS(ASN1_INTEGER)
int		i2c_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,const unsigned char **pp,
                               long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,const unsigned char **pp,
                                long length);
ASN1_INTEGER *	ASN1_INTEGER_dup(ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(ASN1_INTEGER *x, ASN1_INTEGER *y);

DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
#if 0
time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s);
#endif

int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);

DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
ASN1_OCTET_STRING *	ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *a);
int 	ASN1_OCTET_STRING_cmp(ASN1_OCTET_STRING *a, ASN1_OCTET_STRING *b);
int 	ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);

DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)

DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UTCTIME)
DECLARE_ASN1_FUNCTIONS(ASN1_GENERALIZEDTIME)
DECLARE_ASN1_FUNCTIONS(ASN1_TIME)

DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);
int ASN1_TIME_check(ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);

int i2d_ASN1_SET(STACK *a, unsigned char **pp,
                 i2d_of_void *i2d, int ex_tag, int ex_class, int is_set);
STACK *	d2i_ASN1_SET(STACK **a, const unsigned char **pp, long length,
                        d2i_of_void *d2i, void (*free_func)(void *),
                        int ex_tag, int ex_class);

#ifndef OPENSSL_NO_BIO
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);
#endif
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
                                const char *sn, const char *ln);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);

int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
int ASN1_PRINTABLE_type(const unsigned char *s, int max);

int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass);
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
                            long length, int Ptag, int Pclass);
unsigned long ASN1_tag2bit(int tag);
/* type is one or more of the B_ASN1_ values. */
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,const unsigned char **pp,
                                 long length,int type);

/* PARSING */
int asn1_Finish(ASN1_CTX *c);
int asn1_const_Finish(ASN1_const_CTX *c);

/* SPECIALS */
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p,long len);
int ASN1_const_check_infinite_end(const unsigned char **p,long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
                     int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x);

#define ASN1_dup_of(type,i2d,d2i,x) \
    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
		     CHECKED_D2I_OF(type, d2i), \
		     CHECKED_PTR_OF_TO_CHAR(type, x)))

#define ASN1_dup_of_const(type,i2d,d2i,x) \
    ((type*)ASN1_dup(CHECKED_I2D_OF(const type, i2d), \
		     CHECKED_D2I_OF(type, d2i), \
		     CHECKED_PTR_OF_TO_CHAR(const type, x)))

void *ASN1_item_dup(const ASN1_ITEM *it, void *x);

/* ASN1 alloc/free macros for when a type is only used internally */

#define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
#define M_ASN1_free_of(x, type) \
		ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))

#ifdef OPENSSL_NO_FP_API
void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);

#define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
			CHECKED_D2I_OF(type, d2i), \
			in, \
			CHECKED_PPTR_OF(type, x)))

void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);

#define ASN1_i2d_fp_of(type,i2d,out,x) \
    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
		 out, \
		 CHECKED_PTR_OF(type, x)))

#define ASN1_i2d_fp_of_const(type,i2d,out,x) \
    (ASN1_i2d_fp(CHECKED_I2D_OF(const type, i2d), \
		 out, \
		 CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags);
#endif

int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);

#ifndef OPENSSL_NO_BIO
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);

#define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
			  CHECKED_D2I_OF(type, d2i), \
			  in, \
			  CHECKED_PPTR_OF(type, x)))

void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x);
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out, unsigned char *x);

#define ASN1_i2d_bio_of(type,i2d,out,x) \
    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
		  out, \
		  CHECKED_PTR_OF(type, x)))

#define ASN1_i2d_bio_of_const(type,i2d,out,x) \
    (ASN1_i2d_bio(CHECKED_I2D_OF(const type, i2d), \
		  out, \
		  CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x);
int ASN1_UTCTIME_print(BIO *fp,ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp,ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp,ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp,ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_parse(BIO *bp,const unsigned char *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,const unsigned char *pp,long len,int indent,int dump);
#endif
const char *ASN1_tag2str(int tag);

/* Used to load and write netscape format cert/key */
int i2d_ASN1_HEADER(ASN1_HEADER *a,unsigned char **pp);
ASN1_HEADER *d2i_ASN1_HEADER(ASN1_HEADER **a,const unsigned char **pp, long length);
ASN1_HEADER *ASN1_HEADER_new(void );
void ASN1_HEADER_free(ASN1_HEADER *a);

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

/* Not used that much at this point, except for the first two */
ASN1_METHOD *X509_asn1_meth(void);
ASN1_METHOD *RSAPrivateKey_asn1_meth(void);
ASN1_METHOD *ASN1_IA5STRING_asn1_meth(void);
ASN1_METHOD *ASN1_BIT_STRING_asn1_meth(void);

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,
                              unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,
                              unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
                                  unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,
                                  unsigned char *data, int max_len);

STACK *ASN1_seq_unpack(const unsigned char *buf, int len,
                       d2i_of_void *d2i, void (*free_func)(void *));
unsigned char *ASN1_seq_pack(STACK *safes, i2d_of_void *i2d,
                             unsigned char **buf, int *len );
void *ASN1_unpack_string(ASN1_STRING *oct, d2i_of_void *d2i);
void *ASN1_item_unpack(ASN1_STRING *oct, const ASN1_ITEM *it);
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d,
                              ASN1_OCTET_STRING **oct);

#define ASN1_pack_string_of(type,obj,i2d,oct) \
    (ASN1_pack_string(CHECKED_PTR_OF(type, obj), \
		      CHECKED_I2D_OF(type, i2d), \
		      oct))

ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_OCTET_STRING **oct);

void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
                       int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
                        int inform, unsigned long mask,
                        long minsize, long maxsize);

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
                                    const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);

/* ASN1 template functions */

/* Old API compatible functions */
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);

void ASN1_add_oid_module(void);

ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);

typedef int asn1_output_data_fn(BIO *out, BIO *data, ASN1_VALUE *val, int flags,
                                const ASN1_ITEM *it);

int int_smime_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
                         int ctype_nid, int econt_nid,
                         STACK_OF(X509_ALGOR) *mdalgs,
                         asn1_output_data_fn *data_fn,
                         const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ASN1_strings(void);

/* Error codes for the ASN1 functions. */

/* Function codes. */
#define ASN1_F_A2D_ASN1_OBJECT				 100
#define ASN1_F_A2I_ASN1_ENUMERATED			 101
#define ASN1_F_A2I_ASN1_INTEGER				 102
#define ASN1_F_A2I_ASN1_STRING				 103
#define ASN1_F_APPEND_EXP				 176
#define ASN1_F_ASN1_BIT_STRING_SET_BIT			 183
#define ASN1_F_ASN1_CB					 177
#define ASN1_F_ASN1_CHECK_TLEN				 104
#define ASN1_F_ASN1_COLLATE_PRIMITIVE			 105
#define ASN1_F_ASN1_COLLECT				 106
#define ASN1_F_ASN1_D2I_EX_PRIMITIVE			 108
#define ASN1_F_ASN1_D2I_FP				 109
#define ASN1_F_ASN1_D2I_READ_BIO			 107
#define ASN1_F_ASN1_DIGEST				 184
#define ASN1_F_ASN1_DO_ADB				 110
#define ASN1_F_ASN1_DUP					 111
#define ASN1_F_ASN1_ENUMERATED_SET			 112
#define ASN1_F_ASN1_ENUMERATED_TO_BN			 113
#define ASN1_F_ASN1_EX_C2I				 204
#define ASN1_F_ASN1_FIND_END				 190
#define ASN1_F_ASN1_GENERALIZEDTIME_SET			 185
#define ASN1_F_ASN1_GENERATE_V3				 178
#define ASN1_F_ASN1_GET_OBJECT				 114
#define ASN1_F_ASN1_HEADER_NEW				 115
#define ASN1_F_ASN1_I2D_BIO				 116
#define ASN1_F_ASN1_I2D_FP				 117
#define ASN1_F_ASN1_INTEGER_SET				 118
#define ASN1_F_ASN1_INTEGER_TO_BN			 119
#define ASN1_F_ASN1_ITEM_D2I_FP				 206
#define ASN1_F_ASN1_ITEM_DUP				 191
#define ASN1_F_ASN1_ITEM_EX_COMBINE_NEW			 121
#define ASN1_F_ASN1_ITEM_EX_D2I				 120
#define ASN1_F_ASN1_ITEM_I2D_BIO			 192
#define ASN1_F_ASN1_ITEM_I2D_FP				 193
#define ASN1_F_ASN1_ITEM_PACK				 198
#define ASN1_F_ASN1_ITEM_SIGN				 195
#define ASN1_F_ASN1_ITEM_UNPACK				 199
#define ASN1_F_ASN1_ITEM_VERIFY				 197
#define ASN1_F_ASN1_MBSTRING_NCOPY			 122
#define ASN1_F_ASN1_OBJECT_NEW				 123
#define ASN1_F_ASN1_OUTPUT_DATA				 207
#define ASN1_F_ASN1_PACK_STRING				 124
#define ASN1_F_ASN1_PCTX_NEW				 205
#define ASN1_F_ASN1_PKCS5_PBE_SET			 125
#define ASN1_F_ASN1_SEQ_PACK				 126
#define ASN1_F_ASN1_SEQ_UNPACK				 127
#define ASN1_F_ASN1_SIGN				 128
#define ASN1_F_ASN1_STR2TYPE				 179
#define ASN1_F_ASN1_STRING_SET				 186
#define ASN1_F_ASN1_STRING_TABLE_ADD			 129
#define ASN1_F_ASN1_STRING_TYPE_NEW			 130
#define ASN1_F_ASN1_TEMPLATE_EX_D2I			 132
#define ASN1_F_ASN1_TEMPLATE_NEW			 133
#define ASN1_F_ASN1_TEMPLATE_NOEXP_D2I			 131
#define ASN1_F_ASN1_TIME_SET				 175
#define ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING		 134
#define ASN1_F_ASN1_TYPE_GET_OCTETSTRING		 135
#define ASN1_F_ASN1_UNPACK_STRING			 136
#define ASN1_F_ASN1_UTCTIME_SET				 187
#define ASN1_F_ASN1_VERIFY				 137
#define ASN1_F_B64_READ_ASN1				 208
#define ASN1_F_B64_WRITE_ASN1				 209
#define ASN1_F_BITSTR_CB				 180
#define ASN1_F_BN_TO_ASN1_ENUMERATED			 138
#define ASN1_F_BN_TO_ASN1_INTEGER			 139
#define ASN1_F_C2I_ASN1_BIT_STRING			 189
#define ASN1_F_C2I_ASN1_INTEGER				 194
#define ASN1_F_C2I_ASN1_OBJECT				 196
#define ASN1_F_COLLECT_DATA				 140
#define ASN1_F_D2I_ASN1_BIT_STRING			 141
#define ASN1_F_D2I_ASN1_BOOLEAN				 142
#define ASN1_F_D2I_ASN1_BYTES				 143
#define ASN1_F_D2I_ASN1_GENERALIZEDTIME			 144
#define ASN1_F_D2I_ASN1_HEADER				 145
#define ASN1_F_D2I_ASN1_INTEGER				 146
#define ASN1_F_D2I_ASN1_OBJECT				 147
#define ASN1_F_D2I_ASN1_SET				 148
#define ASN1_F_D2I_ASN1_TYPE_BYTES			 149
#define ASN1_F_D2I_ASN1_UINTEGER			 150
#define ASN1_F_D2I_ASN1_UTCTIME				 151
#define ASN1_F_D2I_NETSCAPE_RSA				 152
#define ASN1_F_D2I_NETSCAPE_RSA_2			 153
#define ASN1_F_D2I_PRIVATEKEY				 154
#define ASN1_F_D2I_PUBLICKEY				 155
#define ASN1_F_D2I_RSA_NET				 200
#define ASN1_F_D2I_RSA_NET_2				 201
#define ASN1_F_D2I_X509					 156
#define ASN1_F_D2I_X509_CINF				 157
#define ASN1_F_D2I_X509_PKEY				 159
#define ASN1_F_I2D_ASN1_SET				 188
#define ASN1_F_I2D_ASN1_TIME				 160
#define ASN1_F_I2D_DSA_PUBKEY				 161
#define ASN1_F_I2D_EC_PUBKEY				 181
#define ASN1_F_I2D_PRIVATEKEY				 163
#define ASN1_F_I2D_PUBLICKEY				 164
#define ASN1_F_I2D_RSA_NET				 162
#define ASN1_F_I2D_RSA_PUBKEY				 165
#define ASN1_F_LONG_C2I					 166
#define ASN1_F_OID_MODULE_INIT				 174
#define ASN1_F_PARSE_TAGGING				 182
#define ASN1_F_PKCS5_PBE2_SET				 167
#define ASN1_F_PKCS5_PBE_SET				 202
#define ASN1_F_SMIME_READ_ASN1				 210
#define ASN1_F_SMIME_TEXT				 211
#define ASN1_F_X509_CINF_NEW				 168
#define ASN1_F_X509_CRL_ADD0_REVOKED			 169
#define ASN1_F_X509_INFO_NEW				 170
#define ASN1_F_X509_NAME_ENCODE				 203
#define ASN1_F_X509_NAME_EX_D2I				 158
#define ASN1_F_X509_NAME_EX_NEW				 171
#define ASN1_F_X509_NEW					 172
#define ASN1_F_X509_PKEY_NEW				 173

/* Reason codes. */
#define ASN1_R_ADDING_OBJECT				 171
#define ASN1_R_ASN1_PARSE_ERROR				 198
#define ASN1_R_ASN1_SIG_PARSE_ERROR			 199
#define ASN1_R_AUX_ERROR				 100
#define ASN1_R_BAD_CLASS				 101
#define ASN1_R_BAD_OBJECT_HEADER			 102
#define ASN1_R_BAD_PASSWORD_READ			 103
#define ASN1_R_BAD_TAG					 104
#define ASN1_R_BMPSTRING_IS_WRONG_LENGTH		 210
#define ASN1_R_BN_LIB					 105
#define ASN1_R_BOOLEAN_IS_WRONG_LENGTH			 106
#define ASN1_R_BUFFER_TOO_SMALL				 107
#define ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER		 108
#define ASN1_R_DATA_IS_WRONG				 109
#define ASN1_R_DECODE_ERROR				 110
#define ASN1_R_DECODING_ERROR				 111
#define ASN1_R_DEPTH_EXCEEDED				 174
#define ASN1_R_ENCODE_ERROR				 112
#define ASN1_R_ERROR_GETTING_TIME			 173
#define ASN1_R_ERROR_LOADING_SECTION			 172
#define ASN1_R_ERROR_PARSING_SET_ELEMENT		 113
#define ASN1_R_ERROR_SETTING_CIPHER_PARAMS		 114
#define ASN1_R_EXPECTING_AN_INTEGER			 115
#define ASN1_R_EXPECTING_AN_OBJECT			 116
#define ASN1_R_EXPECTING_A_BOOLEAN			 117
#define ASN1_R_EXPECTING_A_TIME				 118
#define ASN1_R_EXPLICIT_LENGTH_MISMATCH			 119
#define ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED		 120
#define ASN1_R_FIELD_MISSING				 121
#define ASN1_R_FIRST_NUM_TOO_LARGE			 122
#define ASN1_R_HEADER_TOO_LONG				 123
#define ASN1_R_ILLEGAL_BITSTRING_FORMAT			 175
#define ASN1_R_ILLEGAL_BOOLEAN				 176
#define ASN1_R_ILLEGAL_CHARACTERS			 124
#define ASN1_R_ILLEGAL_FORMAT				 177
#define ASN1_R_ILLEGAL_HEX				 178
#define ASN1_R_ILLEGAL_IMPLICIT_TAG			 179
#define ASN1_R_ILLEGAL_INTEGER				 180
#define ASN1_R_ILLEGAL_NESTED_TAGGING			 181
#define ASN1_R_ILLEGAL_NULL				 125
#define ASN1_R_ILLEGAL_NULL_VALUE			 182
#define ASN1_R_ILLEGAL_OBJECT				 183
#define ASN1_R_ILLEGAL_OPTIONAL_ANY			 126
#define ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE		 170
#define ASN1_R_ILLEGAL_TAGGED_ANY			 127
#define ASN1_R_ILLEGAL_TIME_VALUE			 184
#define ASN1_R_INTEGER_NOT_ASCII_FORMAT			 185
#define ASN1_R_INTEGER_TOO_LARGE_FOR_LONG		 128
#define ASN1_R_INVALID_BMPSTRING_LENGTH			 129
#define ASN1_R_INVALID_DIGIT				 130
#define ASN1_R_INVALID_MIME_TYPE			 200
#define ASN1_R_INVALID_MODIFIER				 186
#define ASN1_R_INVALID_NUMBER				 187
#define ASN1_R_INVALID_OBJECT_ENCODING			 212
#define ASN1_R_INVALID_SEPARATOR			 131
#define ASN1_R_INVALID_TIME_FORMAT			 132
#define ASN1_R_INVALID_UNIVERSALSTRING_LENGTH		 133
#define ASN1_R_INVALID_UTF8STRING			 134
#define ASN1_R_IV_TOO_LARGE				 135
#define ASN1_R_LENGTH_ERROR				 136
#define ASN1_R_LIST_ERROR				 188
#define ASN1_R_MIME_NO_CONTENT_TYPE			 201
#define ASN1_R_MIME_PARSE_ERROR				 202
#define ASN1_R_MIME_SIG_PARSE_ERROR			 203
#define ASN1_R_MISSING_EOC				 137
#define ASN1_R_MISSING_SECOND_NUMBER			 138
#define ASN1_R_MISSING_VALUE				 189
#define ASN1_R_MSTRING_NOT_UNIVERSAL			 139
#define ASN1_R_MSTRING_WRONG_TAG			 140
#define ASN1_R_NESTED_ASN1_STRING			 197
#define ASN1_R_NON_HEX_CHARACTERS			 141
#define ASN1_R_NOT_ASCII_FORMAT				 190
#define ASN1_R_NOT_ENOUGH_DATA				 142
#define ASN1_R_NO_CONTENT_TYPE				 204
#define ASN1_R_NO_MATCHING_CHOICE_TYPE			 143
#define ASN1_R_NO_MULTIPART_BODY_FAILURE		 205
#define ASN1_R_NO_MULTIPART_BOUNDARY			 206
#define ASN1_R_NO_SIG_CONTENT_TYPE			 207
#define ASN1_R_NULL_IS_WRONG_LENGTH			 144
#define ASN1_R_OBJECT_NOT_ASCII_FORMAT			 191
#define ASN1_R_ODD_NUMBER_OF_CHARS			 145
#define ASN1_R_PRIVATE_KEY_HEADER_MISSING		 146
#define ASN1_R_SECOND_NUMBER_TOO_LARGE			 147
#define ASN1_R_SEQUENCE_LENGTH_MISMATCH			 148
#define ASN1_R_SEQUENCE_NOT_CONSTRUCTED			 149
#define ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG		 192
#define ASN1_R_SHORT_LINE				 150
#define ASN1_R_SIG_INVALID_MIME_TYPE			 208
#define ASN1_R_STREAMING_NOT_SUPPORTED			 209
#define ASN1_R_STRING_TOO_LONG				 151
#define ASN1_R_STRING_TOO_SHORT				 152
#define ASN1_R_TAG_VALUE_TOO_HIGH			 153
#define ASN1_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 154
#define ASN1_R_TIME_NOT_ASCII_FORMAT			 193
#define ASN1_R_TOO_LONG					 155
#define ASN1_R_TYPE_NOT_CONSTRUCTED			 156
#define ASN1_R_UNABLE_TO_DECODE_RSA_KEY			 157
#define ASN1_R_UNABLE_TO_DECODE_RSA_PRIVATE_KEY		 158
#define ASN1_R_UNEXPECTED_EOC				 159
#define ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH		 211
#define ASN1_R_UNKNOWN_FORMAT				 160
#define ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM		 161
#define ASN1_R_UNKNOWN_OBJECT_TYPE			 162
#define ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE			 163
#define ASN1_R_UNKNOWN_TAG				 194
#define ASN1_R_UNKOWN_FORMAT				 195
#define ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE		 164
#define ASN1_R_UNSUPPORTED_CIPHER			 165
#define ASN1_R_UNSUPPORTED_ENCRYPTION_ALGORITHM		 166
#define ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE		 167
#define ASN1_R_UNSUPPORTED_TYPE				 196
#define ASN1_R_WRONG_TAG				 168
#define ASN1_R_WRONG_TYPE				 169


#define SN_undef			"UNDEF"
#define LN_undef			"undefined"
#define NID_undef			0
#define OBJ_undef			0L

#define SN_itu_t		"ITU-T"
#define LN_itu_t		"itu-t"
#define NID_itu_t		645
#define OBJ_itu_t		0L

#define NID_ccitt		404
#define OBJ_ccitt		OBJ_itu_t

#define SN_iso		"ISO"
#define LN_iso		"iso"
#define NID_iso		181
#define OBJ_iso		1L

#define SN_joint_iso_itu_t		"JOINT-ISO-ITU-T"
#define LN_joint_iso_itu_t		"joint-iso-itu-t"
#define NID_joint_iso_itu_t		646
#define OBJ_joint_iso_itu_t		2L

#define NID_joint_iso_ccitt		393
#define OBJ_joint_iso_ccitt		OBJ_joint_iso_itu_t

#define SN_member_body		"member-body"
#define LN_member_body		"ISO Member Body"
#define NID_member_body		182
#define OBJ_member_body		OBJ_iso,2L

#define SN_identified_organization		"identified-organization"
#define NID_identified_organization		676
#define OBJ_identified_organization		OBJ_iso,3L

#define SN_hmac_md5		"HMAC-MD5"
#define LN_hmac_md5		"hmac-md5"
#define NID_hmac_md5		780
#define OBJ_hmac_md5		OBJ_identified_organization,6L,1L,5L,5L,8L,1L,1L

#define SN_hmac_sha1		"HMAC-SHA1"
#define LN_hmac_sha1		"hmac-sha1"
#define NID_hmac_sha1		781
#define OBJ_hmac_sha1		OBJ_identified_organization,6L,1L,5L,5L,8L,1L,2L

#define SN_certicom_arc		"certicom-arc"
#define NID_certicom_arc		677
#define OBJ_certicom_arc		OBJ_identified_organization,132L

#define SN_international_organizations		"international-organizations"
#define LN_international_organizations		"International Organizations"
#define NID_international_organizations		647
#define OBJ_international_organizations		OBJ_joint_iso_itu_t,23L

#define SN_wap		"wap"
#define NID_wap		678
#define OBJ_wap		OBJ_international_organizations,43L

#define SN_wap_wsg		"wap-wsg"
#define NID_wap_wsg		679
#define OBJ_wap_wsg		OBJ_wap,1L

#define SN_selected_attribute_types		"selected-attribute-types"
#define LN_selected_attribute_types		"Selected Attribute Types"
#define NID_selected_attribute_types		394
#define OBJ_selected_attribute_types		OBJ_joint_iso_itu_t,5L,1L,5L

#define SN_clearance		"clearance"
#define NID_clearance		395
#define OBJ_clearance		OBJ_selected_attribute_types,55L

#define SN_ISO_US		"ISO-US"
#define LN_ISO_US		"ISO US Member Body"
#define NID_ISO_US		183
#define OBJ_ISO_US		OBJ_member_body,840L

#define SN_X9_57		"X9-57"
#define LN_X9_57		"X9.57"
#define NID_X9_57		184
#define OBJ_X9_57		OBJ_ISO_US,10040L

#define SN_X9cm		"X9cm"
#define LN_X9cm		"X9.57 CM ?"
#define NID_X9cm		185
#define OBJ_X9cm		OBJ_X9_57,4L

#define SN_dsa		"DSA"
#define LN_dsa		"dsaEncryption"
#define NID_dsa		116
#define OBJ_dsa		OBJ_X9cm,1L

#define SN_dsaWithSHA1		"DSA-SHA1"
#define LN_dsaWithSHA1		"dsaWithSHA1"
#define NID_dsaWithSHA1		113
#define OBJ_dsaWithSHA1		OBJ_X9cm,3L

#define SN_ansi_X9_62		"ansi-X9-62"
#define LN_ansi_X9_62		"ANSI X9.62"
#define NID_ansi_X9_62		405
#define OBJ_ansi_X9_62		OBJ_ISO_US,10045L

#define OBJ_X9_62_id_fieldType		OBJ_ansi_X9_62,1L

#define SN_X9_62_prime_field		"prime-field"
#define NID_X9_62_prime_field		406
#define OBJ_X9_62_prime_field		OBJ_X9_62_id_fieldType,1L

#define SN_X9_62_characteristic_two_field		"characteristic-two-field"
#define NID_X9_62_characteristic_two_field		407
#define OBJ_X9_62_characteristic_two_field		OBJ_X9_62_id_fieldType,2L

#define SN_X9_62_id_characteristic_two_basis		"id-characteristic-two-basis"
#define NID_X9_62_id_characteristic_two_basis		680
#define OBJ_X9_62_id_characteristic_two_basis		OBJ_X9_62_characteristic_two_field,3L

#define SN_X9_62_onBasis		"onBasis"
#define NID_X9_62_onBasis		681
#define OBJ_X9_62_onBasis		OBJ_X9_62_id_characteristic_two_basis,1L

#define SN_X9_62_tpBasis		"tpBasis"
#define NID_X9_62_tpBasis		682
#define OBJ_X9_62_tpBasis		OBJ_X9_62_id_characteristic_two_basis,2L

#define SN_X9_62_ppBasis		"ppBasis"
#define NID_X9_62_ppBasis		683
#define OBJ_X9_62_ppBasis		OBJ_X9_62_id_characteristic_two_basis,3L

#define OBJ_X9_62_id_publicKeyType		OBJ_ansi_X9_62,2L

#define SN_X9_62_id_ecPublicKey		"id-ecPublicKey"
#define NID_X9_62_id_ecPublicKey		408
#define OBJ_X9_62_id_ecPublicKey		OBJ_X9_62_id_publicKeyType,1L

#define OBJ_X9_62_ellipticCurve		OBJ_ansi_X9_62,3L

#define OBJ_X9_62_c_TwoCurve		OBJ_X9_62_ellipticCurve,0L

#define SN_X9_62_c2pnb163v1		"c2pnb163v1"
#define NID_X9_62_c2pnb163v1		684
#define OBJ_X9_62_c2pnb163v1		OBJ_X9_62_c_TwoCurve,1L

#define SN_X9_62_c2pnb163v2		"c2pnb163v2"
#define NID_X9_62_c2pnb163v2		685
#define OBJ_X9_62_c2pnb163v2		OBJ_X9_62_c_TwoCurve,2L

#define SN_X9_62_c2pnb163v3		"c2pnb163v3"
#define NID_X9_62_c2pnb163v3		686
#define OBJ_X9_62_c2pnb163v3		OBJ_X9_62_c_TwoCurve,3L

#define SN_X9_62_c2pnb176v1		"c2pnb176v1"
#define NID_X9_62_c2pnb176v1		687
#define OBJ_X9_62_c2pnb176v1		OBJ_X9_62_c_TwoCurve,4L

#define SN_X9_62_c2tnb191v1		"c2tnb191v1"
#define NID_X9_62_c2tnb191v1		688
#define OBJ_X9_62_c2tnb191v1		OBJ_X9_62_c_TwoCurve,5L

#define SN_X9_62_c2tnb191v2		"c2tnb191v2"
#define NID_X9_62_c2tnb191v2		689
#define OBJ_X9_62_c2tnb191v2		OBJ_X9_62_c_TwoCurve,6L

#define SN_X9_62_c2tnb191v3		"c2tnb191v3"
#define NID_X9_62_c2tnb191v3		690
#define OBJ_X9_62_c2tnb191v3		OBJ_X9_62_c_TwoCurve,7L

#define SN_X9_62_c2onb191v4		"c2onb191v4"
#define NID_X9_62_c2onb191v4		691
#define OBJ_X9_62_c2onb191v4		OBJ_X9_62_c_TwoCurve,8L

#define SN_X9_62_c2onb191v5		"c2onb191v5"
#define NID_X9_62_c2onb191v5		692
#define OBJ_X9_62_c2onb191v5		OBJ_X9_62_c_TwoCurve,9L

#define SN_X9_62_c2pnb208w1		"c2pnb208w1"
#define NID_X9_62_c2pnb208w1		693
#define OBJ_X9_62_c2pnb208w1		OBJ_X9_62_c_TwoCurve,10L

#define SN_X9_62_c2tnb239v1		"c2tnb239v1"
#define NID_X9_62_c2tnb239v1		694
#define OBJ_X9_62_c2tnb239v1		OBJ_X9_62_c_TwoCurve,11L

#define SN_X9_62_c2tnb239v2		"c2tnb239v2"
#define NID_X9_62_c2tnb239v2		695
#define OBJ_X9_62_c2tnb239v2		OBJ_X9_62_c_TwoCurve,12L

#define SN_X9_62_c2tnb239v3		"c2tnb239v3"
#define NID_X9_62_c2tnb239v3		696
#define OBJ_X9_62_c2tnb239v3		OBJ_X9_62_c_TwoCurve,13L

#define SN_X9_62_c2onb239v4		"c2onb239v4"
#define NID_X9_62_c2onb239v4		697
#define OBJ_X9_62_c2onb239v4		OBJ_X9_62_c_TwoCurve,14L

#define SN_X9_62_c2onb239v5		"c2onb239v5"
#define NID_X9_62_c2onb239v5		698
#define OBJ_X9_62_c2onb239v5		OBJ_X9_62_c_TwoCurve,15L

#define SN_X9_62_c2pnb272w1		"c2pnb272w1"
#define NID_X9_62_c2pnb272w1		699
#define OBJ_X9_62_c2pnb272w1		OBJ_X9_62_c_TwoCurve,16L

#define SN_X9_62_c2pnb304w1		"c2pnb304w1"
#define NID_X9_62_c2pnb304w1		700
#define OBJ_X9_62_c2pnb304w1		OBJ_X9_62_c_TwoCurve,17L

#define SN_X9_62_c2tnb359v1		"c2tnb359v1"
#define NID_X9_62_c2tnb359v1		701
#define OBJ_X9_62_c2tnb359v1		OBJ_X9_62_c_TwoCurve,18L

#define SN_X9_62_c2pnb368w1		"c2pnb368w1"
#define NID_X9_62_c2pnb368w1		702
#define OBJ_X9_62_c2pnb368w1		OBJ_X9_62_c_TwoCurve,19L

#define SN_X9_62_c2tnb431r1		"c2tnb431r1"
#define NID_X9_62_c2tnb431r1		703
#define OBJ_X9_62_c2tnb431r1		OBJ_X9_62_c_TwoCurve,20L

#define OBJ_X9_62_primeCurve		OBJ_X9_62_ellipticCurve,1L

#define SN_X9_62_prime192v1		"prime192v1"
#define NID_X9_62_prime192v1		409
#define OBJ_X9_62_prime192v1		OBJ_X9_62_primeCurve,1L

#define SN_X9_62_prime192v2		"prime192v2"
#define NID_X9_62_prime192v2		410
#define OBJ_X9_62_prime192v2		OBJ_X9_62_primeCurve,2L

#define SN_X9_62_prime192v3		"prime192v3"
#define NID_X9_62_prime192v3		411
#define OBJ_X9_62_prime192v3		OBJ_X9_62_primeCurve,3L

#define SN_X9_62_prime239v1		"prime239v1"
#define NID_X9_62_prime239v1		412
#define OBJ_X9_62_prime239v1		OBJ_X9_62_primeCurve,4L

#define SN_X9_62_prime239v2		"prime239v2"
#define NID_X9_62_prime239v2		413
#define OBJ_X9_62_prime239v2		OBJ_X9_62_primeCurve,5L

#define SN_X9_62_prime239v3		"prime239v3"
#define NID_X9_62_prime239v3		414
#define OBJ_X9_62_prime239v3		OBJ_X9_62_primeCurve,6L

#define SN_X9_62_prime256v1		"prime256v1"
#define NID_X9_62_prime256v1		415
#define OBJ_X9_62_prime256v1		OBJ_X9_62_primeCurve,7L

#define OBJ_X9_62_id_ecSigType		OBJ_ansi_X9_62,4L

#define SN_ecdsa_with_SHA1		"ecdsa-with-SHA1"
#define NID_ecdsa_with_SHA1		416
#define OBJ_ecdsa_with_SHA1		OBJ_X9_62_id_ecSigType,1L

#define SN_ecdsa_with_Recommended		"ecdsa-with-Recommended"
#define NID_ecdsa_with_Recommended		791
#define OBJ_ecdsa_with_Recommended		OBJ_X9_62_id_ecSigType,2L

#define SN_ecdsa_with_Specified		"ecdsa-with-Specified"
#define NID_ecdsa_with_Specified		792
#define OBJ_ecdsa_with_Specified		OBJ_X9_62_id_ecSigType,3L

#define SN_ecdsa_with_SHA224		"ecdsa-with-SHA224"
#define NID_ecdsa_with_SHA224		793
#define OBJ_ecdsa_with_SHA224		OBJ_ecdsa_with_Specified,1L

#define SN_ecdsa_with_SHA256		"ecdsa-with-SHA256"
#define NID_ecdsa_with_SHA256		794
#define OBJ_ecdsa_with_SHA256		OBJ_ecdsa_with_Specified,2L

#define SN_ecdsa_with_SHA384		"ecdsa-with-SHA384"
#define NID_ecdsa_with_SHA384		795
#define OBJ_ecdsa_with_SHA384		OBJ_ecdsa_with_Specified,3L

#define SN_ecdsa_with_SHA512		"ecdsa-with-SHA512"
#define NID_ecdsa_with_SHA512		796
#define OBJ_ecdsa_with_SHA512		OBJ_ecdsa_with_Specified,4L

#define OBJ_secg_ellipticCurve		OBJ_certicom_arc,0L

#define SN_secp112r1		"secp112r1"
#define NID_secp112r1		704
#define OBJ_secp112r1		OBJ_secg_ellipticCurve,6L

#define SN_secp112r2		"secp112r2"
#define NID_secp112r2		705
#define OBJ_secp112r2		OBJ_secg_ellipticCurve,7L

#define SN_secp128r1		"secp128r1"
#define NID_secp128r1		706
#define OBJ_secp128r1		OBJ_secg_ellipticCurve,28L

#define SN_secp128r2		"secp128r2"
#define NID_secp128r2		707
#define OBJ_secp128r2		OBJ_secg_ellipticCurve,29L

#define SN_secp160k1		"secp160k1"
#define NID_secp160k1		708
#define OBJ_secp160k1		OBJ_secg_ellipticCurve,9L

#define SN_secp160r1		"secp160r1"
#define NID_secp160r1		709
#define OBJ_secp160r1		OBJ_secg_ellipticCurve,8L

#define SN_secp160r2		"secp160r2"
#define NID_secp160r2		710
#define OBJ_secp160r2		OBJ_secg_ellipticCurve,30L

#define SN_secp192k1		"secp192k1"
#define NID_secp192k1		711
#define OBJ_secp192k1		OBJ_secg_ellipticCurve,31L

#define SN_secp224k1		"secp224k1"
#define NID_secp224k1		712
#define OBJ_secp224k1		OBJ_secg_ellipticCurve,32L

#define SN_secp224r1		"secp224r1"
#define NID_secp224r1		713
#define OBJ_secp224r1		OBJ_secg_ellipticCurve,33L

#define SN_secp256k1		"secp256k1"
#define NID_secp256k1		714
#define OBJ_secp256k1		OBJ_secg_ellipticCurve,10L

#define SN_secp384r1		"secp384r1"
#define NID_secp384r1		715
#define OBJ_secp384r1		OBJ_secg_ellipticCurve,34L

#define SN_secp521r1		"secp521r1"
#define NID_secp521r1		716
#define OBJ_secp521r1		OBJ_secg_ellipticCurve,35L

#define SN_sect113r1		"sect113r1"
#define NID_sect113r1		717
#define OBJ_sect113r1		OBJ_secg_ellipticCurve,4L

#define SN_sect113r2		"sect113r2"
#define NID_sect113r2		718
#define OBJ_sect113r2		OBJ_secg_ellipticCurve,5L

#define SN_sect131r1		"sect131r1"
#define NID_sect131r1		719
#define OBJ_sect131r1		OBJ_secg_ellipticCurve,22L

#define SN_sect131r2		"sect131r2"
#define NID_sect131r2		720
#define OBJ_sect131r2		OBJ_secg_ellipticCurve,23L

#define SN_sect163k1		"sect163k1"
#define NID_sect163k1		721
#define OBJ_sect163k1		OBJ_secg_ellipticCurve,1L

#define SN_sect163r1		"sect163r1"
#define NID_sect163r1		722
#define OBJ_sect163r1		OBJ_secg_ellipticCurve,2L

#define SN_sect163r2		"sect163r2"
#define NID_sect163r2		723
#define OBJ_sect163r2		OBJ_secg_ellipticCurve,15L

#define SN_sect193r1		"sect193r1"
#define NID_sect193r1		724
#define OBJ_sect193r1		OBJ_secg_ellipticCurve,24L

#define SN_sect193r2		"sect193r2"
#define NID_sect193r2		725
#define OBJ_sect193r2		OBJ_secg_ellipticCurve,25L

#define SN_sect233k1		"sect233k1"
#define NID_sect233k1		726
#define OBJ_sect233k1		OBJ_secg_ellipticCurve,26L

#define SN_sect233r1		"sect233r1"
#define NID_sect233r1		727
#define OBJ_sect233r1		OBJ_secg_ellipticCurve,27L

#define SN_sect239k1		"sect239k1"
#define NID_sect239k1		728
#define OBJ_sect239k1		OBJ_secg_ellipticCurve,3L

#define SN_sect283k1		"sect283k1"
#define NID_sect283k1		729
#define OBJ_sect283k1		OBJ_secg_ellipticCurve,16L

#define SN_sect283r1		"sect283r1"
#define NID_sect283r1		730
#define OBJ_sect283r1		OBJ_secg_ellipticCurve,17L

#define SN_sect409k1		"sect409k1"
#define NID_sect409k1		731
#define OBJ_sect409k1		OBJ_secg_ellipticCurve,36L

#define SN_sect409r1		"sect409r1"
#define NID_sect409r1		732
#define OBJ_sect409r1		OBJ_secg_ellipticCurve,37L

#define SN_sect571k1		"sect571k1"
#define NID_sect571k1		733
#define OBJ_sect571k1		OBJ_secg_ellipticCurve,38L

#define SN_sect571r1		"sect571r1"
#define NID_sect571r1		734
#define OBJ_sect571r1		OBJ_secg_ellipticCurve,39L

#define OBJ_wap_wsg_idm_ecid		OBJ_wap_wsg,4L

#define SN_wap_wsg_idm_ecid_wtls1		"wap-wsg-idm-ecid-wtls1"
#define NID_wap_wsg_idm_ecid_wtls1		735
#define OBJ_wap_wsg_idm_ecid_wtls1		OBJ_wap_wsg_idm_ecid,1L

#define SN_wap_wsg_idm_ecid_wtls3		"wap-wsg-idm-ecid-wtls3"
#define NID_wap_wsg_idm_ecid_wtls3		736
#define OBJ_wap_wsg_idm_ecid_wtls3		OBJ_wap_wsg_idm_ecid,3L

#define SN_wap_wsg_idm_ecid_wtls4		"wap-wsg-idm-ecid-wtls4"
#define NID_wap_wsg_idm_ecid_wtls4		737
#define OBJ_wap_wsg_idm_ecid_wtls4		OBJ_wap_wsg_idm_ecid,4L

#define SN_wap_wsg_idm_ecid_wtls5		"wap-wsg-idm-ecid-wtls5"
#define NID_wap_wsg_idm_ecid_wtls5		738
#define OBJ_wap_wsg_idm_ecid_wtls5		OBJ_wap_wsg_idm_ecid,5L

#define SN_wap_wsg_idm_ecid_wtls6		"wap-wsg-idm-ecid-wtls6"
#define NID_wap_wsg_idm_ecid_wtls6		739
#define OBJ_wap_wsg_idm_ecid_wtls6		OBJ_wap_wsg_idm_ecid,6L

#define SN_wap_wsg_idm_ecid_wtls7		"wap-wsg-idm-ecid-wtls7"
#define NID_wap_wsg_idm_ecid_wtls7		740
#define OBJ_wap_wsg_idm_ecid_wtls7		OBJ_wap_wsg_idm_ecid,7L

#define SN_wap_wsg_idm_ecid_wtls8		"wap-wsg-idm-ecid-wtls8"
#define NID_wap_wsg_idm_ecid_wtls8		741
#define OBJ_wap_wsg_idm_ecid_wtls8		OBJ_wap_wsg_idm_ecid,8L

#define SN_wap_wsg_idm_ecid_wtls9		"wap-wsg-idm-ecid-wtls9"
#define NID_wap_wsg_idm_ecid_wtls9		742
#define OBJ_wap_wsg_idm_ecid_wtls9		OBJ_wap_wsg_idm_ecid,9L

#define SN_wap_wsg_idm_ecid_wtls10		"wap-wsg-idm-ecid-wtls10"
#define NID_wap_wsg_idm_ecid_wtls10		743
#define OBJ_wap_wsg_idm_ecid_wtls10		OBJ_wap_wsg_idm_ecid,10L

#define SN_wap_wsg_idm_ecid_wtls11		"wap-wsg-idm-ecid-wtls11"
#define NID_wap_wsg_idm_ecid_wtls11		744
#define OBJ_wap_wsg_idm_ecid_wtls11		OBJ_wap_wsg_idm_ecid,11L

#define SN_wap_wsg_idm_ecid_wtls12		"wap-wsg-idm-ecid-wtls12"
#define NID_wap_wsg_idm_ecid_wtls12		745
#define OBJ_wap_wsg_idm_ecid_wtls12		OBJ_wap_wsg_idm_ecid,12L

#define SN_cast5_cbc		"CAST5-CBC"
#define LN_cast5_cbc		"cast5-cbc"
#define NID_cast5_cbc		108
#define OBJ_cast5_cbc		OBJ_ISO_US,113533L,7L,66L,10L

#define SN_cast5_ecb		"CAST5-ECB"
#define LN_cast5_ecb		"cast5-ecb"
#define NID_cast5_ecb		109

#define SN_cast5_cfb64		"CAST5-CFB"
#define LN_cast5_cfb64		"cast5-cfb"
#define NID_cast5_cfb64		110

#define SN_cast5_ofb64		"CAST5-OFB"
#define LN_cast5_ofb64		"cast5-ofb"
#define NID_cast5_ofb64		111

#define LN_pbeWithMD5AndCast5_CBC		"pbeWithMD5AndCast5CBC"
#define NID_pbeWithMD5AndCast5_CBC		112
#define OBJ_pbeWithMD5AndCast5_CBC		OBJ_ISO_US,113533L,7L,66L,12L

#define SN_id_PasswordBasedMAC		"id-PasswordBasedMAC"
#define LN_id_PasswordBasedMAC		"password based MAC"
#define NID_id_PasswordBasedMAC		782
#define OBJ_id_PasswordBasedMAC		OBJ_ISO_US,113533L,7L,66L,13L

#define SN_id_DHBasedMac		"id-DHBasedMac"
#define LN_id_DHBasedMac		"Diffie-Hellman based MAC"
#define NID_id_DHBasedMac		783
#define OBJ_id_DHBasedMac		OBJ_ISO_US,113533L,7L,66L,30L

#define SN_rsadsi		"rsadsi"
#define LN_rsadsi		"RSA Data Security, Inc."
#define NID_rsadsi		1
#define OBJ_rsadsi		OBJ_ISO_US,113549L

#define SN_pkcs		"pkcs"
#define LN_pkcs		"RSA Data Security, Inc. PKCS"
#define NID_pkcs		15
#define OBJ_pkcs		OBJ_rsadsi,1L

#define SN_pkcs1		"pkcs1"
#define NID_pkcs1		16
#define OBJ_pkcs1		OBJ_pkcs,1L

#define LN_rsaEncryption		"rsaEncryption"
#define NID_rsaEncryption		1			//samyang modify
#define OBJ_rsaEncryption		OBJ_pkcs1,1L

#define SN_md2WithRSAEncryption		"RSA-MD2"
#define LN_md2WithRSAEncryption		"md2WithRSAEncryption"
#define NID_md2WithRSAEncryption		7
#define OBJ_md2WithRSAEncryption		OBJ_pkcs1,2L

#define SN_md4WithRSAEncryption		"RSA-MD4"
#define LN_md4WithRSAEncryption		"md4WithRSAEncryption"
#define NID_md4WithRSAEncryption		396
#define OBJ_md4WithRSAEncryption		OBJ_pkcs1,3L

#define SN_md5WithRSAEncryption		"RSA-MD5"
#define LN_md5WithRSAEncryption		"md5WithRSAEncryption"
#define NID_md5WithRSAEncryption		17
#define OBJ_md5WithRSAEncryption		OBJ_pkcs1,4L

#define SN_sha1WithRSAEncryption		"RSA-SHA1"
#define LN_sha1WithRSAEncryption		"sha1WithRSAEncryption"
#define NID_sha1WithRSAEncryption		22
#define OBJ_sha1WithRSAEncryption		OBJ_pkcs1,5L

#define SN_sha256WithRSAEncryption		"RSA-SHA256"
#define LN_sha256WithRSAEncryption		"sha256WithRSAEncryption"
#define NID_sha256WithRSAEncryption	18
#define OBJ_sha256WithRSAEncryption	OBJ_pkcs1,11L

#define SN_sha384WithRSAEncryption		"RSA-SHA384"
#define LN_sha384WithRSAEncryption		"sha384WithRSAEncryption"
#define NID_sha384WithRSAEncryption	19
#define OBJ_sha384WithRSAEncryption	OBJ_pkcs1,12L

#define SN_sha512WithRSAEncryption		"RSA-SHA512"
#define LN_sha512WithRSAEncryption		"sha512WithRSAEncryption"
#define NID_sha512WithRSAEncryption	20
#define OBJ_sha512WithRSAEncryption	OBJ_pkcs1,13L

#define SN_sha224WithRSAEncryption		"RSA-SHA224"
#define LN_sha224WithRSAEncryption		"sha224WithRSAEncryption"
#define NID_sha224WithRSAEncryption	21
#define OBJ_sha224WithRSAEncryption	OBJ_pkcs1,14L

#define SN_pkcs3		"pkcs3"
#define NID_pkcs3		27
#define OBJ_pkcs3		OBJ_pkcs,3L

#define LN_dhKeyAgreement		"dhKeyAgreement"
#define NID_dhKeyAgreement		28
#define OBJ_dhKeyAgreement		OBJ_pkcs3,1L

#define SN_pkcs5		"pkcs5"
#define NID_pkcs5		187
#define OBJ_pkcs5		OBJ_pkcs,5L

#define SN_pbeWithMD2AndDES_CBC		"PBE-MD2-DES"
#define LN_pbeWithMD2AndDES_CBC		"pbeWithMD2AndDES-CBC"
#define NID_pbeWithMD2AndDES_CBC		9
#define OBJ_pbeWithMD2AndDES_CBC		OBJ_pkcs5,1L

#define SN_pbeWithMD5AndDES_CBC		"PBE-MD5-DES"
#define LN_pbeWithMD5AndDES_CBC		"pbeWithMD5AndDES-CBC"
#define NID_pbeWithMD5AndDES_CBC		10
#define OBJ_pbeWithMD5AndDES_CBC		OBJ_pkcs5,3L

#define SN_pbeWithMD2AndRC2_CBC		"PBE-MD2-RC2-64"
#define LN_pbeWithMD2AndRC2_CBC		"pbeWithMD2AndRC2-CBC"
#define NID_pbeWithMD2AndRC2_CBC		168
#define OBJ_pbeWithMD2AndRC2_CBC		OBJ_pkcs5,4L

#define SN_pbeWithMD5AndRC2_CBC		"PBE-MD5-RC2-64"
#define LN_pbeWithMD5AndRC2_CBC		"pbeWithMD5AndRC2-CBC"
#define NID_pbeWithMD5AndRC2_CBC		169
#define OBJ_pbeWithMD5AndRC2_CBC		OBJ_pkcs5,6L

#define SN_pbeWithSHA1AndDES_CBC		"PBE-SHA1-DES"
#define LN_pbeWithSHA1AndDES_CBC		"pbeWithSHA1AndDES-CBC"
#define NID_pbeWithSHA1AndDES_CBC		170
#define OBJ_pbeWithSHA1AndDES_CBC		OBJ_pkcs5,10L

#define SN_pbeWithSHA1AndRC2_CBC		"PBE-SHA1-RC2-64"
#define LN_pbeWithSHA1AndRC2_CBC		"pbeWithSHA1AndRC2-CBC"
#define NID_pbeWithSHA1AndRC2_CBC		68
#define OBJ_pbeWithSHA1AndRC2_CBC		OBJ_pkcs5,11L

#define LN_id_pbkdf2		"PBKDF2"
#define NID_id_pbkdf2		69
#define OBJ_id_pbkdf2		OBJ_pkcs5,12L

#define LN_pbes2		"PBES2"
#define NID_pbes2		161
#define OBJ_pbes2		OBJ_pkcs5,13L

#define LN_pbmac1		"PBMAC1"
#define NID_pbmac1		162
#define OBJ_pbmac1		OBJ_pkcs5,14L

#define SN_pkcs7		"pkcs7"
#define NID_pkcs7		20
#define OBJ_pkcs7		OBJ_pkcs,7L

#define LN_pkcs7_data		"pkcs7-data"
#define NID_pkcs7_data		21
#define OBJ_pkcs7_data		OBJ_pkcs7,1L

#define LN_pkcs7_signed		"pkcs7-signedData"
#define NID_pkcs7_signed		22
#define OBJ_pkcs7_signed		OBJ_pkcs7,2L

#define LN_pkcs7_enveloped		"pkcs7-envelopedData"
#define NID_pkcs7_enveloped		23
#define OBJ_pkcs7_enveloped		OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped		"pkcs7-signedAndEnvelopedData"
#define NID_pkcs7_signedAndEnveloped		24
#define OBJ_pkcs7_signedAndEnveloped		OBJ_pkcs7,4L

#define LN_pkcs7_digest		"pkcs7-digestData"
#define NID_pkcs7_digest		25
#define OBJ_pkcs7_digest		OBJ_pkcs7,5L

#define LN_pkcs7_encrypted		"pkcs7-encryptedData"
#define NID_pkcs7_encrypted		26
#define OBJ_pkcs7_encrypted		OBJ_pkcs7,6L

#define SN_pkcs9		"pkcs9"
#define NID_pkcs9		47
#define OBJ_pkcs9		OBJ_pkcs,9L

#define LN_pkcs9_emailAddress		"emailAddress"
#define NID_pkcs9_emailAddress		48
#define OBJ_pkcs9_emailAddress		OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName		"unstructuredName"
#define NID_pkcs9_unstructuredName		49
#define OBJ_pkcs9_unstructuredName		OBJ_pkcs9,2L

#define LN_pkcs9_contentType		"contentType"
#define NID_pkcs9_contentType		50
#define OBJ_pkcs9_contentType		OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest		"messageDigest"
#define NID_pkcs9_messageDigest		51
#define OBJ_pkcs9_messageDigest		OBJ_pkcs9,4L

#define LN_pkcs9_signingTime		"signingTime"
#define NID_pkcs9_signingTime		52
#define OBJ_pkcs9_signingTime		OBJ_pkcs9,5L

#define LN_pkcs9_countersignature		"countersignature"
#define NID_pkcs9_countersignature		53
#define OBJ_pkcs9_countersignature		OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword		"challengePassword"
#define NID_pkcs9_challengePassword		54
#define OBJ_pkcs9_challengePassword		OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress		"unstructuredAddress"
#define NID_pkcs9_unstructuredAddress		55
#define OBJ_pkcs9_unstructuredAddress		OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes		"extendedCertificateAttributes"
#define NID_pkcs9_extCertAttributes		56
#define OBJ_pkcs9_extCertAttributes		OBJ_pkcs9,9L

#define SN_ext_req		"extReq"
#define LN_ext_req		"Extension Request"
#define NID_ext_req		172
#define OBJ_ext_req		OBJ_pkcs9,14L

#define SN_SMIMECapabilities		"SMIME-CAPS"
#define LN_SMIMECapabilities		"S/MIME Capabilities"
#define NID_SMIMECapabilities		167
#define OBJ_SMIMECapabilities		OBJ_pkcs9,15L

#define SN_SMIME		"SMIME"
#define LN_SMIME		"S/MIME"
#define NID_SMIME		188
#define OBJ_SMIME		OBJ_pkcs9,16L

#define SN_id_smime_mod		"id-smime-mod"
#define NID_id_smime_mod		189
#define OBJ_id_smime_mod		OBJ_SMIME,0L

#define SN_id_smime_ct		"id-smime-ct"
#define NID_id_smime_ct		190
#define OBJ_id_smime_ct		OBJ_SMIME,1L

#define SN_id_smime_aa		"id-smime-aa"
#define NID_id_smime_aa		191
#define OBJ_id_smime_aa		OBJ_SMIME,2L

#define SN_id_smime_alg		"id-smime-alg"
#define NID_id_smime_alg		192
#define OBJ_id_smime_alg		OBJ_SMIME,3L

#define SN_id_smime_cd		"id-smime-cd"
#define NID_id_smime_cd		193
#define OBJ_id_smime_cd		OBJ_SMIME,4L

#define SN_id_smime_spq		"id-smime-spq"
#define NID_id_smime_spq		194
#define OBJ_id_smime_spq		OBJ_SMIME,5L

#define SN_id_smime_cti		"id-smime-cti"
#define NID_id_smime_cti		195
#define OBJ_id_smime_cti		OBJ_SMIME,6L

#define SN_id_smime_mod_cms		"id-smime-mod-cms"
#define NID_id_smime_mod_cms		196
#define OBJ_id_smime_mod_cms		OBJ_id_smime_mod,1L

#define SN_id_smime_mod_ess		"id-smime-mod-ess"
#define NID_id_smime_mod_ess		197
#define OBJ_id_smime_mod_ess		OBJ_id_smime_mod,2L

#define SN_id_smime_mod_oid		"id-smime-mod-oid"
#define NID_id_smime_mod_oid		198
#define OBJ_id_smime_mod_oid		OBJ_id_smime_mod,3L

#define SN_id_smime_mod_msg_v3		"id-smime-mod-msg-v3"
#define NID_id_smime_mod_msg_v3		199
#define OBJ_id_smime_mod_msg_v3		OBJ_id_smime_mod,4L

#define SN_id_smime_mod_ets_eSignature_88		"id-smime-mod-ets-eSignature-88"
#define NID_id_smime_mod_ets_eSignature_88		200
#define OBJ_id_smime_mod_ets_eSignature_88		OBJ_id_smime_mod,5L

#define SN_id_smime_mod_ets_eSignature_97		"id-smime-mod-ets-eSignature-97"
#define NID_id_smime_mod_ets_eSignature_97		201
#define OBJ_id_smime_mod_ets_eSignature_97		OBJ_id_smime_mod,6L

#define SN_id_smime_mod_ets_eSigPolicy_88		"id-smime-mod-ets-eSigPolicy-88"
#define NID_id_smime_mod_ets_eSigPolicy_88		202
#define OBJ_id_smime_mod_ets_eSigPolicy_88		OBJ_id_smime_mod,7L

#define SN_id_smime_mod_ets_eSigPolicy_97		"id-smime-mod-ets-eSigPolicy-97"
#define NID_id_smime_mod_ets_eSigPolicy_97		203
#define OBJ_id_smime_mod_ets_eSigPolicy_97		OBJ_id_smime_mod,8L

#define SN_id_smime_ct_receipt		"id-smime-ct-receipt"
#define NID_id_smime_ct_receipt		204
#define OBJ_id_smime_ct_receipt		OBJ_id_smime_ct,1L

#define SN_id_smime_ct_authData		"id-smime-ct-authData"
#define NID_id_smime_ct_authData		205
#define OBJ_id_smime_ct_authData		OBJ_id_smime_ct,2L

#define SN_id_smime_ct_publishCert		"id-smime-ct-publishCert"
#define NID_id_smime_ct_publishCert		206
#define OBJ_id_smime_ct_publishCert		OBJ_id_smime_ct,3L

#define SN_id_smime_ct_TSTInfo		"id-smime-ct-TSTInfo"
#define NID_id_smime_ct_TSTInfo		207
#define OBJ_id_smime_ct_TSTInfo		OBJ_id_smime_ct,4L

#define SN_id_smime_ct_TDTInfo		"id-smime-ct-TDTInfo"
#define NID_id_smime_ct_TDTInfo		208
#define OBJ_id_smime_ct_TDTInfo		OBJ_id_smime_ct,5L

#define SN_id_smime_ct_contentInfo		"id-smime-ct-contentInfo"
#define NID_id_smime_ct_contentInfo		209
#define OBJ_id_smime_ct_contentInfo		OBJ_id_smime_ct,6L

#define SN_id_smime_ct_DVCSRequestData		"id-smime-ct-DVCSRequestData"
#define NID_id_smime_ct_DVCSRequestData		210
#define OBJ_id_smime_ct_DVCSRequestData		OBJ_id_smime_ct,7L

#define SN_id_smime_ct_DVCSResponseData		"id-smime-ct-DVCSResponseData"
#define NID_id_smime_ct_DVCSResponseData		211
#define OBJ_id_smime_ct_DVCSResponseData		OBJ_id_smime_ct,8L

#define SN_id_smime_ct_compressedData		"id-smime-ct-compressedData"
#define NID_id_smime_ct_compressedData		786
#define OBJ_id_smime_ct_compressedData		OBJ_id_smime_ct,9L

#define SN_id_ct_asciiTextWithCRLF		"id-ct-asciiTextWithCRLF"
#define NID_id_ct_asciiTextWithCRLF		787
#define OBJ_id_ct_asciiTextWithCRLF		OBJ_id_smime_ct,27L

#define SN_id_smime_aa_receiptRequest		"id-smime-aa-receiptRequest"
#define NID_id_smime_aa_receiptRequest		212
#define OBJ_id_smime_aa_receiptRequest		OBJ_id_smime_aa,1L

#define SN_id_smime_aa_securityLabel		"id-smime-aa-securityLabel"
#define NID_id_smime_aa_securityLabel		213
#define OBJ_id_smime_aa_securityLabel		OBJ_id_smime_aa,2L

#define SN_id_smime_aa_mlExpandHistory		"id-smime-aa-mlExpandHistory"
#define NID_id_smime_aa_mlExpandHistory		214
#define OBJ_id_smime_aa_mlExpandHistory		OBJ_id_smime_aa,3L

#define SN_id_smime_aa_contentHint		"id-smime-aa-contentHint"
#define NID_id_smime_aa_contentHint		215
#define OBJ_id_smime_aa_contentHint		OBJ_id_smime_aa,4L

#define SN_id_smime_aa_msgSigDigest		"id-smime-aa-msgSigDigest"
#define NID_id_smime_aa_msgSigDigest		216
#define OBJ_id_smime_aa_msgSigDigest		OBJ_id_smime_aa,5L

#define SN_id_smime_aa_encapContentType		"id-smime-aa-encapContentType"
#define NID_id_smime_aa_encapContentType		217
#define OBJ_id_smime_aa_encapContentType		OBJ_id_smime_aa,6L

#define SN_id_smime_aa_contentIdentifier		"id-smime-aa-contentIdentifier"
#define NID_id_smime_aa_contentIdentifier		218
#define OBJ_id_smime_aa_contentIdentifier		OBJ_id_smime_aa,7L

#define SN_id_smime_aa_macValue		"id-smime-aa-macValue"
#define NID_id_smime_aa_macValue		219
#define OBJ_id_smime_aa_macValue		OBJ_id_smime_aa,8L

#define SN_id_smime_aa_equivalentLabels		"id-smime-aa-equivalentLabels"
#define NID_id_smime_aa_equivalentLabels		220
#define OBJ_id_smime_aa_equivalentLabels		OBJ_id_smime_aa,9L

#define SN_id_smime_aa_contentReference		"id-smime-aa-contentReference"
#define NID_id_smime_aa_contentReference		221
#define OBJ_id_smime_aa_contentReference		OBJ_id_smime_aa,10L

#define SN_id_smime_aa_encrypKeyPref		"id-smime-aa-encrypKeyPref"
#define NID_id_smime_aa_encrypKeyPref		222
#define OBJ_id_smime_aa_encrypKeyPref		OBJ_id_smime_aa,11L

#define SN_id_smime_aa_signingCertificate		"id-smime-aa-signingCertificate"
#define NID_id_smime_aa_signingCertificate		223
#define OBJ_id_smime_aa_signingCertificate		OBJ_id_smime_aa,12L

#define SN_id_smime_aa_smimeEncryptCerts		"id-smime-aa-smimeEncryptCerts"
#define NID_id_smime_aa_smimeEncryptCerts		224
#define OBJ_id_smime_aa_smimeEncryptCerts		OBJ_id_smime_aa,13L

#define SN_id_smime_aa_timeStampToken		"id-smime-aa-timeStampToken"
#define NID_id_smime_aa_timeStampToken		225
#define OBJ_id_smime_aa_timeStampToken		OBJ_id_smime_aa,14L

#define SN_id_smime_aa_ets_sigPolicyId		"id-smime-aa-ets-sigPolicyId"
#define NID_id_smime_aa_ets_sigPolicyId		226
#define OBJ_id_smime_aa_ets_sigPolicyId		OBJ_id_smime_aa,15L

#define SN_id_smime_aa_ets_commitmentType		"id-smime-aa-ets-commitmentType"
#define NID_id_smime_aa_ets_commitmentType		227
#define OBJ_id_smime_aa_ets_commitmentType		OBJ_id_smime_aa,16L

#define SN_id_smime_aa_ets_signerLocation		"id-smime-aa-ets-signerLocation"
#define NID_id_smime_aa_ets_signerLocation		228
#define OBJ_id_smime_aa_ets_signerLocation		OBJ_id_smime_aa,17L

#define SN_id_smime_aa_ets_signerAttr		"id-smime-aa-ets-signerAttr"
#define NID_id_smime_aa_ets_signerAttr		229
#define OBJ_id_smime_aa_ets_signerAttr		OBJ_id_smime_aa,18L

#define SN_id_smime_aa_ets_otherSigCert		"id-smime-aa-ets-otherSigCert"
#define NID_id_smime_aa_ets_otherSigCert		230
#define OBJ_id_smime_aa_ets_otherSigCert		OBJ_id_smime_aa,19L

#define SN_id_smime_aa_ets_contentTimestamp		"id-smime-aa-ets-contentTimestamp"
#define NID_id_smime_aa_ets_contentTimestamp		231
#define OBJ_id_smime_aa_ets_contentTimestamp		OBJ_id_smime_aa,20L

#define SN_id_smime_aa_ets_CertificateRefs		"id-smime-aa-ets-CertificateRefs"
#define NID_id_smime_aa_ets_CertificateRefs		232
#define OBJ_id_smime_aa_ets_CertificateRefs		OBJ_id_smime_aa,21L

#define SN_id_smime_aa_ets_RevocationRefs		"id-smime-aa-ets-RevocationRefs"
#define NID_id_smime_aa_ets_RevocationRefs		233
#define OBJ_id_smime_aa_ets_RevocationRefs		OBJ_id_smime_aa,22L

#define SN_id_smime_aa_ets_certValues		"id-smime-aa-ets-certValues"
#define NID_id_smime_aa_ets_certValues		234
#define OBJ_id_smime_aa_ets_certValues		OBJ_id_smime_aa,23L

#define SN_id_smime_aa_ets_revocationValues		"id-smime-aa-ets-revocationValues"
#define NID_id_smime_aa_ets_revocationValues		235
#define OBJ_id_smime_aa_ets_revocationValues		OBJ_id_smime_aa,24L

#define SN_id_smime_aa_ets_escTimeStamp		"id-smime-aa-ets-escTimeStamp"
#define NID_id_smime_aa_ets_escTimeStamp		236
#define OBJ_id_smime_aa_ets_escTimeStamp		OBJ_id_smime_aa,25L

#define SN_id_smime_aa_ets_certCRLTimestamp		"id-smime-aa-ets-certCRLTimestamp"
#define NID_id_smime_aa_ets_certCRLTimestamp		237
#define OBJ_id_smime_aa_ets_certCRLTimestamp		OBJ_id_smime_aa,26L

#define SN_id_smime_aa_ets_archiveTimeStamp		"id-smime-aa-ets-archiveTimeStamp"
#define NID_id_smime_aa_ets_archiveTimeStamp		238
#define OBJ_id_smime_aa_ets_archiveTimeStamp		OBJ_id_smime_aa,27L

#define SN_id_smime_aa_signatureType		"id-smime-aa-signatureType"
#define NID_id_smime_aa_signatureType		239
#define OBJ_id_smime_aa_signatureType		OBJ_id_smime_aa,28L

#define SN_id_smime_aa_dvcs_dvc		"id-smime-aa-dvcs-dvc"
#define NID_id_smime_aa_dvcs_dvc		240
#define OBJ_id_smime_aa_dvcs_dvc		OBJ_id_smime_aa,29L

#define SN_id_smime_alg_ESDHwith3DES		"id-smime-alg-ESDHwith3DES"
#define NID_id_smime_alg_ESDHwith3DES		241
#define OBJ_id_smime_alg_ESDHwith3DES		OBJ_id_smime_alg,1L

#define SN_id_smime_alg_ESDHwithRC2		"id-smime-alg-ESDHwithRC2"
#define NID_id_smime_alg_ESDHwithRC2		242
#define OBJ_id_smime_alg_ESDHwithRC2		OBJ_id_smime_alg,2L

#define SN_id_smime_alg_3DESwrap		"id-smime-alg-3DESwrap"
#define NID_id_smime_alg_3DESwrap		243
#define OBJ_id_smime_alg_3DESwrap		OBJ_id_smime_alg,3L

#define SN_id_smime_alg_RC2wrap		"id-smime-alg-RC2wrap"
#define NID_id_smime_alg_RC2wrap		244
#define OBJ_id_smime_alg_RC2wrap		OBJ_id_smime_alg,4L

#define SN_id_smime_alg_ESDH		"id-smime-alg-ESDH"
#define NID_id_smime_alg_ESDH		245
#define OBJ_id_smime_alg_ESDH		OBJ_id_smime_alg,5L

#define SN_id_smime_alg_CMS3DESwrap		"id-smime-alg-CMS3DESwrap"
#define NID_id_smime_alg_CMS3DESwrap		246
#define OBJ_id_smime_alg_CMS3DESwrap		OBJ_id_smime_alg,6L

#define SN_id_smime_alg_CMSRC2wrap		"id-smime-alg-CMSRC2wrap"
#define NID_id_smime_alg_CMSRC2wrap		247
#define OBJ_id_smime_alg_CMSRC2wrap		OBJ_id_smime_alg,7L

#define SN_id_smime_cd_ldap		"id-smime-cd-ldap"
#define NID_id_smime_cd_ldap		248
#define OBJ_id_smime_cd_ldap		OBJ_id_smime_cd,1L

#define SN_id_smime_spq_ets_sqt_uri		"id-smime-spq-ets-sqt-uri"
#define NID_id_smime_spq_ets_sqt_uri		249
#define OBJ_id_smime_spq_ets_sqt_uri		OBJ_id_smime_spq,1L

#define SN_id_smime_spq_ets_sqt_unotice		"id-smime-spq-ets-sqt-unotice"
#define NID_id_smime_spq_ets_sqt_unotice		250
#define OBJ_id_smime_spq_ets_sqt_unotice		OBJ_id_smime_spq,2L

#define SN_id_smime_cti_ets_proofOfOrigin		"id-smime-cti-ets-proofOfOrigin"
#define NID_id_smime_cti_ets_proofOfOrigin		251
#define OBJ_id_smime_cti_ets_proofOfOrigin		OBJ_id_smime_cti,1L

#define SN_id_smime_cti_ets_proofOfReceipt		"id-smime-cti-ets-proofOfReceipt"
#define NID_id_smime_cti_ets_proofOfReceipt		252
#define OBJ_id_smime_cti_ets_proofOfReceipt		OBJ_id_smime_cti,2L

#define SN_id_smime_cti_ets_proofOfDelivery		"id-smime-cti-ets-proofOfDelivery"
#define NID_id_smime_cti_ets_proofOfDelivery		253
#define OBJ_id_smime_cti_ets_proofOfDelivery		OBJ_id_smime_cti,3L

#define SN_id_smime_cti_ets_proofOfSender		"id-smime-cti-ets-proofOfSender"
#define NID_id_smime_cti_ets_proofOfSender		254
#define OBJ_id_smime_cti_ets_proofOfSender		OBJ_id_smime_cti,4L

#define SN_id_smime_cti_ets_proofOfApproval		"id-smime-cti-ets-proofOfApproval"
#define NID_id_smime_cti_ets_proofOfApproval		255
#define OBJ_id_smime_cti_ets_proofOfApproval		OBJ_id_smime_cti,5L

#define SN_id_smime_cti_ets_proofOfCreation		"id-smime-cti-ets-proofOfCreation"
#define NID_id_smime_cti_ets_proofOfCreation		256
#define OBJ_id_smime_cti_ets_proofOfCreation		OBJ_id_smime_cti,6L

#define LN_friendlyName		"friendlyName"
#define NID_friendlyName		156
#define OBJ_friendlyName		OBJ_pkcs9,20L

#define LN_localKeyID		"localKeyID"
#define NID_localKeyID		157
#define OBJ_localKeyID		OBJ_pkcs9,21L

#define SN_ms_csp_name		"CSPName"
#define LN_ms_csp_name		"Microsoft CSP Name"
#define NID_ms_csp_name		417
#define OBJ_ms_csp_name		1L,3L,6L,1L,4L,1L,311L,17L,1L

#define SN_LocalKeySet		"LocalKeySet"
#define LN_LocalKeySet		"Microsoft Local Key set"
#define NID_LocalKeySet		856
#define OBJ_LocalKeySet		1L,3L,6L,1L,4L,1L,311L,17L,2L

#define OBJ_certTypes		OBJ_pkcs9,22L

#define LN_x509Certificate		"x509Certificate"
#define NID_x509Certificate		158
#define OBJ_x509Certificate		OBJ_certTypes,1L

#define LN_sdsiCertificate		"sdsiCertificate"
#define NID_sdsiCertificate		159
#define OBJ_sdsiCertificate		OBJ_certTypes,2L

#define OBJ_crlTypes		OBJ_pkcs9,23L

#define LN_x509Crl		"x509Crl"
#define NID_x509Crl		160
#define OBJ_x509Crl		OBJ_crlTypes,1L

#define OBJ_pkcs12		OBJ_pkcs,12L

#define OBJ_pkcs12_pbeids		OBJ_pkcs12,1L

#define SN_pbe_WithSHA1And128BitRC4		"PBE-SHA1-RC4-128"
#define LN_pbe_WithSHA1And128BitRC4		"pbeWithSHA1And128BitRC4"
#define NID_pbe_WithSHA1And128BitRC4		144
#define OBJ_pbe_WithSHA1And128BitRC4		OBJ_pkcs12_pbeids,1L

#define SN_pbe_WithSHA1And40BitRC4		"PBE-SHA1-RC4-40"
#define LN_pbe_WithSHA1And40BitRC4		"pbeWithSHA1And40BitRC4"
#define NID_pbe_WithSHA1And40BitRC4		145
#define OBJ_pbe_WithSHA1And40BitRC4		OBJ_pkcs12_pbeids,2L

#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC		"PBE-SHA1-3DES"
#define LN_pbe_WithSHA1And3_Key_TripleDES_CBC		"pbeWithSHA1And3-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC		146
#define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC		OBJ_pkcs12_pbeids,3L

#define SN_pbe_WithSHA1And2_Key_TripleDES_CBC		"PBE-SHA1-2DES"
#define LN_pbe_WithSHA1And2_Key_TripleDES_CBC		"pbeWithSHA1And2-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC		147
#define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC		OBJ_pkcs12_pbeids,4L

#define SN_pbe_WithSHA1And128BitRC2_CBC		"PBE-SHA1-RC2-128"
#define LN_pbe_WithSHA1And128BitRC2_CBC		"pbeWithSHA1And128BitRC2-CBC"
#define NID_pbe_WithSHA1And128BitRC2_CBC		148
#define OBJ_pbe_WithSHA1And128BitRC2_CBC		OBJ_pkcs12_pbeids,5L

#define SN_pbe_WithSHA1And40BitRC2_CBC		"PBE-SHA1-RC2-40"
#define LN_pbe_WithSHA1And40BitRC2_CBC		"pbeWithSHA1And40BitRC2-CBC"
#define NID_pbe_WithSHA1And40BitRC2_CBC		149
#define OBJ_pbe_WithSHA1And40BitRC2_CBC		OBJ_pkcs12_pbeids,6L

#define OBJ_pkcs12_Version1		OBJ_pkcs12,10L

#define OBJ_pkcs12_BagIds		OBJ_pkcs12_Version1,1L

#define LN_keyBag		"keyBag"
#define NID_keyBag		150
#define OBJ_keyBag		OBJ_pkcs12_BagIds,1L

#define LN_pkcs8ShroudedKeyBag		"pkcs8ShroudedKeyBag"
#define NID_pkcs8ShroudedKeyBag		151
#define OBJ_pkcs8ShroudedKeyBag		OBJ_pkcs12_BagIds,2L

#define LN_certBag		"certBag"
#define NID_certBag		152
#define OBJ_certBag		OBJ_pkcs12_BagIds,3L

#define LN_crlBag		"crlBag"
#define NID_crlBag		153
#define OBJ_crlBag		OBJ_pkcs12_BagIds,4L

#define LN_secretBag		"secretBag"
#define NID_secretBag		154
#define OBJ_secretBag		OBJ_pkcs12_BagIds,5L

#define LN_safeContentsBag		"safeContentsBag"
#define NID_safeContentsBag		155
#define OBJ_safeContentsBag		OBJ_pkcs12_BagIds,6L

#define SN_md2		"MD2"
#define LN_md2		"md2"
#define NID_md2		3
#define OBJ_md2		OBJ_rsadsi,2L,2L

#define SN_md4		"MD4"
#define LN_md4		"md4"
#define NID_md4		257
#define OBJ_md4		OBJ_rsadsi,2L,4L

#define SN_md5		"MD5"
#define LN_md5		"md5"
#define NID_md5		4
#define OBJ_md5		OBJ_rsadsi,2L,5L

#define SN_md5_sha1		"MD5-SHA1"
#define LN_md5_sha1		"md5-sha1"
#define NID_md5_sha1		114

#define LN_hmacWithMD5		"hmacWithMD5"
#define NID_hmacWithMD5		797
#define OBJ_hmacWithMD5		OBJ_rsadsi,2L,6L

#define LN_hmacWithSHA1		"hmacWithSHA1"
#define NID_hmacWithSHA1		163
#define OBJ_hmacWithSHA1		OBJ_rsadsi,2L,7L

#define LN_hmacWithSHA224		"hmacWithSHA224"
#define NID_hmacWithSHA224		798
#define OBJ_hmacWithSHA224		OBJ_rsadsi,2L,8L

#define LN_hmacWithSHA256		"hmacWithSHA256"
#define NID_hmacWithSHA256		799
#define OBJ_hmacWithSHA256		OBJ_rsadsi,2L,9L

#define LN_hmacWithSHA384		"hmacWithSHA384"
#define NID_hmacWithSHA384		800
#define OBJ_hmacWithSHA384		OBJ_rsadsi,2L,10L

#define LN_hmacWithSHA512		"hmacWithSHA512"
#define NID_hmacWithSHA512		801
#define OBJ_hmacWithSHA512		OBJ_rsadsi,2L,11L

#define SN_rc2_cbc		"RC2-CBC"
#define LN_rc2_cbc		"rc2-cbc"
#define NID_rc2_cbc		37
#define OBJ_rc2_cbc		OBJ_rsadsi,3L,2L

#define SN_rc2_ecb		"RC2-ECB"
#define LN_rc2_ecb		"rc2-ecb"
#define NID_rc2_ecb		38

#define SN_rc2_cfb64		"RC2-CFB"
#define LN_rc2_cfb64		"rc2-cfb"
#define NID_rc2_cfb64		39

#define SN_rc2_ofb64		"RC2-OFB"
#define LN_rc2_ofb64		"rc2-ofb"
#define NID_rc2_ofb64		40

#define SN_rc2_40_cbc		"RC2-40-CBC"
#define LN_rc2_40_cbc		"rc2-40-cbc"
#define NID_rc2_40_cbc		98

#define SN_rc2_64_cbc		"RC2-64-CBC"
#define LN_rc2_64_cbc		"rc2-64-cbc"
#define NID_rc2_64_cbc		166

#define SN_rc4		"RC4"
#define LN_rc4		"rc4"
#define NID_rc4		5
#define OBJ_rc4		OBJ_rsadsi,3L,4L

#define SN_rc4_40		"RC4-40"
#define LN_rc4_40		"rc4-40"
#define NID_rc4_40		97

#define SN_des_ede3_cbc		"DES-EDE3-CBC"
#define LN_des_ede3_cbc		"des-ede3-cbc"
#define NID_des_ede3_cbc		44
#define OBJ_des_ede3_cbc		OBJ_rsadsi,3L,7L

#define SN_rc5_cbc		"RC5-CBC"
#define LN_rc5_cbc		"rc5-cbc"
#define NID_rc5_cbc		120
#define OBJ_rc5_cbc		OBJ_rsadsi,3L,8L

#define SN_rc5_ecb		"RC5-ECB"
#define LN_rc5_ecb		"rc5-ecb"
#define NID_rc5_ecb		121

#define SN_rc5_cfb64		"RC5-CFB"
#define LN_rc5_cfb64		"rc5-cfb"
#define NID_rc5_cfb64		122

#define SN_rc5_ofb64		"RC5-OFB"
#define LN_rc5_ofb64		"rc5-ofb"
#define NID_rc5_ofb64		123

#define SN_ms_ext_req		"msExtReq"
#define LN_ms_ext_req		"Microsoft Extension Request"
#define NID_ms_ext_req		171
#define OBJ_ms_ext_req		1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

#define SN_ms_code_ind		"msCodeInd"
#define LN_ms_code_ind		"Microsoft Individual Code Signing"
#define NID_ms_code_ind		134
#define OBJ_ms_code_ind		1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

#define SN_ms_code_com		"msCodeCom"
#define LN_ms_code_com		"Microsoft Commercial Code Signing"
#define NID_ms_code_com		135
#define OBJ_ms_code_com		1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

#define SN_ms_ctl_sign		"msCTLSign"
#define LN_ms_ctl_sign		"Microsoft Trust List Signing"
#define NID_ms_ctl_sign		136
#define OBJ_ms_ctl_sign		1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

#define SN_ms_sgc		"msSGC"
#define LN_ms_sgc		"Microsoft Server Gated Crypto"
#define NID_ms_sgc		137
#define OBJ_ms_sgc		1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

#define SN_ms_efs		"msEFS"
#define LN_ms_efs		"Microsoft Encrypted File System"
#define NID_ms_efs		138
#define OBJ_ms_efs		1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

#define SN_ms_smartcard_login		"msSmartcardLogin"
#define LN_ms_smartcard_login		"Microsoft Smartcardlogin"
#define NID_ms_smartcard_login		648
#define OBJ_ms_smartcard_login		1L,3L,6L,1L,4L,1L,311L,20L,2L,2L

#define SN_ms_upn		"msUPN"
#define LN_ms_upn		"Microsoft Universal Principal Name"
#define NID_ms_upn		649
#define OBJ_ms_upn		1L,3L,6L,1L,4L,1L,311L,20L,2L,3L

#define SN_idea_cbc		"IDEA-CBC"
#define LN_idea_cbc		"idea-cbc"
#define NID_idea_cbc		34
#define OBJ_idea_cbc		1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#define SN_idea_ecb		"IDEA-ECB"
#define LN_idea_ecb		"idea-ecb"
#define NID_idea_ecb		36

#define SN_idea_cfb64		"IDEA-CFB"
#define LN_idea_cfb64		"idea-cfb"
#define NID_idea_cfb64		35

#define SN_idea_ofb64		"IDEA-OFB"
#define LN_idea_ofb64		"idea-ofb"
#define NID_idea_ofb64		46

#define SN_bf_cbc		"BF-CBC"
#define LN_bf_cbc		"bf-cbc"
#define NID_bf_cbc		91
#define OBJ_bf_cbc		1L,3L,6L,1L,4L,1L,3029L,1L,2L

#define SN_bf_ecb		"BF-ECB"
#define LN_bf_ecb		"bf-ecb"
#define NID_bf_ecb		92

#define SN_bf_cfb64		"BF-CFB"
#define LN_bf_cfb64		"bf-cfb"
#define NID_bf_cfb64		93

#define SN_bf_ofb64		"BF-OFB"
#define LN_bf_ofb64		"bf-ofb"
#define NID_bf_ofb64		94

#define SN_id_pkix		"PKIX"
#define NID_id_pkix		127
#define OBJ_id_pkix		1L,3L,6L,1L,5L,5L,7L

#define SN_id_pkix_mod		"id-pkix-mod"
#define NID_id_pkix_mod		258
#define OBJ_id_pkix_mod		OBJ_id_pkix,0L

#define SN_id_pe		"id-pe"
#define NID_id_pe		175
#define OBJ_id_pe		OBJ_id_pkix,1L

#define SN_id_qt		"id-qt"
#define NID_id_qt		259
#define OBJ_id_qt		OBJ_id_pkix,2L

#define SN_id_kp		"id-kp"
#define NID_id_kp		128
#define OBJ_id_kp		OBJ_id_pkix,3L

#define SN_id_it		"id-it"
#define NID_id_it		260
#define OBJ_id_it		OBJ_id_pkix,4L

#define SN_id_pkip		"id-pkip"
#define NID_id_pkip		261
#define OBJ_id_pkip		OBJ_id_pkix,5L

#define SN_id_alg		"id-alg"
#define NID_id_alg		262
#define OBJ_id_alg		OBJ_id_pkix,6L

#define SN_id_cmc		"id-cmc"
#define NID_id_cmc		263
#define OBJ_id_cmc		OBJ_id_pkix,7L

#define SN_id_on		"id-on"
#define NID_id_on		264
#define OBJ_id_on		OBJ_id_pkix,8L

#define SN_id_pda		"id-pda"
#define NID_id_pda		265
#define OBJ_id_pda		OBJ_id_pkix,9L

#define SN_id_aca		"id-aca"
#define NID_id_aca		266
#define OBJ_id_aca		OBJ_id_pkix,10L

#define SN_id_qcs		"id-qcs"
#define NID_id_qcs		267
#define OBJ_id_qcs		OBJ_id_pkix,11L

#define SN_id_cct		"id-cct"
#define NID_id_cct		268
#define OBJ_id_cct		OBJ_id_pkix,12L

#define SN_id_ppl		"id-ppl"
#define NID_id_ppl		662
#define OBJ_id_ppl		OBJ_id_pkix,21L

#define SN_id_ad		"id-ad"
#define NID_id_ad		176
#define OBJ_id_ad		OBJ_id_pkix,48L

#define SN_id_pkix1_explicit_88		"id-pkix1-explicit-88"
#define NID_id_pkix1_explicit_88		269
#define OBJ_id_pkix1_explicit_88		OBJ_id_pkix_mod,1L

#define SN_id_pkix1_implicit_88		"id-pkix1-implicit-88"
#define NID_id_pkix1_implicit_88		270
#define OBJ_id_pkix1_implicit_88		OBJ_id_pkix_mod,2L

#define SN_id_pkix1_explicit_93		"id-pkix1-explicit-93"
#define NID_id_pkix1_explicit_93		271
#define OBJ_id_pkix1_explicit_93		OBJ_id_pkix_mod,3L

#define SN_id_pkix1_implicit_93		"id-pkix1-implicit-93"
#define NID_id_pkix1_implicit_93		272
#define OBJ_id_pkix1_implicit_93		OBJ_id_pkix_mod,4L

#define SN_id_mod_crmf		"id-mod-crmf"
#define NID_id_mod_crmf		273
#define OBJ_id_mod_crmf		OBJ_id_pkix_mod,5L

#define SN_id_mod_cmc		"id-mod-cmc"
#define NID_id_mod_cmc		274
#define OBJ_id_mod_cmc		OBJ_id_pkix_mod,6L

#define SN_id_mod_kea_profile_88		"id-mod-kea-profile-88"
#define NID_id_mod_kea_profile_88		275
#define OBJ_id_mod_kea_profile_88		OBJ_id_pkix_mod,7L

#define SN_id_mod_kea_profile_93		"id-mod-kea-profile-93"
#define NID_id_mod_kea_profile_93		276
#define OBJ_id_mod_kea_profile_93		OBJ_id_pkix_mod,8L

#define SN_id_mod_cmp		"id-mod-cmp"
#define NID_id_mod_cmp		277
#define OBJ_id_mod_cmp		OBJ_id_pkix_mod,9L

#define SN_id_mod_qualified_cert_88		"id-mod-qualified-cert-88"
#define NID_id_mod_qualified_cert_88		278
#define OBJ_id_mod_qualified_cert_88		OBJ_id_pkix_mod,10L

#define SN_id_mod_qualified_cert_93		"id-mod-qualified-cert-93"
#define NID_id_mod_qualified_cert_93		279
#define OBJ_id_mod_qualified_cert_93		OBJ_id_pkix_mod,11L

#define SN_id_mod_attribute_cert		"id-mod-attribute-cert"
#define NID_id_mod_attribute_cert		280
#define OBJ_id_mod_attribute_cert		OBJ_id_pkix_mod,12L

#define SN_id_mod_timestamp_protocol		"id-mod-timestamp-protocol"
#define NID_id_mod_timestamp_protocol		281
#define OBJ_id_mod_timestamp_protocol		OBJ_id_pkix_mod,13L

#define SN_id_mod_ocsp		"id-mod-ocsp"
#define NID_id_mod_ocsp		282
#define OBJ_id_mod_ocsp		OBJ_id_pkix_mod,14L

#define SN_id_mod_dvcs		"id-mod-dvcs"
#define NID_id_mod_dvcs		283
#define OBJ_id_mod_dvcs		OBJ_id_pkix_mod,15L

#define SN_id_mod_cmp2000		"id-mod-cmp2000"
#define NID_id_mod_cmp2000		284
#define OBJ_id_mod_cmp2000		OBJ_id_pkix_mod,16L

#define SN_info_access		"authorityInfoAccess"
#define LN_info_access		"Authority Information Access"
#define NID_info_access		177
#define OBJ_info_access		OBJ_id_pe,1L

#define SN_biometricInfo		"biometricInfo"
#define LN_biometricInfo		"Biometric Info"
#define NID_biometricInfo		285
#define OBJ_biometricInfo		OBJ_id_pe,2L

#define SN_qcStatements		"qcStatements"
#define NID_qcStatements		286
#define OBJ_qcStatements		OBJ_id_pe,3L

#define SN_ac_auditEntity		"ac-auditEntity"
#define NID_ac_auditEntity		287
#define OBJ_ac_auditEntity		OBJ_id_pe,4L

#define SN_ac_targeting		"ac-targeting"
#define NID_ac_targeting		288
#define OBJ_ac_targeting		OBJ_id_pe,5L

#define SN_aaControls		"aaControls"
#define NID_aaControls		289
#define OBJ_aaControls		OBJ_id_pe,6L

#define SN_sbgp_ipAddrBlock		"sbgp-ipAddrBlock"
#define NID_sbgp_ipAddrBlock		290
#define OBJ_sbgp_ipAddrBlock		OBJ_id_pe,7L

#define SN_sbgp_autonomousSysNum		"sbgp-autonomousSysNum"
#define NID_sbgp_autonomousSysNum		291
#define OBJ_sbgp_autonomousSysNum		OBJ_id_pe,8L

#define SN_sbgp_routerIdentifier		"sbgp-routerIdentifier"
#define NID_sbgp_routerIdentifier		292
#define OBJ_sbgp_routerIdentifier		OBJ_id_pe,9L

#define SN_ac_proxying		"ac-proxying"
#define NID_ac_proxying		397
#define OBJ_ac_proxying		OBJ_id_pe,10L

#define SN_sinfo_access		"subjectInfoAccess"
#define LN_sinfo_access		"Subject Information Access"
#define NID_sinfo_access		398
#define OBJ_sinfo_access		OBJ_id_pe,11L

#define SN_proxyCertInfo		"proxyCertInfo"
#define LN_proxyCertInfo		"Proxy Certificate Information"
#define NID_proxyCertInfo		663
#define OBJ_proxyCertInfo		OBJ_id_pe,14L

#define SN_id_qt_cps		"id-qt-cps"
#define LN_id_qt_cps		"Policy Qualifier CPS"
#define NID_id_qt_cps		164
#define OBJ_id_qt_cps		OBJ_id_qt,1L

#define SN_id_qt_unotice		"id-qt-unotice"
#define LN_id_qt_unotice		"Policy Qualifier User Notice"
#define NID_id_qt_unotice		165
#define OBJ_id_qt_unotice		OBJ_id_qt,2L

#define SN_textNotice		"textNotice"
#define NID_textNotice		293
#define OBJ_textNotice		OBJ_id_qt,3L

#define SN_server_auth		"serverAuth"
#define LN_server_auth		"TLS Web Server Authentication"
#define NID_server_auth		129
#define OBJ_server_auth		OBJ_id_kp,1L

#define SN_client_auth		"clientAuth"
#define LN_client_auth		"TLS Web Client Authentication"
#define NID_client_auth		130
#define OBJ_client_auth		OBJ_id_kp,2L

#define SN_code_sign		"codeSigning"
#define LN_code_sign		"Code Signing"
#define NID_code_sign		131
#define OBJ_code_sign		OBJ_id_kp,3L

#define SN_email_protect		"emailProtection"
#define LN_email_protect		"E-mail Protection"
#define NID_email_protect		132
#define OBJ_email_protect		OBJ_id_kp,4L

#define SN_ipsecEndSystem		"ipsecEndSystem"
#define LN_ipsecEndSystem		"IPSec End System"
#define NID_ipsecEndSystem		294
#define OBJ_ipsecEndSystem		OBJ_id_kp,5L

#define SN_ipsecTunnel		"ipsecTunnel"
#define LN_ipsecTunnel		"IPSec Tunnel"
#define NID_ipsecTunnel		295
#define OBJ_ipsecTunnel		OBJ_id_kp,6L

#define SN_ipsecUser		"ipsecUser"
#define LN_ipsecUser		"IPSec User"
#define NID_ipsecUser		296
#define OBJ_ipsecUser		OBJ_id_kp,7L

#define SN_time_stamp		"timeStamping"
#define LN_time_stamp		"Time Stamping"
#define NID_time_stamp		133
#define OBJ_time_stamp		OBJ_id_kp,8L

#define SN_OCSP_sign		"OCSPSigning"
#define LN_OCSP_sign		"OCSP Signing"
#define NID_OCSP_sign		180
#define OBJ_OCSP_sign		OBJ_id_kp,9L

#define SN_dvcs		"DVCS"
#define LN_dvcs		"dvcs"
#define NID_dvcs		297
#define OBJ_dvcs		OBJ_id_kp,10L

#define SN_id_it_caProtEncCert		"id-it-caProtEncCert"
#define NID_id_it_caProtEncCert		298
#define OBJ_id_it_caProtEncCert		OBJ_id_it,1L

#define SN_id_it_signKeyPairTypes		"id-it-signKeyPairTypes"
#define NID_id_it_signKeyPairTypes		299
#define OBJ_id_it_signKeyPairTypes		OBJ_id_it,2L

#define SN_id_it_encKeyPairTypes		"id-it-encKeyPairTypes"
#define NID_id_it_encKeyPairTypes		300
#define OBJ_id_it_encKeyPairTypes		OBJ_id_it,3L

#define SN_id_it_preferredSymmAlg		"id-it-preferredSymmAlg"
#define NID_id_it_preferredSymmAlg		301
#define OBJ_id_it_preferredSymmAlg		OBJ_id_it,4L

#define SN_id_it_caKeyUpdateInfo		"id-it-caKeyUpdateInfo"
#define NID_id_it_caKeyUpdateInfo		302
#define OBJ_id_it_caKeyUpdateInfo		OBJ_id_it,5L

#define SN_id_it_currentCRL		"id-it-currentCRL"
#define NID_id_it_currentCRL		303
#define OBJ_id_it_currentCRL		OBJ_id_it,6L

#define SN_id_it_unsupportedOIDs		"id-it-unsupportedOIDs"
#define NID_id_it_unsupportedOIDs		304
#define OBJ_id_it_unsupportedOIDs		OBJ_id_it,7L

#define SN_id_it_subscriptionRequest		"id-it-subscriptionRequest"
#define NID_id_it_subscriptionRequest		305
#define OBJ_id_it_subscriptionRequest		OBJ_id_it,8L

#define SN_id_it_subscriptionResponse		"id-it-subscriptionResponse"
#define NID_id_it_subscriptionResponse		306
#define OBJ_id_it_subscriptionResponse		OBJ_id_it,9L

#define SN_id_it_keyPairParamReq		"id-it-keyPairParamReq"
#define NID_id_it_keyPairParamReq		307
#define OBJ_id_it_keyPairParamReq		OBJ_id_it,10L

#define SN_id_it_keyPairParamRep		"id-it-keyPairParamRep"
#define NID_id_it_keyPairParamRep		308
#define OBJ_id_it_keyPairParamRep		OBJ_id_it,11L

#define SN_id_it_revPassphrase		"id-it-revPassphrase"
#define NID_id_it_revPassphrase		309
#define OBJ_id_it_revPassphrase		OBJ_id_it,12L

#define SN_id_it_implicitConfirm		"id-it-implicitConfirm"
#define NID_id_it_implicitConfirm		310
#define OBJ_id_it_implicitConfirm		OBJ_id_it,13L

#define SN_id_it_confirmWaitTime		"id-it-confirmWaitTime"
#define NID_id_it_confirmWaitTime		311
#define OBJ_id_it_confirmWaitTime		OBJ_id_it,14L

#define SN_id_it_origPKIMessage		"id-it-origPKIMessage"
#define NID_id_it_origPKIMessage		312
#define OBJ_id_it_origPKIMessage		OBJ_id_it,15L

#define SN_id_it_suppLangTags		"id-it-suppLangTags"
#define NID_id_it_suppLangTags		784
#define OBJ_id_it_suppLangTags		OBJ_id_it,16L

#define SN_id_regCtrl		"id-regCtrl"
#define NID_id_regCtrl		313
#define OBJ_id_regCtrl		OBJ_id_pkip,1L

#define SN_id_regInfo		"id-regInfo"
#define NID_id_regInfo		314
#define OBJ_id_regInfo		OBJ_id_pkip,2L

#define SN_id_regCtrl_regToken		"id-regCtrl-regToken"
#define NID_id_regCtrl_regToken		315
#define OBJ_id_regCtrl_regToken		OBJ_id_regCtrl,1L

#define SN_id_regCtrl_authenticator		"id-regCtrl-authenticator"
#define NID_id_regCtrl_authenticator		316
#define OBJ_id_regCtrl_authenticator		OBJ_id_regCtrl,2L

#define SN_id_regCtrl_pkiPublicationInfo		"id-regCtrl-pkiPublicationInfo"
#define NID_id_regCtrl_pkiPublicationInfo		317
#define OBJ_id_regCtrl_pkiPublicationInfo		OBJ_id_regCtrl,3L

#define SN_id_regCtrl_pkiArchiveOptions		"id-regCtrl-pkiArchiveOptions"
#define NID_id_regCtrl_pkiArchiveOptions		318
#define OBJ_id_regCtrl_pkiArchiveOptions		OBJ_id_regCtrl,4L

#define SN_id_regCtrl_oldCertID		"id-regCtrl-oldCertID"
#define NID_id_regCtrl_oldCertID		319
#define OBJ_id_regCtrl_oldCertID		OBJ_id_regCtrl,5L

#define SN_id_regCtrl_protocolEncrKey		"id-regCtrl-protocolEncrKey"
#define NID_id_regCtrl_protocolEncrKey		320
#define OBJ_id_regCtrl_protocolEncrKey		OBJ_id_regCtrl,6L

#define SN_id_regInfo_utf8Pairs		"id-regInfo-utf8Pairs"
#define NID_id_regInfo_utf8Pairs		321
#define OBJ_id_regInfo_utf8Pairs		OBJ_id_regInfo,1L

#define SN_id_regInfo_certReq		"id-regInfo-certReq"
#define NID_id_regInfo_certReq		322
#define OBJ_id_regInfo_certReq		OBJ_id_regInfo,2L

#define SN_id_alg_des40		"id-alg-des40"
#define NID_id_alg_des40		323
#define OBJ_id_alg_des40		OBJ_id_alg,1L

#define SN_id_alg_noSignature		"id-alg-noSignature"
#define NID_id_alg_noSignature		324
#define OBJ_id_alg_noSignature		OBJ_id_alg,2L

#define SN_id_alg_dh_sig_hmac_sha1		"id-alg-dh-sig-hmac-sha1"
#define NID_id_alg_dh_sig_hmac_sha1		325
#define OBJ_id_alg_dh_sig_hmac_sha1		OBJ_id_alg,3L

#define SN_id_alg_dh_pop		"id-alg-dh-pop"
#define NID_id_alg_dh_pop		326
#define OBJ_id_alg_dh_pop		OBJ_id_alg,4L

#define SN_id_cmc_statusInfo		"id-cmc-statusInfo"
#define NID_id_cmc_statusInfo		327
#define OBJ_id_cmc_statusInfo		OBJ_id_cmc,1L

#define SN_id_cmc_identification		"id-cmc-identification"
#define NID_id_cmc_identification		328
#define OBJ_id_cmc_identification		OBJ_id_cmc,2L

#define SN_id_cmc_identityProof		"id-cmc-identityProof"
#define NID_id_cmc_identityProof		329
#define OBJ_id_cmc_identityProof		OBJ_id_cmc,3L

#define SN_id_cmc_dataReturn		"id-cmc-dataReturn"
#define NID_id_cmc_dataReturn		330
#define OBJ_id_cmc_dataReturn		OBJ_id_cmc,4L

#define SN_id_cmc_transactionId		"id-cmc-transactionId"
#define NID_id_cmc_transactionId		331
#define OBJ_id_cmc_transactionId		OBJ_id_cmc,5L

#define SN_id_cmc_senderNonce		"id-cmc-senderNonce"
#define NID_id_cmc_senderNonce		332
#define OBJ_id_cmc_senderNonce		OBJ_id_cmc,6L

#define SN_id_cmc_recipientNonce		"id-cmc-recipientNonce"
#define NID_id_cmc_recipientNonce		333
#define OBJ_id_cmc_recipientNonce		OBJ_id_cmc,7L

#define SN_id_cmc_addExtensions		"id-cmc-addExtensions"
#define NID_id_cmc_addExtensions		334
#define OBJ_id_cmc_addExtensions		OBJ_id_cmc,8L

#define SN_id_cmc_encryptedPOP		"id-cmc-encryptedPOP"
#define NID_id_cmc_encryptedPOP		335
#define OBJ_id_cmc_encryptedPOP		OBJ_id_cmc,9L

#define SN_id_cmc_decryptedPOP		"id-cmc-decryptedPOP"
#define NID_id_cmc_decryptedPOP		336
#define OBJ_id_cmc_decryptedPOP		OBJ_id_cmc,10L

#define SN_id_cmc_lraPOPWitness		"id-cmc-lraPOPWitness"
#define NID_id_cmc_lraPOPWitness		337
#define OBJ_id_cmc_lraPOPWitness		OBJ_id_cmc,11L

#define SN_id_cmc_getCert		"id-cmc-getCert"
#define NID_id_cmc_getCert		338
#define OBJ_id_cmc_getCert		OBJ_id_cmc,15L

#define SN_id_cmc_getCRL		"id-cmc-getCRL"
#define NID_id_cmc_getCRL		339
#define OBJ_id_cmc_getCRL		OBJ_id_cmc,16L

#define SN_id_cmc_revokeRequest		"id-cmc-revokeRequest"
#define NID_id_cmc_revokeRequest		340
#define OBJ_id_cmc_revokeRequest		OBJ_id_cmc,17L

#define SN_id_cmc_regInfo		"id-cmc-regInfo"
#define NID_id_cmc_regInfo		341
#define OBJ_id_cmc_regInfo		OBJ_id_cmc,18L

#define SN_id_cmc_responseInfo		"id-cmc-responseInfo"
#define NID_id_cmc_responseInfo		342
#define OBJ_id_cmc_responseInfo		OBJ_id_cmc,19L

#define SN_id_cmc_queryPending		"id-cmc-queryPending"
#define NID_id_cmc_queryPending		343
#define OBJ_id_cmc_queryPending		OBJ_id_cmc,21L

#define SN_id_cmc_popLinkRandom		"id-cmc-popLinkRandom"
#define NID_id_cmc_popLinkRandom		344
#define OBJ_id_cmc_popLinkRandom		OBJ_id_cmc,22L

#define SN_id_cmc_popLinkWitness		"id-cmc-popLinkWitness"
#define NID_id_cmc_popLinkWitness		345
#define OBJ_id_cmc_popLinkWitness		OBJ_id_cmc,23L

#define SN_id_cmc_confirmCertAcceptance		"id-cmc-confirmCertAcceptance"
#define NID_id_cmc_confirmCertAcceptance		346
#define OBJ_id_cmc_confirmCertAcceptance		OBJ_id_cmc,24L

#define SN_id_on_personalData		"id-on-personalData"
#define NID_id_on_personalData		347
#define OBJ_id_on_personalData		OBJ_id_on,1L

#define SN_id_on_permanentIdentifier		"id-on-permanentIdentifier"
#define LN_id_on_permanentIdentifier		"Permanent Identifier"
#define NID_id_on_permanentIdentifier		858
#define OBJ_id_on_permanentIdentifier		OBJ_id_on,3L

#define SN_id_pda_dateOfBirth		"id-pda-dateOfBirth"
#define NID_id_pda_dateOfBirth		348
#define OBJ_id_pda_dateOfBirth		OBJ_id_pda,1L

#define SN_id_pda_placeOfBirth		"id-pda-placeOfBirth"
#define NID_id_pda_placeOfBirth		349
#define OBJ_id_pda_placeOfBirth		OBJ_id_pda,2L

#define SN_id_pda_gender		"id-pda-gender"
#define NID_id_pda_gender		351
#define OBJ_id_pda_gender		OBJ_id_pda,3L

#define SN_id_pda_countryOfCitizenship		"id-pda-countryOfCitizenship"
#define NID_id_pda_countryOfCitizenship		352
#define OBJ_id_pda_countryOfCitizenship		OBJ_id_pda,4L

#define SN_id_pda_countryOfResidence		"id-pda-countryOfResidence"
#define NID_id_pda_countryOfResidence		353
#define OBJ_id_pda_countryOfResidence		OBJ_id_pda,5L

#define SN_id_aca_authenticationInfo		"id-aca-authenticationInfo"
#define NID_id_aca_authenticationInfo		354
#define OBJ_id_aca_authenticationInfo		OBJ_id_aca,1L

#define SN_id_aca_accessIdentity		"id-aca-accessIdentity"
#define NID_id_aca_accessIdentity		355
#define OBJ_id_aca_accessIdentity		OBJ_id_aca,2L

#define SN_id_aca_chargingIdentity		"id-aca-chargingIdentity"
#define NID_id_aca_chargingIdentity		356
#define OBJ_id_aca_chargingIdentity		OBJ_id_aca,3L

#define SN_id_aca_group		"id-aca-group"
#define NID_id_aca_group		357
#define OBJ_id_aca_group		OBJ_id_aca,4L

#define SN_id_aca_role		"id-aca-role"
#define NID_id_aca_role		358
#define OBJ_id_aca_role		OBJ_id_aca,5L

#define SN_id_aca_encAttrs		"id-aca-encAttrs"
#define NID_id_aca_encAttrs		399
#define OBJ_id_aca_encAttrs		OBJ_id_aca,6L

#define SN_id_qcs_pkixQCSyntax_v1		"id-qcs-pkixQCSyntax-v1"
#define NID_id_qcs_pkixQCSyntax_v1		359
#define OBJ_id_qcs_pkixQCSyntax_v1		OBJ_id_qcs,1L

#define SN_id_cct_crs		"id-cct-crs"
#define NID_id_cct_crs		360
#define OBJ_id_cct_crs		OBJ_id_cct,1L

#define SN_id_cct_PKIData		"id-cct-PKIData"
#define NID_id_cct_PKIData		361
#define OBJ_id_cct_PKIData		OBJ_id_cct,2L

#define SN_id_cct_PKIResponse		"id-cct-PKIResponse"
#define NID_id_cct_PKIResponse		362
#define OBJ_id_cct_PKIResponse		OBJ_id_cct,3L

#define SN_id_ppl_anyLanguage		"id-ppl-anyLanguage"
#define LN_id_ppl_anyLanguage		"Any language"
#define NID_id_ppl_anyLanguage		664
#define OBJ_id_ppl_anyLanguage		OBJ_id_ppl,0L

#define SN_id_ppl_inheritAll		"id-ppl-inheritAll"
#define LN_id_ppl_inheritAll		"Inherit all"
#define NID_id_ppl_inheritAll		665
#define OBJ_id_ppl_inheritAll		OBJ_id_ppl,1L

#define SN_Independent		"id-ppl-independent"
#define LN_Independent		"Independent"
#define NID_Independent		667
#define OBJ_Independent		OBJ_id_ppl,2L

#define SN_ad_OCSP		"OCSP"
#define LN_ad_OCSP		"OCSP"
#define NID_ad_OCSP		178
#define OBJ_ad_OCSP		OBJ_id_ad,1L

#define SN_ad_ca_issuers		"caIssuers"
#define LN_ad_ca_issuers		"CA Issuers"
#define NID_ad_ca_issuers		179
#define OBJ_ad_ca_issuers		OBJ_id_ad,2L

#define SN_ad_timeStamping		"ad_timestamping"
#define LN_ad_timeStamping		"AD Time Stamping"
#define NID_ad_timeStamping		363
#define OBJ_ad_timeStamping		OBJ_id_ad,3L

#define SN_ad_dvcs		"AD_DVCS"
#define LN_ad_dvcs		"ad dvcs"
#define NID_ad_dvcs		364
#define OBJ_ad_dvcs		OBJ_id_ad,4L

#define SN_caRepository		"caRepository"
#define LN_caRepository		"CA Repository"
#define NID_caRepository		785
#define OBJ_caRepository		OBJ_id_ad,5L

#define OBJ_id_pkix_OCSP		OBJ_ad_OCSP

#define SN_id_pkix_OCSP_basic		"basicOCSPResponse"
#define LN_id_pkix_OCSP_basic		"Basic OCSP Response"
#define NID_id_pkix_OCSP_basic		365
#define OBJ_id_pkix_OCSP_basic		OBJ_id_pkix_OCSP,1L

#define SN_id_pkix_OCSP_Nonce		"Nonce"
#define LN_id_pkix_OCSP_Nonce		"OCSP Nonce"
#define NID_id_pkix_OCSP_Nonce		366
#define OBJ_id_pkix_OCSP_Nonce		OBJ_id_pkix_OCSP,2L

#define SN_id_pkix_OCSP_CrlID		"CrlID"
#define LN_id_pkix_OCSP_CrlID		"OCSP CRL ID"
#define NID_id_pkix_OCSP_CrlID		367
#define OBJ_id_pkix_OCSP_CrlID		OBJ_id_pkix_OCSP,3L

#define SN_id_pkix_OCSP_acceptableResponses		"acceptableResponses"
#define LN_id_pkix_OCSP_acceptableResponses		"Acceptable OCSP Responses"
#define NID_id_pkix_OCSP_acceptableResponses		368
#define OBJ_id_pkix_OCSP_acceptableResponses		OBJ_id_pkix_OCSP,4L

#define SN_id_pkix_OCSP_noCheck		"noCheck"
#define LN_id_pkix_OCSP_noCheck		"OCSP No Check"
#define NID_id_pkix_OCSP_noCheck		369
#define OBJ_id_pkix_OCSP_noCheck		OBJ_id_pkix_OCSP,5L

#define SN_id_pkix_OCSP_archiveCutoff		"archiveCutoff"
#define LN_id_pkix_OCSP_archiveCutoff		"OCSP Archive Cutoff"
#define NID_id_pkix_OCSP_archiveCutoff		370
#define OBJ_id_pkix_OCSP_archiveCutoff		OBJ_id_pkix_OCSP,6L

#define SN_id_pkix_OCSP_serviceLocator		"serviceLocator"
#define LN_id_pkix_OCSP_serviceLocator		"OCSP Service Locator"
#define NID_id_pkix_OCSP_serviceLocator		371
#define OBJ_id_pkix_OCSP_serviceLocator		OBJ_id_pkix_OCSP,7L

#define SN_id_pkix_OCSP_extendedStatus		"extendedStatus"
#define LN_id_pkix_OCSP_extendedStatus		"Extended OCSP Status"
#define NID_id_pkix_OCSP_extendedStatus		372
#define OBJ_id_pkix_OCSP_extendedStatus		OBJ_id_pkix_OCSP,8L

#define SN_id_pkix_OCSP_valid		"valid"
#define NID_id_pkix_OCSP_valid		373
#define OBJ_id_pkix_OCSP_valid		OBJ_id_pkix_OCSP,9L

#define SN_id_pkix_OCSP_path		"path"
#define NID_id_pkix_OCSP_path		374
#define OBJ_id_pkix_OCSP_path		OBJ_id_pkix_OCSP,10L

#define SN_id_pkix_OCSP_trustRoot		"trustRoot"
#define LN_id_pkix_OCSP_trustRoot		"Trust Root"
#define NID_id_pkix_OCSP_trustRoot		375
#define OBJ_id_pkix_OCSP_trustRoot		OBJ_id_pkix_OCSP,11L

#define SN_algorithm		"algorithm"
#define LN_algorithm		"algorithm"
#define NID_algorithm		376
#define OBJ_algorithm		1L,3L,14L,3L,2L

#define SN_md5WithRSA		"RSA-NP-MD5"
#define LN_md5WithRSA		"md5WithRSA"
#define NID_md5WithRSA		104
#define OBJ_md5WithRSA		OBJ_algorithm,3L

#define SN_des_ecb		"DES-ECB"
#define LN_des_ecb		"des-ecb"
#define NID_des_ecb		29
#define OBJ_des_ecb		OBJ_algorithm,6L

#define SN_des_cbc		"DES-CBC"
#define LN_des_cbc		"des-cbc"
#define NID_des_cbc		31
#define OBJ_des_cbc		OBJ_algorithm,7L

#define SN_des_ofb64		"DES-OFB"
#define LN_des_ofb64		"des-ofb"
#define NID_des_ofb64		45
#define OBJ_des_ofb64		OBJ_algorithm,8L

#define SN_des_cfb64		"DES-CFB"
#define LN_des_cfb64		"des-cfb"
#define NID_des_cfb64		30
#define OBJ_des_cfb64		OBJ_algorithm,9L

#define SN_rsaSignature		"rsaSignature"
#define NID_rsaSignature		377
#define OBJ_rsaSignature		OBJ_algorithm,11L

#define SN_dsa_2		"DSA-old"
#define LN_dsa_2		"dsaEncryption-old"
#define NID_dsa_2		67
#define OBJ_dsa_2		OBJ_algorithm,12L

#define SN_dsaWithSHA		"DSA-SHA"
#define LN_dsaWithSHA		"dsaWithSHA"
#define NID_dsaWithSHA		66
#define OBJ_dsaWithSHA		OBJ_algorithm,13L

#define SN_shaWithRSAEncryption		"RSA-SHA"
#define LN_shaWithRSAEncryption		"shaWithRSAEncryption"
#define NID_shaWithRSAEncryption		42
#define OBJ_shaWithRSAEncryption		OBJ_algorithm,15L

#define SN_des_ede_ecb		"DES-EDE"
#define LN_des_ede_ecb		"des-ede"
#define NID_des_ede_ecb		32
#define OBJ_des_ede_ecb		OBJ_algorithm,17L

#define SN_des_ede3_ecb		"DES-EDE3"
#define LN_des_ede3_ecb		"des-ede3"
#define NID_des_ede3_ecb		33

#define SN_des_ede_cbc		"DES-EDE-CBC"
#define LN_des_ede_cbc		"des-ede-cbc"
#define NID_des_ede_cbc		43

#define SN_des_ede_cfb64		"DES-EDE-CFB"
#define LN_des_ede_cfb64		"des-ede-cfb"
#define NID_des_ede_cfb64		60

#define SN_des_ede3_cfb64		"DES-EDE3-CFB"
#define LN_des_ede3_cfb64		"des-ede3-cfb"
#define NID_des_ede3_cfb64		61

#define SN_des_ede_ofb64		"DES-EDE-OFB"
#define LN_des_ede_ofb64		"des-ede-ofb"
#define NID_des_ede_ofb64		62

#define SN_des_ede3_ofb64		"DES-EDE3-OFB"
#define LN_des_ede3_ofb64		"des-ede3-ofb"
#define NID_des_ede3_ofb64		63

#define SN_desx_cbc		"DESX-CBC"
#define LN_desx_cbc		"desx-cbc"
#define NID_desx_cbc		80

#define SN_sha		"SHA"
#define LN_sha		"sha"
#define NID_sha		41
#define OBJ_sha		OBJ_algorithm,18L

#define SN_sha1		"SHA1"
#define LN_sha1		"sha1"
#define NID_sha1		64
#define OBJ_sha1		OBJ_algorithm,26L

#define SN_dsaWithSHA1_2		"DSA-SHA1-old"
#define LN_dsaWithSHA1_2		"dsaWithSHA1-old"
#define NID_dsaWithSHA1_2		70
#define OBJ_dsaWithSHA1_2		OBJ_algorithm,27L

#define SN_sha1WithRSA		"RSA-SHA1-2"
#define LN_sha1WithRSA		"sha1WithRSA"
#define NID_sha1WithRSA		115
#define OBJ_sha1WithRSA		OBJ_algorithm,29L

#define SN_ripemd160		"RIPEMD160"
#define LN_ripemd160		"ripemd160"
#define NID_ripemd160		117
#define OBJ_ripemd160		1L,3L,36L,3L,2L,1L

#define SN_ripemd160WithRSA		"RSA-RIPEMD160"
#define LN_ripemd160WithRSA		"ripemd160WithRSA"
#define NID_ripemd160WithRSA		119
#define OBJ_ripemd160WithRSA		1L,3L,36L,3L,3L,1L,2L

#define SN_sxnet		"SXNetID"
#define LN_sxnet		"Strong Extranet ID"
#define NID_sxnet		143
#define OBJ_sxnet		1L,3L,101L,1L,4L,1L

#define SN_X500		"X500"
#define LN_X500		"directory services (X.500)"
#define NID_X500		11
#define OBJ_X500		2L,5L

#define SN_X509		"X509"
#define NID_X509		12
#define OBJ_X509		OBJ_X500,4L

#define SN_commonName		"CN"
#define LN_commonName		"commonName"
#define NID_commonName		13
#define OBJ_commonName		OBJ_X509,3L

#define SN_surname		"SN"
#define LN_surname		"surname"
#define NID_surname		100
#define OBJ_surname		OBJ_X509,4L

#define LN_serialNumber		"serialNumber"
#define NID_serialNumber		105
#define OBJ_serialNumber		OBJ_X509,5L

#define SN_countryName		"C"
#define LN_countryName		"countryName"
#define NID_countryName		14
#define OBJ_countryName		OBJ_X509,6L

#define SN_localityName		"L"
#define LN_localityName		"localityName"
#define NID_localityName		15
#define OBJ_localityName		OBJ_X509,7L

#define SN_stateOrProvinceName		"ST"
#define LN_stateOrProvinceName		"stateOrProvinceName"
#define NID_stateOrProvinceName		16
#define OBJ_stateOrProvinceName		OBJ_X509,8L

#define SN_streetAddress		"street"
#define LN_streetAddress		"streetAddress"
#define NID_streetAddress		660
#define OBJ_streetAddress		OBJ_X509,9L

#define SN_organizationName		"O"
#define LN_organizationName		"organizationName"
#define NID_organizationName		17
#define OBJ_organizationName		OBJ_X509,10L

#define SN_organizationalUnitName		"OU"
#define LN_organizationalUnitName		"organizationalUnitName"
#define NID_organizationalUnitName		18
#define OBJ_organizationalUnitName		OBJ_X509,11L

#define SN_title		"title"
#define LN_title		"title"
#define NID_title		106
#define OBJ_title		OBJ_X509,12L

#define LN_description		"description"
#define NID_description		107
#define OBJ_description		OBJ_X509,13L

#define LN_searchGuide		"searchGuide"
#define NID_searchGuide		859
#define OBJ_searchGuide		OBJ_X509,14L

#define LN_businessCategory		"businessCategory"
#define NID_businessCategory		860
#define OBJ_businessCategory		OBJ_X509,15L

#define LN_postalAddress		"postalAddress"
#define NID_postalAddress		861
#define OBJ_postalAddress		OBJ_X509,16L

#define LN_postalCode		"postalCode"
#define NID_postalCode		661
#define OBJ_postalCode		OBJ_X509,17L

#define LN_postOfficeBox		"postOfficeBox"
#define NID_postOfficeBox		862
#define OBJ_postOfficeBox		OBJ_X509,18L

#define LN_physicalDeliveryOfficeName		"physicalDeliveryOfficeName"
#define NID_physicalDeliveryOfficeName		863
#define OBJ_physicalDeliveryOfficeName		OBJ_X509,19L

#define LN_telephoneNumber		"telephoneNumber"
#define NID_telephoneNumber		864
#define OBJ_telephoneNumber		OBJ_X509,20L

#define LN_telexNumber		"telexNumber"
#define NID_telexNumber		865
#define OBJ_telexNumber		OBJ_X509,21L

#define LN_teletexTerminalIdentifier		"teletexTerminalIdentifier"
#define NID_teletexTerminalIdentifier		866
#define OBJ_teletexTerminalIdentifier		OBJ_X509,22L

#define LN_facsimileTelephoneNumber		"facsimileTelephoneNumber"
#define NID_facsimileTelephoneNumber		867
#define OBJ_facsimileTelephoneNumber		OBJ_X509,23L

#define LN_x121Address		"x121Address"
#define NID_x121Address		868
#define OBJ_x121Address		OBJ_X509,24L

#define LN_internationaliSDNNumber		"internationaliSDNNumber"
#define NID_internationaliSDNNumber		869
#define OBJ_internationaliSDNNumber		OBJ_X509,25L

#define LN_registeredAddress		"registeredAddress"
#define NID_registeredAddress		870
#define OBJ_registeredAddress		OBJ_X509,26L

#define LN_destinationIndicator		"destinationIndicator"
#define NID_destinationIndicator		871
#define OBJ_destinationIndicator		OBJ_X509,27L

#define LN_preferredDeliveryMethod		"preferredDeliveryMethod"
#define NID_preferredDeliveryMethod		872
#define OBJ_preferredDeliveryMethod		OBJ_X509,28L

#define LN_presentationAddress		"presentationAddress"
#define NID_presentationAddress		873
#define OBJ_presentationAddress		OBJ_X509,29L

#define LN_supportedApplicationContext		"supportedApplicationContext"
#define NID_supportedApplicationContext		874
#define OBJ_supportedApplicationContext		OBJ_X509,30L

#define SN_member		"member"
#define NID_member		875
#define OBJ_member		OBJ_X509,31L

#define SN_owner		"owner"
#define NID_owner		876
#define OBJ_owner		OBJ_X509,32L

#define LN_roleOccupant		"roleOccupant"
#define NID_roleOccupant		877
#define OBJ_roleOccupant		OBJ_X509,33L

#define SN_seeAlso		"seeAlso"
#define NID_seeAlso		878
#define OBJ_seeAlso		OBJ_X509,34L

#define LN_userPassword		"userPassword"
#define NID_userPassword		879
#define OBJ_userPassword		OBJ_X509,35L

#define LN_userCertificate		"userCertificate"
#define NID_userCertificate		880
#define OBJ_userCertificate		OBJ_X509,36L

#define LN_cACertificate		"cACertificate"
#define NID_cACertificate		881
#define OBJ_cACertificate		OBJ_X509,37L

#define LN_authorityRevocationList		"authorityRevocationList"
#define NID_authorityRevocationList		882
#define OBJ_authorityRevocationList		OBJ_X509,38L

#define LN_certificateRevocationList		"certificateRevocationList"
#define NID_certificateRevocationList		883
#define OBJ_certificateRevocationList		OBJ_X509,39L

#define LN_crossCertificatePair		"crossCertificatePair"
#define NID_crossCertificatePair		884
#define OBJ_crossCertificatePair		OBJ_X509,40L

#define SN_name		"name"
#define LN_name		"name"
#define NID_name		173
#define OBJ_name		OBJ_X509,41L

#define SN_givenName		"GN"
#define LN_givenName		"givenName"
#define NID_givenName		99
#define OBJ_givenName		OBJ_X509,42L

#define SN_initials		"initials"
#define LN_initials		"initials"
#define NID_initials		101
#define OBJ_initials		OBJ_X509,43L

#define LN_generationQualifier		"generationQualifier"
#define NID_generationQualifier		509
#define OBJ_generationQualifier		OBJ_X509,44L

#define LN_x500UniqueIdentifier		"x500UniqueIdentifier"
#define NID_x500UniqueIdentifier		503
#define OBJ_x500UniqueIdentifier		OBJ_X509,45L

#define SN_dnQualifier		"dnQualifier"
#define LN_dnQualifier		"dnQualifier"
#define NID_dnQualifier		174
#define OBJ_dnQualifier		OBJ_X509,46L

#define LN_enhancedSearchGuide		"enhancedSearchGuide"
#define NID_enhancedSearchGuide		885
#define OBJ_enhancedSearchGuide		OBJ_X509,47L

#define LN_protocolInformation		"protocolInformation"
#define NID_protocolInformation		886
#define OBJ_protocolInformation		OBJ_X509,48L

#define LN_distinguishedName		"distinguishedName"
#define NID_distinguishedName		887
#define OBJ_distinguishedName		OBJ_X509,49L

#define LN_uniqueMember		"uniqueMember"
#define NID_uniqueMember		888
#define OBJ_uniqueMember		OBJ_X509,50L

#define LN_houseIdentifier		"houseIdentifier"
#define NID_houseIdentifier		889
#define OBJ_houseIdentifier		OBJ_X509,51L

#define LN_supportedAlgorithms		"supportedAlgorithms"
#define NID_supportedAlgorithms		890
#define OBJ_supportedAlgorithms		OBJ_X509,52L

#define LN_deltaRevocationList		"deltaRevocationList"
#define NID_deltaRevocationList		891
#define OBJ_deltaRevocationList		OBJ_X509,53L

#define SN_dmdName		"dmdName"
#define NID_dmdName		892
#define OBJ_dmdName		OBJ_X509,54L

#define LN_pseudonym		"pseudonym"
#define NID_pseudonym		510
#define OBJ_pseudonym		OBJ_X509,65L

#define SN_role		"role"
#define LN_role		"role"
#define NID_role		400
#define OBJ_role		OBJ_X509,72L

#define SN_X500algorithms		"X500algorithms"
#define LN_X500algorithms		"directory services - algorithms"
#define NID_X500algorithms		378
#define OBJ_X500algorithms		OBJ_X500,8L

#define SN_rsa		"RSA"
#define LN_rsa		"rsa"
#define NID_rsa		19
#define OBJ_rsa		OBJ_X500algorithms,1L,1L

#define SN_mdc2WithRSA		"RSA-MDC2"
#define LN_mdc2WithRSA		"mdc2WithRSA"
#define NID_mdc2WithRSA		96
#define OBJ_mdc2WithRSA		OBJ_X500algorithms,3L,100L

#define SN_mdc2		"MDC2"
#define LN_mdc2		"mdc2"
#define NID_mdc2		95
#define OBJ_mdc2		OBJ_X500algorithms,3L,101L

#define SN_id_ce		"id-ce"
#define NID_id_ce		81
#define OBJ_id_ce		OBJ_X500,29L

#define SN_subject_directory_attributes		"subjectDirectoryAttributes"
#define LN_subject_directory_attributes		"X509v3 Subject Directory Attributes"
#define NID_subject_directory_attributes		769
#define OBJ_subject_directory_attributes		OBJ_id_ce,9L

#define SN_subject_key_identifier		"subjectKeyIdentifier"
#define LN_subject_key_identifier		"X509v3 Subject Key Identifier"
#define NID_subject_key_identifier		82
#define OBJ_subject_key_identifier		OBJ_id_ce,14L

#define SN_key_usage		"keyUsage"
#define LN_key_usage		"X509v3 Key Usage"
#define NID_key_usage		83
#define OBJ_key_usage		OBJ_id_ce,15L

#define SN_private_key_usage_period		"privateKeyUsagePeriod"
#define LN_private_key_usage_period		"X509v3 Private Key Usage Period"
#define NID_private_key_usage_period		84
#define OBJ_private_key_usage_period		OBJ_id_ce,16L

#define SN_subject_alt_name		"subjectAltName"
#define LN_subject_alt_name		"X509v3 Subject Alternative Name"
#define NID_subject_alt_name		85
#define OBJ_subject_alt_name		OBJ_id_ce,17L

#define SN_issuer_alt_name		"issuerAltName"
#define LN_issuer_alt_name		"X509v3 Issuer Alternative Name"
#define NID_issuer_alt_name		86
#define OBJ_issuer_alt_name		OBJ_id_ce,18L

#define SN_basic_constraints		"basicConstraints"
#define LN_basic_constraints		"X509v3 Basic Constraints"
#define NID_basic_constraints		87
#define OBJ_basic_constraints		OBJ_id_ce,19L

#define SN_crl_number		"crlNumber"
#define LN_crl_number		"X509v3 CRL Number"
#define NID_crl_number		88
#define OBJ_crl_number		OBJ_id_ce,20L

#define SN_crl_reason		"CRLReason"
#define LN_crl_reason		"X509v3 CRL Reason Code"
#define NID_crl_reason		141
#define OBJ_crl_reason		OBJ_id_ce,21L

#define SN_invalidity_date		"invalidityDate"
#define LN_invalidity_date		"Invalidity Date"
#define NID_invalidity_date		142
#define OBJ_invalidity_date		OBJ_id_ce,24L

#define SN_delta_crl		"deltaCRL"
#define LN_delta_crl		"X509v3 Delta CRL Indicator"
#define NID_delta_crl		140
#define OBJ_delta_crl		OBJ_id_ce,27L

#define SN_issuing_distribution_point		"issuingDistributionPoint"
#define LN_issuing_distribution_point		"X509v3 Issuing Distrubution Point"
#define NID_issuing_distribution_point		770
#define OBJ_issuing_distribution_point		OBJ_id_ce,28L

#define SN_certificate_issuer		"certificateIssuer"
#define LN_certificate_issuer		"X509v3 Certificate Issuer"
#define NID_certificate_issuer		771
#define OBJ_certificate_issuer		OBJ_id_ce,29L

#define SN_name_constraints		"nameConstraints"
#define LN_name_constraints		"X509v3 Name Constraints"
#define NID_name_constraints		666
#define OBJ_name_constraints		OBJ_id_ce,30L

#define SN_crl_distribution_points		"crlDistributionPoints"
#define LN_crl_distribution_points		"X509v3 CRL Distribution Points"
#define NID_crl_distribution_points		103
#define OBJ_crl_distribution_points		OBJ_id_ce,31L

#define SN_certificate_policies		"certificatePolicies"
#define LN_certificate_policies		"X509v3 Certificate Policies"
#define NID_certificate_policies		89
#define OBJ_certificate_policies		OBJ_id_ce,32L

#define SN_any_policy		"anyPolicy"
#define LN_any_policy		"X509v3 Any Policy"
#define NID_any_policy		746
#define OBJ_any_policy		OBJ_certificate_policies,0L

#define SN_policy_mappings		"policyMappings"
#define LN_policy_mappings		"X509v3 Policy Mappings"
#define NID_policy_mappings		747
#define OBJ_policy_mappings		OBJ_id_ce,33L

#define SN_authority_key_identifier		"authorityKeyIdentifier"
#define LN_authority_key_identifier		"X509v3 Authority Key Identifier"
#define NID_authority_key_identifier		90
#define OBJ_authority_key_identifier		OBJ_id_ce,35L

#define SN_policy_constraints		"policyConstraints"
#define LN_policy_constraints		"X509v3 Policy Constraints"
#define NID_policy_constraints		401
#define OBJ_policy_constraints		OBJ_id_ce,36L

#define SN_ext_key_usage		"extendedKeyUsage"
#define LN_ext_key_usage		"X509v3 Extended Key Usage"
#define NID_ext_key_usage		126
#define OBJ_ext_key_usage		OBJ_id_ce,37L

#define SN_freshest_crl		"freshestCRL"
#define LN_freshest_crl		"X509v3 Freshest CRL"
#define NID_freshest_crl		857
#define OBJ_freshest_crl		OBJ_id_ce,46L

#define SN_inhibit_any_policy		"inhibitAnyPolicy"
#define LN_inhibit_any_policy		"X509v3 Inhibit Any Policy"
#define NID_inhibit_any_policy		748
#define OBJ_inhibit_any_policy		OBJ_id_ce,54L

#define SN_target_information		"targetInformation"
#define LN_target_information		"X509v3 AC Targeting"
#define NID_target_information		402
#define OBJ_target_information		OBJ_id_ce,55L

#define SN_no_rev_avail		"noRevAvail"
#define LN_no_rev_avail		"X509v3 No Revocation Available"
#define NID_no_rev_avail		403
#define OBJ_no_rev_avail		OBJ_id_ce,56L

#define SN_netscape		"Netscape"
#define LN_netscape		"Netscape Communications Corp."
#define NID_netscape		2
#define OBJ_netscape		2L,16L,840L,1L,113730L

#define SN_netscape_cert_extension		"nsCertExt"
#define LN_netscape_cert_extension		"Netscape Certificate Extension"
#define NID_netscape_cert_extension		3
#define OBJ_netscape_cert_extension		OBJ_netscape,1L

#define SN_netscape_data_type		"nsDataType"
#define LN_netscape_data_type		"Netscape Data Type"
#define NID_netscape_data_type		59
#define OBJ_netscape_data_type		OBJ_netscape,2L

#define SN_netscape_cert_type		"nsCertType"
#define LN_netscape_cert_type		"Netscape Cert Type"
#define NID_netscape_cert_type		4
#define OBJ_netscape_cert_type		OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url		"samyang7"
#define LN_netscape_base_url		"test7"
#define NID_netscape_base_url		5
#define OBJ_netscape_base_url		OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url		"samyang6"
#define LN_netscape_revocation_url		"test6"
#define NID_netscape_revocation_url	6
#define OBJ_netscape_revocation_url		OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url		"samyang5"
#define LN_netscape_ca_revocation_url		"test5"
#define NID_netscape_ca_revocation_url		7
#define OBJ_netscape_ca_revocation_url		OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url		"samyang4"
#define LN_netscape_renewal_url		"test4"
#define NID_netscape_renewal_url		8
#define OBJ_netscape_renewal_url		OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url		"samyang3"
#define LN_netscape_ca_policy_url		"test3"
#define NID_netscape_ca_policy_url		9
#define OBJ_netscape_ca_policy_url		OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name		"samyang2"
#define LN_netscape_ssl_server_name		"test2"
#define NID_netscape_ssl_server_name		10
#define OBJ_netscape_ssl_server_name		OBJ_netscape_cert_extension,12L

#define SN_netscape_comment		"samyang1"
#define LN_netscape_comment		"test1"
#define NID_netscape_comment		11
#define OBJ_netscape_comment		OBJ_netscape_cert_extension,13L

//////////////////samyang modify/////////////////

#define SN_test_comment		"samyang8"
#define LN_test_comment		"My_comment"
#define NID_test_comment		12
#define OBJ_test_comment		OBJ_netscape_cert_extension,14L


#define SN_aw_cert_extension			"AW"
#define LN_aw_cert_extension			"ALLWINNER  EXTENSION"
#define NID_aw_cert_extension		13
#define OBJ_aw_cert_extension		2L,16L,840L,1L,113549L


#define SN_aw_comment1			"awcomment1"
#define LN_aw_comment1			"allwinner comment1"
#define NID_aw_comment1			14
#define OBJ_aw_comment1              OBJ_aw_cert_extension,1L


////////////////////////////////////////////////


#define SN_netscape_cert_sequence		"nsCertSequence"
#define LN_netscape_cert_sequence		"Netscape Certificate Sequence"
#define NID_netscape_cert_sequence		79
#define OBJ_netscape_cert_sequence		OBJ_netscape_data_type,5L

#define SN_ns_sgc		"nsSGC"
#define LN_ns_sgc		"Netscape Server Gated Crypto"
#define NID_ns_sgc		139
#define OBJ_ns_sgc		OBJ_netscape,4L,1L

#define SN_org		"ORG"
#define LN_org		"org"
#define NID_org		379
#define OBJ_org		OBJ_iso,3L

#define SN_dod		"DOD"
#define LN_dod		"dod"
#define NID_dod		380
#define OBJ_dod		OBJ_org,6L

#define SN_iana		"IANA"
#define LN_iana		"iana"
#define NID_iana		381
#define OBJ_iana		OBJ_dod,1L

#define OBJ_internet		OBJ_iana

#define SN_Directory		"directory"
#define LN_Directory		"Directory"
#define NID_Directory		382
#define OBJ_Directory		OBJ_internet,1L

#define SN_Management		"mgmt"
#define LN_Management		"Management"
#define NID_Management		383
#define OBJ_Management		OBJ_internet,2L

#define SN_Experimental		"experimental"
#define LN_Experimental		"Experimental"
#define NID_Experimental		384
#define OBJ_Experimental		OBJ_internet,3L

#define SN_Private		"private"
#define LN_Private		"Private"
#define NID_Private		385
#define OBJ_Private		OBJ_internet,4L

#define SN_Security		"security"
#define LN_Security		"Security"
#define NID_Security		386
#define OBJ_Security		OBJ_internet,5L

#define SN_SNMPv2		"snmpv2"
#define LN_SNMPv2		"SNMPv2"
#define NID_SNMPv2		387
#define OBJ_SNMPv2		OBJ_internet,6L

#define LN_Mail		"Mail"
#define NID_Mail		388
#define OBJ_Mail		OBJ_internet,7L

#define SN_Enterprises		"enterprises"
#define LN_Enterprises		"Enterprises"
#define NID_Enterprises		389
#define OBJ_Enterprises		OBJ_Private,1L

#define SN_dcObject		"dcobject"
#define LN_dcObject		"dcObject"
#define NID_dcObject		390
#define OBJ_dcObject		OBJ_Enterprises,1466L,344L

#define SN_mime_mhs		"mime-mhs"
#define LN_mime_mhs		"MIME MHS"
#define NID_mime_mhs		504
#define OBJ_mime_mhs		OBJ_Mail,1L

#define SN_mime_mhs_headings		"mime-mhs-headings"
#define LN_mime_mhs_headings		"mime-mhs-headings"
#define NID_mime_mhs_headings		505
#define OBJ_mime_mhs_headings		OBJ_mime_mhs,1L

#define SN_mime_mhs_bodies		"mime-mhs-bodies"
#define LN_mime_mhs_bodies		"mime-mhs-bodies"
#define NID_mime_mhs_bodies		506
#define OBJ_mime_mhs_bodies		OBJ_mime_mhs,2L

#define SN_id_hex_partial_message		"id-hex-partial-message"
#define LN_id_hex_partial_message		"id-hex-partial-message"
#define NID_id_hex_partial_message		507
#define OBJ_id_hex_partial_message		OBJ_mime_mhs_headings,1L

#define SN_id_hex_multipart_message		"id-hex-multipart-message"
#define LN_id_hex_multipart_message		"id-hex-multipart-message"
#define NID_id_hex_multipart_message		508
#define OBJ_id_hex_multipart_message		OBJ_mime_mhs_headings,2L

#define SN_rle_compression		"RLE"
#define LN_rle_compression		"run length compression"
#define NID_rle_compression		124
#define OBJ_rle_compression		1L,1L,1L,1L,666L,1L

#define SN_zlib_compression		"ZLIB"
#define LN_zlib_compression		"zlib compression"
#define NID_zlib_compression		125
#define OBJ_zlib_compression		OBJ_id_smime_alg,8L

#define OBJ_csor		2L,16L,840L,1L,101L,3L

#define OBJ_nistAlgorithms		OBJ_csor,4L

#define OBJ_aes		OBJ_nistAlgorithms,1L

#define SN_aes_128_ecb		"AES-128-ECB"
#define LN_aes_128_ecb		"aes-128-ecb"
#define NID_aes_128_ecb		418
#define OBJ_aes_128_ecb		OBJ_aes,1L

#define SN_aes_128_cbc		"AES-128-CBC"
#define LN_aes_128_cbc		"aes-128-cbc"
#define NID_aes_128_cbc		419
#define OBJ_aes_128_cbc		OBJ_aes,2L

#define SN_aes_128_ofb128		"AES-128-OFB"
#define LN_aes_128_ofb128		"aes-128-ofb"
#define NID_aes_128_ofb128		420
#define OBJ_aes_128_ofb128		OBJ_aes,3L

#define SN_aes_128_cfb128		"AES-128-CFB"
#define LN_aes_128_cfb128		"aes-128-cfb"
#define NID_aes_128_cfb128		421
#define OBJ_aes_128_cfb128		OBJ_aes,4L

#define SN_aes_192_ecb		"AES-192-ECB"
#define LN_aes_192_ecb		"aes-192-ecb"
#define NID_aes_192_ecb		422
#define OBJ_aes_192_ecb		OBJ_aes,21L

#define SN_aes_192_cbc		"AES-192-CBC"
#define LN_aes_192_cbc		"aes-192-cbc"
#define NID_aes_192_cbc		423
#define OBJ_aes_192_cbc		OBJ_aes,22L

#define SN_aes_192_ofb128		"AES-192-OFB"
#define LN_aes_192_ofb128		"aes-192-ofb"
#define NID_aes_192_ofb128		424
#define OBJ_aes_192_ofb128		OBJ_aes,23L

#define SN_aes_192_cfb128		"AES-192-CFB"
#define LN_aes_192_cfb128		"aes-192-cfb"
#define NID_aes_192_cfb128		425
#define OBJ_aes_192_cfb128		OBJ_aes,24L

#define SN_aes_256_ecb		"AES-256-ECB"
#define LN_aes_256_ecb		"aes-256-ecb"
#define NID_aes_256_ecb		426
#define OBJ_aes_256_ecb		OBJ_aes,41L

#define SN_aes_256_cbc		"AES-256-CBC"
#define LN_aes_256_cbc		"aes-256-cbc"
#define NID_aes_256_cbc		427
#define OBJ_aes_256_cbc		OBJ_aes,42L

#define SN_aes_256_ofb128		"AES-256-OFB"
#define LN_aes_256_ofb128		"aes-256-ofb"
#define NID_aes_256_ofb128		428
#define OBJ_aes_256_ofb128		OBJ_aes,43L

#define SN_aes_256_cfb128		"AES-256-CFB"
#define LN_aes_256_cfb128		"aes-256-cfb"
#define NID_aes_256_cfb128		429
#define OBJ_aes_256_cfb128		OBJ_aes,44L

#define SN_aes_128_cfb1		"AES-128-CFB1"
#define LN_aes_128_cfb1		"aes-128-cfb1"
#define NID_aes_128_cfb1		650

#define SN_aes_192_cfb1		"AES-192-CFB1"
#define LN_aes_192_cfb1		"aes-192-cfb1"
#define NID_aes_192_cfb1		651

#define SN_aes_256_cfb1		"AES-256-CFB1"
#define LN_aes_256_cfb1		"aes-256-cfb1"
#define NID_aes_256_cfb1		652

#define SN_aes_128_cfb8		"AES-128-CFB8"
#define LN_aes_128_cfb8		"aes-128-cfb8"
#define NID_aes_128_cfb8		653

#define SN_aes_192_cfb8		"AES-192-CFB8"
#define LN_aes_192_cfb8		"aes-192-cfb8"
#define NID_aes_192_cfb8		654

#define SN_aes_256_cfb8		"AES-256-CFB8"
#define LN_aes_256_cfb8		"aes-256-cfb8"
#define NID_aes_256_cfb8		655

#define SN_des_cfb1		"DES-CFB1"
#define LN_des_cfb1		"des-cfb1"
#define NID_des_cfb1		656

#define SN_des_cfb8		"DES-CFB8"
#define LN_des_cfb8		"des-cfb8"
#define NID_des_cfb8		657

#define SN_des_ede3_cfb1		"DES-EDE3-CFB1"
#define LN_des_ede3_cfb1		"des-ede3-cfb1"
#define NID_des_ede3_cfb1		658

#define SN_des_ede3_cfb8		"DES-EDE3-CFB8"
#define LN_des_ede3_cfb8		"des-ede3-cfb8"
#define NID_des_ede3_cfb8		659

#define SN_id_aes128_wrap		"id-aes128-wrap"
#define NID_id_aes128_wrap		788
#define OBJ_id_aes128_wrap		OBJ_aes,5L

#define SN_id_aes192_wrap		"id-aes192-wrap"
#define NID_id_aes192_wrap		789
#define OBJ_id_aes192_wrap		OBJ_aes,25L

#define SN_id_aes256_wrap		"id-aes256-wrap"
#define NID_id_aes256_wrap		790
#define OBJ_id_aes256_wrap		OBJ_aes,45L

#define OBJ_nist_hashalgs		OBJ_nistAlgorithms,2L

#define SN_sha256		"SHA256"
#define LN_sha256		"sha256"
#define NID_sha256		672
#define OBJ_sha256		OBJ_nist_hashalgs,1L

#define SN_sha384		"SHA384"
#define LN_sha384		"sha384"
#define NID_sha384		673
#define OBJ_sha384		OBJ_nist_hashalgs,2L

#define SN_sha512		"SHA512"
#define LN_sha512		"sha512"
#define NID_sha512		674
#define OBJ_sha512		OBJ_nist_hashalgs,3L

#define SN_sha224		"SHA224"
#define LN_sha224		"sha224"
#define NID_sha224		675
#define OBJ_sha224		OBJ_nist_hashalgs,4L

#define OBJ_dsa_with_sha2		OBJ_nistAlgorithms,3L

#define SN_dsa_with_SHA224		"dsa_with_SHA224"
#define NID_dsa_with_SHA224		802
#define OBJ_dsa_with_SHA224		OBJ_dsa_with_sha2,1L

#define SN_dsa_with_SHA256		"dsa_with_SHA256"
#define NID_dsa_with_SHA256		803
#define OBJ_dsa_with_SHA256		OBJ_dsa_with_sha2,2L

#define SN_hold_instruction_code		"holdInstructionCode"
#define LN_hold_instruction_code		"Hold Instruction Code"
#define NID_hold_instruction_code		430
#define OBJ_hold_instruction_code		OBJ_id_ce,23L

#define OBJ_holdInstruction		OBJ_X9_57,2L

#define SN_hold_instruction_none		"holdInstructionNone"
#define LN_hold_instruction_none		"Hold Instruction None"
#define NID_hold_instruction_none		431
#define OBJ_hold_instruction_none		OBJ_holdInstruction,1L

#define SN_hold_instruction_call_issuer		"holdInstructionCallIssuer"
#define LN_hold_instruction_call_issuer		"Hold Instruction Call Issuer"
#define NID_hold_instruction_call_issuer		432
#define OBJ_hold_instruction_call_issuer		OBJ_holdInstruction,2L

#define SN_hold_instruction_reject		"holdInstructionReject"
#define LN_hold_instruction_reject		"Hold Instruction Reject"
#define NID_hold_instruction_reject		433
#define OBJ_hold_instruction_reject		OBJ_holdInstruction,3L

#define SN_data		"data"
#define NID_data		434
#define OBJ_data		OBJ_itu_t,9L

#define SN_pss		"pss"
#define NID_pss		435
#define OBJ_pss		OBJ_data,2342L

#define SN_ucl		"ucl"
#define NID_ucl		436
#define OBJ_ucl		OBJ_pss,19200300L

#define SN_pilot		"pilot"
#define NID_pilot		437
#define OBJ_pilot		OBJ_ucl,100L

#define LN_pilotAttributeType		"pilotAttributeType"
#define NID_pilotAttributeType		438
#define OBJ_pilotAttributeType		OBJ_pilot,1L

#define LN_pilotAttributeSyntax		"pilotAttributeSyntax"
#define NID_pilotAttributeSyntax		439
#define OBJ_pilotAttributeSyntax		OBJ_pilot,3L

#define LN_pilotObjectClass		"pilotObjectClass"
#define NID_pilotObjectClass		440
#define OBJ_pilotObjectClass		OBJ_pilot,4L

#define LN_pilotGroups		"pilotGroups"
#define NID_pilotGroups		441
#define OBJ_pilotGroups		OBJ_pilot,10L

#define LN_iA5StringSyntax		"iA5StringSyntax"
#define NID_iA5StringSyntax		442
#define OBJ_iA5StringSyntax		OBJ_pilotAttributeSyntax,4L

#define LN_caseIgnoreIA5StringSyntax		"caseIgnoreIA5StringSyntax"
#define NID_caseIgnoreIA5StringSyntax		443
#define OBJ_caseIgnoreIA5StringSyntax		OBJ_pilotAttributeSyntax,5L

#define LN_pilotObject		"pilotObject"
#define NID_pilotObject		444
#define OBJ_pilotObject		OBJ_pilotObjectClass,3L

#define LN_pilotPerson		"pilotPerson"
#define NID_pilotPerson		445
#define OBJ_pilotPerson		OBJ_pilotObjectClass,4L

#define SN_account		"account"
#define NID_account		446
#define OBJ_account		OBJ_pilotObjectClass,5L

#define SN_document		"document"
#define NID_document		447
#define OBJ_document		OBJ_pilotObjectClass,6L

#define SN_room		"room"
#define NID_room		448
#define OBJ_room		OBJ_pilotObjectClass,7L

#define LN_documentSeries		"documentSeries"
#define NID_documentSeries		449
#define OBJ_documentSeries		OBJ_pilotObjectClass,9L

#define SN_Domain		"domain"
#define LN_Domain		"Domain"
#define NID_Domain		392
#define OBJ_Domain		OBJ_pilotObjectClass,13L

#define LN_rFC822localPart		"rFC822localPart"
#define NID_rFC822localPart		450
#define OBJ_rFC822localPart		OBJ_pilotObjectClass,14L

#define LN_dNSDomain		"dNSDomain"
#define NID_dNSDomain		451
#define OBJ_dNSDomain		OBJ_pilotObjectClass,15L

#define LN_domainRelatedObject		"domainRelatedObject"
#define NID_domainRelatedObject		452
#define OBJ_domainRelatedObject		OBJ_pilotObjectClass,17L

#define LN_friendlyCountry		"friendlyCountry"
#define NID_friendlyCountry		453
#define OBJ_friendlyCountry		OBJ_pilotObjectClass,18L

#define LN_simpleSecurityObject		"simpleSecurityObject"
#define NID_simpleSecurityObject		454
#define OBJ_simpleSecurityObject		OBJ_pilotObjectClass,19L

#define LN_pilotOrganization		"pilotOrganization"
#define NID_pilotOrganization		455
#define OBJ_pilotOrganization		OBJ_pilotObjectClass,20L

#define LN_pilotDSA		"pilotDSA"
#define NID_pilotDSA		456
#define OBJ_pilotDSA		OBJ_pilotObjectClass,21L

#define LN_qualityLabelledData		"qualityLabelledData"
#define NID_qualityLabelledData		457
#define OBJ_qualityLabelledData		OBJ_pilotObjectClass,22L

#define SN_userId		"UID"
#define LN_userId		"userId"
#define NID_userId		458
#define OBJ_userId		OBJ_pilotAttributeType,1L

#define LN_textEncodedORAddress		"textEncodedORAddress"
#define NID_textEncodedORAddress		459
#define OBJ_textEncodedORAddress		OBJ_pilotAttributeType,2L

#define SN_rfc822Mailbox		"mail"
#define LN_rfc822Mailbox		"rfc822Mailbox"
#define NID_rfc822Mailbox		460
#define OBJ_rfc822Mailbox		OBJ_pilotAttributeType,3L

#define SN_info		"info"
#define NID_info		461
#define OBJ_info		OBJ_pilotAttributeType,4L

#define LN_favouriteDrink		"favouriteDrink"
#define NID_favouriteDrink		462
#define OBJ_favouriteDrink		OBJ_pilotAttributeType,5L

#define LN_roomNumber		"roomNumber"
#define NID_roomNumber		463
#define OBJ_roomNumber		OBJ_pilotAttributeType,6L

#define SN_photo		"photo"
#define NID_photo		464
#define OBJ_photo		OBJ_pilotAttributeType,7L

#define LN_userClass		"userClass"
#define NID_userClass		465
#define OBJ_userClass		OBJ_pilotAttributeType,8L

#define SN_host		"host"
#define NID_host		466
#define OBJ_host		OBJ_pilotAttributeType,9L

#define SN_manager		"manager"
#define NID_manager		467
#define OBJ_manager		OBJ_pilotAttributeType,10L

#define LN_documentIdentifier		"documentIdentifier"
#define NID_documentIdentifier		468
#define OBJ_documentIdentifier		OBJ_pilotAttributeType,11L

#define LN_documentTitle		"documentTitle"
#define NID_documentTitle		469
#define OBJ_documentTitle		OBJ_pilotAttributeType,12L

#define LN_documentVersion		"documentVersion"
#define NID_documentVersion		470
#define OBJ_documentVersion		OBJ_pilotAttributeType,13L

#define LN_documentAuthor		"documentAuthor"
#define NID_documentAuthor		471
#define OBJ_documentAuthor		OBJ_pilotAttributeType,14L

#define LN_documentLocation		"documentLocation"
#define NID_documentLocation		472
#define OBJ_documentLocation		OBJ_pilotAttributeType,15L

#define LN_homeTelephoneNumber		"homeTelephoneNumber"
#define NID_homeTelephoneNumber		473
#define OBJ_homeTelephoneNumber		OBJ_pilotAttributeType,20L

#define SN_secretary		"secretary"
#define NID_secretary		474
#define OBJ_secretary		OBJ_pilotAttributeType,21L

#define LN_otherMailbox		"otherMailbox"
#define NID_otherMailbox		475
#define OBJ_otherMailbox		OBJ_pilotAttributeType,22L

#define LN_lastModifiedTime		"lastModifiedTime"
#define NID_lastModifiedTime		476
#define OBJ_lastModifiedTime		OBJ_pilotAttributeType,23L

#define LN_lastModifiedBy		"lastModifiedBy"
#define NID_lastModifiedBy		477
#define OBJ_lastModifiedBy		OBJ_pilotAttributeType,24L

#define SN_domainComponent		"DC"
#define LN_domainComponent		"domainComponent"
#define NID_domainComponent		391
#define OBJ_domainComponent		OBJ_pilotAttributeType,25L

#define LN_aRecord		"aRecord"
#define NID_aRecord		478
#define OBJ_aRecord		OBJ_pilotAttributeType,26L

#define LN_pilotAttributeType27		"pilotAttributeType27"
#define NID_pilotAttributeType27		479
#define OBJ_pilotAttributeType27		OBJ_pilotAttributeType,27L

#define LN_mXRecord		"mXRecord"
#define NID_mXRecord		480
#define OBJ_mXRecord		OBJ_pilotAttributeType,28L

#define LN_nSRecord		"nSRecord"
#define NID_nSRecord		481
#define OBJ_nSRecord		OBJ_pilotAttributeType,29L

#define LN_sOARecord		"sOARecord"
#define NID_sOARecord		482
#define OBJ_sOARecord		OBJ_pilotAttributeType,30L

#define LN_cNAMERecord		"cNAMERecord"
#define NID_cNAMERecord		483
#define OBJ_cNAMERecord		OBJ_pilotAttributeType,31L

#define LN_associatedDomain		"associatedDomain"
#define NID_associatedDomain		484
#define OBJ_associatedDomain		OBJ_pilotAttributeType,37L

#define LN_associatedName		"associatedName"
#define NID_associatedName		485
#define OBJ_associatedName		OBJ_pilotAttributeType,38L

#define LN_homePostalAddress		"homePostalAddress"
#define NID_homePostalAddress		486
#define OBJ_homePostalAddress		OBJ_pilotAttributeType,39L

#define LN_personalTitle		"personalTitle"
#define NID_personalTitle		487
#define OBJ_personalTitle		OBJ_pilotAttributeType,40L

#define LN_mobileTelephoneNumber		"mobileTelephoneNumber"
#define NID_mobileTelephoneNumber		488
#define OBJ_mobileTelephoneNumber		OBJ_pilotAttributeType,41L

#define LN_pagerTelephoneNumber		"pagerTelephoneNumber"
#define NID_pagerTelephoneNumber		489
#define OBJ_pagerTelephoneNumber		OBJ_pilotAttributeType,42L

#define LN_friendlyCountryName		"friendlyCountryName"
#define NID_friendlyCountryName		490
#define OBJ_friendlyCountryName		OBJ_pilotAttributeType,43L

#define LN_organizationalStatus		"organizationalStatus"
#define NID_organizationalStatus		491
#define OBJ_organizationalStatus		OBJ_pilotAttributeType,45L

#define LN_janetMailbox		"janetMailbox"
#define NID_janetMailbox		492
#define OBJ_janetMailbox		OBJ_pilotAttributeType,46L

#define LN_mailPreferenceOption		"mailPreferenceOption"
#define NID_mailPreferenceOption		493
#define OBJ_mailPreferenceOption		OBJ_pilotAttributeType,47L

#define LN_buildingName		"buildingName"
#define NID_buildingName		494
#define OBJ_buildingName		OBJ_pilotAttributeType,48L

#define LN_dSAQuality		"dSAQuality"
#define NID_dSAQuality		495
#define OBJ_dSAQuality		OBJ_pilotAttributeType,49L

#define LN_singleLevelQuality		"singleLevelQuality"
#define NID_singleLevelQuality		496
#define OBJ_singleLevelQuality		OBJ_pilotAttributeType,50L

#define LN_subtreeMinimumQuality		"subtreeMinimumQuality"
#define NID_subtreeMinimumQuality		497
#define OBJ_subtreeMinimumQuality		OBJ_pilotAttributeType,51L

#define LN_subtreeMaximumQuality		"subtreeMaximumQuality"
#define NID_subtreeMaximumQuality		498
#define OBJ_subtreeMaximumQuality		OBJ_pilotAttributeType,52L

#define LN_personalSignature		"personalSignature"
#define NID_personalSignature		499
#define OBJ_personalSignature		OBJ_pilotAttributeType,53L

#define LN_dITRedirect		"dITRedirect"
#define NID_dITRedirect		500
#define OBJ_dITRedirect		OBJ_pilotAttributeType,54L

#define SN_audio		"audio"
#define NID_audio		501
#define OBJ_audio		OBJ_pilotAttributeType,55L

#define LN_documentPublisher		"documentPublisher"
#define NID_documentPublisher		502
#define OBJ_documentPublisher		OBJ_pilotAttributeType,56L

#define SN_id_set		"id-set"
#define LN_id_set		"Secure Electronic Transactions"
#define NID_id_set		512
#define OBJ_id_set		OBJ_international_organizations,42L

#define SN_set_ctype		"set-ctype"
#define LN_set_ctype		"content types"
#define NID_set_ctype		513
#define OBJ_set_ctype		OBJ_id_set,0L

#define SN_set_msgExt		"set-msgExt"
#define LN_set_msgExt		"message extensions"
#define NID_set_msgExt		514
#define OBJ_set_msgExt		OBJ_id_set,1L

#define SN_set_attr		"set-attr"
#define NID_set_attr		515
#define OBJ_set_attr		OBJ_id_set,3L

#define SN_set_policy		"set-policy"
#define NID_set_policy		516
#define OBJ_set_policy		OBJ_id_set,5L

#define SN_set_certExt		"set-certExt"
#define LN_set_certExt		"certificate extensions"
#define NID_set_certExt		517
#define OBJ_set_certExt		OBJ_id_set,7L

#define SN_set_brand		"set-brand"
#define NID_set_brand		518
#define OBJ_set_brand		OBJ_id_set,8L

#define SN_setct_PANData		"setct-PANData"
#define NID_setct_PANData		519
#define OBJ_setct_PANData		OBJ_set_ctype,0L

#define SN_setct_PANToken		"setct-PANToken"
#define NID_setct_PANToken		520
#define OBJ_setct_PANToken		OBJ_set_ctype,1L

#define SN_setct_PANOnly		"setct-PANOnly"
#define NID_setct_PANOnly		521
#define OBJ_setct_PANOnly		OBJ_set_ctype,2L

#define SN_setct_OIData		"setct-OIData"
#define NID_setct_OIData		522
#define OBJ_setct_OIData		OBJ_set_ctype,3L

#define SN_setct_PI		"setct-PI"
#define NID_setct_PI		523
#define OBJ_setct_PI		OBJ_set_ctype,4L

#define SN_setct_PIData		"setct-PIData"
#define NID_setct_PIData		524
#define OBJ_setct_PIData		OBJ_set_ctype,5L

#define SN_setct_PIDataUnsigned		"setct-PIDataUnsigned"
#define NID_setct_PIDataUnsigned		525
#define OBJ_setct_PIDataUnsigned		OBJ_set_ctype,6L

#define SN_setct_HODInput		"setct-HODInput"
#define NID_setct_HODInput		526
#define OBJ_setct_HODInput		OBJ_set_ctype,7L

#define SN_setct_AuthResBaggage		"setct-AuthResBaggage"
#define NID_setct_AuthResBaggage		527
#define OBJ_setct_AuthResBaggage		OBJ_set_ctype,8L

#define SN_setct_AuthRevReqBaggage		"setct-AuthRevReqBaggage"
#define NID_setct_AuthRevReqBaggage		528
#define OBJ_setct_AuthRevReqBaggage		OBJ_set_ctype,9L

#define SN_setct_AuthRevResBaggage		"setct-AuthRevResBaggage"
#define NID_setct_AuthRevResBaggage		529
#define OBJ_setct_AuthRevResBaggage		OBJ_set_ctype,10L

#define SN_setct_CapTokenSeq		"setct-CapTokenSeq"
#define NID_setct_CapTokenSeq		530
#define OBJ_setct_CapTokenSeq		OBJ_set_ctype,11L

#define SN_setct_PInitResData		"setct-PInitResData"
#define NID_setct_PInitResData		531
#define OBJ_setct_PInitResData		OBJ_set_ctype,12L

#define SN_setct_PI_TBS		"setct-PI-TBS"
#define NID_setct_PI_TBS		532
#define OBJ_setct_PI_TBS		OBJ_set_ctype,13L

#define SN_setct_PResData		"setct-PResData"
#define NID_setct_PResData		533
#define OBJ_setct_PResData		OBJ_set_ctype,14L

#define SN_setct_AuthReqTBS		"setct-AuthReqTBS"
#define NID_setct_AuthReqTBS		534
#define OBJ_setct_AuthReqTBS		OBJ_set_ctype,16L

#define SN_setct_AuthResTBS		"setct-AuthResTBS"
#define NID_setct_AuthResTBS		535
#define OBJ_setct_AuthResTBS		OBJ_set_ctype,17L

#define SN_setct_AuthResTBSX		"setct-AuthResTBSX"
#define NID_setct_AuthResTBSX		536
#define OBJ_setct_AuthResTBSX		OBJ_set_ctype,18L

#define SN_setct_AuthTokenTBS		"setct-AuthTokenTBS"
#define NID_setct_AuthTokenTBS		537
#define OBJ_setct_AuthTokenTBS		OBJ_set_ctype,19L

#define SN_setct_CapTokenData		"setct-CapTokenData"
#define NID_setct_CapTokenData		538
#define OBJ_setct_CapTokenData		OBJ_set_ctype,20L

#define SN_setct_CapTokenTBS		"setct-CapTokenTBS"
#define NID_setct_CapTokenTBS		539
#define OBJ_setct_CapTokenTBS		OBJ_set_ctype,21L

#define SN_setct_AcqCardCodeMsg		"setct-AcqCardCodeMsg"
#define NID_setct_AcqCardCodeMsg		540
#define OBJ_setct_AcqCardCodeMsg		OBJ_set_ctype,22L

#define SN_setct_AuthRevReqTBS		"setct-AuthRevReqTBS"
#define NID_setct_AuthRevReqTBS		541
#define OBJ_setct_AuthRevReqTBS		OBJ_set_ctype,23L

#define SN_setct_AuthRevResData		"setct-AuthRevResData"
#define NID_setct_AuthRevResData		542
#define OBJ_setct_AuthRevResData		OBJ_set_ctype,24L

#define SN_setct_AuthRevResTBS		"setct-AuthRevResTBS"
#define NID_setct_AuthRevResTBS		543
#define OBJ_setct_AuthRevResTBS		OBJ_set_ctype,25L

#define SN_setct_CapReqTBS		"setct-CapReqTBS"
#define NID_setct_CapReqTBS		544
#define OBJ_setct_CapReqTBS		OBJ_set_ctype,26L

#define SN_setct_CapReqTBSX		"setct-CapReqTBSX"
#define NID_setct_CapReqTBSX		545
#define OBJ_setct_CapReqTBSX		OBJ_set_ctype,27L

#define SN_setct_CapResData		"setct-CapResData"
#define NID_setct_CapResData		546
#define OBJ_setct_CapResData		OBJ_set_ctype,28L

#define SN_setct_CapRevReqTBS		"setct-CapRevReqTBS"
#define NID_setct_CapRevReqTBS		547
#define OBJ_setct_CapRevReqTBS		OBJ_set_ctype,29L

#define SN_setct_CapRevReqTBSX		"setct-CapRevReqTBSX"
#define NID_setct_CapRevReqTBSX		548
#define OBJ_setct_CapRevReqTBSX		OBJ_set_ctype,30L

#define SN_setct_CapRevResData		"setct-CapRevResData"
#define NID_setct_CapRevResData		549
#define OBJ_setct_CapRevResData		OBJ_set_ctype,31L

#define SN_setct_CredReqTBS		"setct-CredReqTBS"
#define NID_setct_CredReqTBS		550
#define OBJ_setct_CredReqTBS		OBJ_set_ctype,32L

#define SN_setct_CredReqTBSX		"setct-CredReqTBSX"
#define NID_setct_CredReqTBSX		551
#define OBJ_setct_CredReqTBSX		OBJ_set_ctype,33L

#define SN_setct_CredResData		"setct-CredResData"
#define NID_setct_CredResData		552
#define OBJ_setct_CredResData		OBJ_set_ctype,34L

#define SN_setct_CredRevReqTBS		"setct-CredRevReqTBS"
#define NID_setct_CredRevReqTBS		553
#define OBJ_setct_CredRevReqTBS		OBJ_set_ctype,35L

#define SN_setct_CredRevReqTBSX		"setct-CredRevReqTBSX"
#define NID_setct_CredRevReqTBSX		554
#define OBJ_setct_CredRevReqTBSX		OBJ_set_ctype,36L

#define SN_setct_CredRevResData		"setct-CredRevResData"
#define NID_setct_CredRevResData		555
#define OBJ_setct_CredRevResData		OBJ_set_ctype,37L

#define SN_setct_PCertReqData		"setct-PCertReqData"
#define NID_setct_PCertReqData		556
#define OBJ_setct_PCertReqData		OBJ_set_ctype,38L

#define SN_setct_PCertResTBS		"setct-PCertResTBS"
#define NID_setct_PCertResTBS		557
#define OBJ_setct_PCertResTBS		OBJ_set_ctype,39L

#define SN_setct_BatchAdminReqData		"setct-BatchAdminReqData"
#define NID_setct_BatchAdminReqData		558
#define OBJ_setct_BatchAdminReqData		OBJ_set_ctype,40L

#define SN_setct_BatchAdminResData		"setct-BatchAdminResData"
#define NID_setct_BatchAdminResData		559
#define OBJ_setct_BatchAdminResData		OBJ_set_ctype,41L

#define SN_setct_CardCInitResTBS		"setct-CardCInitResTBS"
#define NID_setct_CardCInitResTBS		560
#define OBJ_setct_CardCInitResTBS		OBJ_set_ctype,42L

#define SN_setct_MeAqCInitResTBS		"setct-MeAqCInitResTBS"
#define NID_setct_MeAqCInitResTBS		561
#define OBJ_setct_MeAqCInitResTBS		OBJ_set_ctype,43L

#define SN_setct_RegFormResTBS		"setct-RegFormResTBS"
#define NID_setct_RegFormResTBS		562
#define OBJ_setct_RegFormResTBS		OBJ_set_ctype,44L

#define SN_setct_CertReqData		"setct-CertReqData"
#define NID_setct_CertReqData		563
#define OBJ_setct_CertReqData		OBJ_set_ctype,45L

#define SN_setct_CertReqTBS		"setct-CertReqTBS"
#define NID_setct_CertReqTBS		564
#define OBJ_setct_CertReqTBS		OBJ_set_ctype,46L

#define SN_setct_CertResData		"setct-CertResData"
#define NID_setct_CertResData		565
#define OBJ_setct_CertResData		OBJ_set_ctype,47L

#define SN_setct_CertInqReqTBS		"setct-CertInqReqTBS"
#define NID_setct_CertInqReqTBS		566
#define OBJ_setct_CertInqReqTBS		OBJ_set_ctype,48L

#define SN_setct_ErrorTBS		"setct-ErrorTBS"
#define NID_setct_ErrorTBS		567
#define OBJ_setct_ErrorTBS		OBJ_set_ctype,49L

#define SN_setct_PIDualSignedTBE		"setct-PIDualSignedTBE"
#define NID_setct_PIDualSignedTBE		568
#define OBJ_setct_PIDualSignedTBE		OBJ_set_ctype,50L

#define SN_setct_PIUnsignedTBE		"setct-PIUnsignedTBE"
#define NID_setct_PIUnsignedTBE		569
#define OBJ_setct_PIUnsignedTBE		OBJ_set_ctype,51L

#define SN_setct_AuthReqTBE		"setct-AuthReqTBE"
#define NID_setct_AuthReqTBE		570
#define OBJ_setct_AuthReqTBE		OBJ_set_ctype,52L

#define SN_setct_AuthResTBE		"setct-AuthResTBE"
#define NID_setct_AuthResTBE		571
#define OBJ_setct_AuthResTBE		OBJ_set_ctype,53L

#define SN_setct_AuthResTBEX		"setct-AuthResTBEX"
#define NID_setct_AuthResTBEX		572
#define OBJ_setct_AuthResTBEX		OBJ_set_ctype,54L

#define SN_setct_AuthTokenTBE		"setct-AuthTokenTBE"
#define NID_setct_AuthTokenTBE		573
#define OBJ_setct_AuthTokenTBE		OBJ_set_ctype,55L

#define SN_setct_CapTokenTBE		"setct-CapTokenTBE"
#define NID_setct_CapTokenTBE		574
#define OBJ_setct_CapTokenTBE		OBJ_set_ctype,56L

#define SN_setct_CapTokenTBEX		"setct-CapTokenTBEX"
#define NID_setct_CapTokenTBEX		575
#define OBJ_setct_CapTokenTBEX		OBJ_set_ctype,57L

#define SN_setct_AcqCardCodeMsgTBE		"setct-AcqCardCodeMsgTBE"
#define NID_setct_AcqCardCodeMsgTBE		576
#define OBJ_setct_AcqCardCodeMsgTBE		OBJ_set_ctype,58L

#define SN_setct_AuthRevReqTBE		"setct-AuthRevReqTBE"
#define NID_setct_AuthRevReqTBE		577
#define OBJ_setct_AuthRevReqTBE		OBJ_set_ctype,59L

#define SN_setct_AuthRevResTBE		"setct-AuthRevResTBE"
#define NID_setct_AuthRevResTBE		578
#define OBJ_setct_AuthRevResTBE		OBJ_set_ctype,60L

#define SN_setct_AuthRevResTBEB		"setct-AuthRevResTBEB"
#define NID_setct_AuthRevResTBEB		579
#define OBJ_setct_AuthRevResTBEB		OBJ_set_ctype,61L

#define SN_setct_CapReqTBE		"setct-CapReqTBE"
#define NID_setct_CapReqTBE		580
#define OBJ_setct_CapReqTBE		OBJ_set_ctype,62L

#define SN_setct_CapReqTBEX		"setct-CapReqTBEX"
#define NID_setct_CapReqTBEX		581
#define OBJ_setct_CapReqTBEX		OBJ_set_ctype,63L

#define SN_setct_CapResTBE		"setct-CapResTBE"
#define NID_setct_CapResTBE		582
#define OBJ_setct_CapResTBE		OBJ_set_ctype,64L

#define SN_setct_CapRevReqTBE		"setct-CapRevReqTBE"
#define NID_setct_CapRevReqTBE		583
#define OBJ_setct_CapRevReqTBE		OBJ_set_ctype,65L

#define SN_setct_CapRevReqTBEX		"setct-CapRevReqTBEX"
#define NID_setct_CapRevReqTBEX		584
#define OBJ_setct_CapRevReqTBEX		OBJ_set_ctype,66L

#define SN_setct_CapRevResTBE		"setct-CapRevResTBE"
#define NID_setct_CapRevResTBE		585
#define OBJ_setct_CapRevResTBE		OBJ_set_ctype,67L

#define SN_setct_CredReqTBE		"setct-CredReqTBE"
#define NID_setct_CredReqTBE		586
#define OBJ_setct_CredReqTBE		OBJ_set_ctype,68L

#define SN_setct_CredReqTBEX		"setct-CredReqTBEX"
#define NID_setct_CredReqTBEX		587
#define OBJ_setct_CredReqTBEX		OBJ_set_ctype,69L

#define SN_setct_CredResTBE		"setct-CredResTBE"
#define NID_setct_CredResTBE		588
#define OBJ_setct_CredResTBE		OBJ_set_ctype,70L

#define SN_setct_CredRevReqTBE		"setct-CredRevReqTBE"
#define NID_setct_CredRevReqTBE		589
#define OBJ_setct_CredRevReqTBE		OBJ_set_ctype,71L

#define SN_setct_CredRevReqTBEX		"setct-CredRevReqTBEX"
#define NID_setct_CredRevReqTBEX		590
#define OBJ_setct_CredRevReqTBEX		OBJ_set_ctype,72L

#define SN_setct_CredRevResTBE		"setct-CredRevResTBE"
#define NID_setct_CredRevResTBE		591
#define OBJ_setct_CredRevResTBE		OBJ_set_ctype,73L

#define SN_setct_BatchAdminReqTBE		"setct-BatchAdminReqTBE"
#define NID_setct_BatchAdminReqTBE		592
#define OBJ_setct_BatchAdminReqTBE		OBJ_set_ctype,74L

#define SN_setct_BatchAdminResTBE		"setct-BatchAdminResTBE"
#define NID_setct_BatchAdminResTBE		593
#define OBJ_setct_BatchAdminResTBE		OBJ_set_ctype,75L

#define SN_setct_RegFormReqTBE		"setct-RegFormReqTBE"
#define NID_setct_RegFormReqTBE		594
#define OBJ_setct_RegFormReqTBE		OBJ_set_ctype,76L

#define SN_setct_CertReqTBE		"setct-CertReqTBE"
#define NID_setct_CertReqTBE		595
#define OBJ_setct_CertReqTBE		OBJ_set_ctype,77L

#define SN_setct_CertReqTBEX		"setct-CertReqTBEX"
#define NID_setct_CertReqTBEX		596
#define OBJ_setct_CertReqTBEX		OBJ_set_ctype,78L

#define SN_setct_CertResTBE		"setct-CertResTBE"
#define NID_setct_CertResTBE		597
#define OBJ_setct_CertResTBE		OBJ_set_ctype,79L

#define SN_setct_CRLNotificationTBS		"setct-CRLNotificationTBS"
#define NID_setct_CRLNotificationTBS		598
#define OBJ_setct_CRLNotificationTBS		OBJ_set_ctype,80L

#define SN_setct_CRLNotificationResTBS		"setct-CRLNotificationResTBS"
#define NID_setct_CRLNotificationResTBS		599
#define OBJ_setct_CRLNotificationResTBS		OBJ_set_ctype,81L

#define SN_setct_BCIDistributionTBS		"setct-BCIDistributionTBS"
#define NID_setct_BCIDistributionTBS		600
#define OBJ_setct_BCIDistributionTBS		OBJ_set_ctype,82L

#define SN_setext_genCrypt		"setext-genCrypt"
#define LN_setext_genCrypt		"generic cryptogram"
#define NID_setext_genCrypt		601
#define OBJ_setext_genCrypt		OBJ_set_msgExt,1L

#define SN_setext_miAuth		"setext-miAuth"
#define LN_setext_miAuth		"merchant initiated auth"
#define NID_setext_miAuth		602
#define OBJ_setext_miAuth		OBJ_set_msgExt,3L

#define SN_setext_pinSecure		"setext-pinSecure"
#define NID_setext_pinSecure		603
#define OBJ_setext_pinSecure		OBJ_set_msgExt,4L

#define SN_setext_pinAny		"setext-pinAny"
#define NID_setext_pinAny		604
#define OBJ_setext_pinAny		OBJ_set_msgExt,5L

#define SN_setext_track2		"setext-track2"
#define NID_setext_track2		605
#define OBJ_setext_track2		OBJ_set_msgExt,7L

#define SN_setext_cv		"setext-cv"
#define LN_setext_cv		"additional verification"
#define NID_setext_cv		606
#define OBJ_setext_cv		OBJ_set_msgExt,8L

#define SN_set_policy_root		"set-policy-root"
#define NID_set_policy_root		607
#define OBJ_set_policy_root		OBJ_set_policy,0L

#define SN_setCext_hashedRoot		"setCext-hashedRoot"
#define NID_setCext_hashedRoot		608
#define OBJ_setCext_hashedRoot		OBJ_set_certExt,0L

#define SN_setCext_certType		"setCext-certType"
#define NID_setCext_certType		609
#define OBJ_setCext_certType		OBJ_set_certExt,1L

#define SN_setCext_merchData		"setCext-merchData"
#define NID_setCext_merchData		610
#define OBJ_setCext_merchData		OBJ_set_certExt,2L

#define SN_setCext_cCertRequired		"setCext-cCertRequired"
#define NID_setCext_cCertRequired		611
#define OBJ_setCext_cCertRequired		OBJ_set_certExt,3L

#define SN_setCext_tunneling		"setCext-tunneling"
#define NID_setCext_tunneling		612
#define OBJ_setCext_tunneling		OBJ_set_certExt,4L

#define SN_setCext_setExt		"setCext-setExt"
#define NID_setCext_setExt		613
#define OBJ_setCext_setExt		OBJ_set_certExt,5L

#define SN_setCext_setQualf		"setCext-setQualf"
#define NID_setCext_setQualf		614
#define OBJ_setCext_setQualf		OBJ_set_certExt,6L

#define SN_setCext_PGWYcapabilities		"setCext-PGWYcapabilities"
#define NID_setCext_PGWYcapabilities		615
#define OBJ_setCext_PGWYcapabilities		OBJ_set_certExt,7L

#define SN_setCext_TokenIdentifier		"setCext-TokenIdentifier"
#define NID_setCext_TokenIdentifier		616
#define OBJ_setCext_TokenIdentifier		OBJ_set_certExt,8L

#define SN_setCext_Track2Data		"setCext-Track2Data"
#define NID_setCext_Track2Data		617
#define OBJ_setCext_Track2Data		OBJ_set_certExt,9L

#define SN_setCext_TokenType		"setCext-TokenType"
#define NID_setCext_TokenType		618
#define OBJ_setCext_TokenType		OBJ_set_certExt,10L

#define SN_setCext_IssuerCapabilities		"setCext-IssuerCapabilities"
#define NID_setCext_IssuerCapabilities		619
#define OBJ_setCext_IssuerCapabilities		OBJ_set_certExt,11L

#define SN_setAttr_Cert		"setAttr-Cert"
#define NID_setAttr_Cert		620
#define OBJ_setAttr_Cert		OBJ_set_attr,0L

#define SN_setAttr_PGWYcap		"setAttr-PGWYcap"
#define LN_setAttr_PGWYcap		"payment gateway capabilities"
#define NID_setAttr_PGWYcap		621
#define OBJ_setAttr_PGWYcap		OBJ_set_attr,1L

#define SN_setAttr_TokenType		"setAttr-TokenType"
#define NID_setAttr_TokenType		622
#define OBJ_setAttr_TokenType		OBJ_set_attr,2L

#define SN_setAttr_IssCap		"setAttr-IssCap"
#define LN_setAttr_IssCap		"issuer capabilities"
#define NID_setAttr_IssCap		623
#define OBJ_setAttr_IssCap		OBJ_set_attr,3L

#define SN_set_rootKeyThumb		"set-rootKeyThumb"
#define NID_set_rootKeyThumb		624
#define OBJ_set_rootKeyThumb		OBJ_setAttr_Cert,0L

#define SN_set_addPolicy		"set-addPolicy"
#define NID_set_addPolicy		625
#define OBJ_set_addPolicy		OBJ_setAttr_Cert,1L

#define SN_setAttr_Token_EMV		"setAttr-Token-EMV"
#define NID_setAttr_Token_EMV		626
#define OBJ_setAttr_Token_EMV		OBJ_setAttr_TokenType,1L

#define SN_setAttr_Token_B0Prime		"setAttr-Token-B0Prime"
#define NID_setAttr_Token_B0Prime		627
#define OBJ_setAttr_Token_B0Prime		OBJ_setAttr_TokenType,2L

#define SN_setAttr_IssCap_CVM		"setAttr-IssCap-CVM"
#define NID_setAttr_IssCap_CVM		628
#define OBJ_setAttr_IssCap_CVM		OBJ_setAttr_IssCap,3L

#define SN_setAttr_IssCap_T2		"setAttr-IssCap-T2"
#define NID_setAttr_IssCap_T2		629
#define OBJ_setAttr_IssCap_T2		OBJ_setAttr_IssCap,4L

#define SN_setAttr_IssCap_Sig		"setAttr-IssCap-Sig"
#define NID_setAttr_IssCap_Sig		630
#define OBJ_setAttr_IssCap_Sig		OBJ_setAttr_IssCap,5L

#define SN_setAttr_GenCryptgrm		"setAttr-GenCryptgrm"
#define LN_setAttr_GenCryptgrm		"generate cryptogram"
#define NID_setAttr_GenCryptgrm		631
#define OBJ_setAttr_GenCryptgrm		OBJ_setAttr_IssCap_CVM,1L

#define SN_setAttr_T2Enc		"setAttr-T2Enc"
#define LN_setAttr_T2Enc		"encrypted track 2"
#define NID_setAttr_T2Enc		632
#define OBJ_setAttr_T2Enc		OBJ_setAttr_IssCap_T2,1L

#define SN_setAttr_T2cleartxt		"setAttr-T2cleartxt"
#define LN_setAttr_T2cleartxt		"cleartext track 2"
#define NID_setAttr_T2cleartxt		633
#define OBJ_setAttr_T2cleartxt		OBJ_setAttr_IssCap_T2,2L

#define SN_setAttr_TokICCsig		"setAttr-TokICCsig"
#define LN_setAttr_TokICCsig		"ICC or token signature"
#define NID_setAttr_TokICCsig		634
#define OBJ_setAttr_TokICCsig		OBJ_setAttr_IssCap_Sig,1L

#define SN_setAttr_SecDevSig		"setAttr-SecDevSig"
#define LN_setAttr_SecDevSig		"secure device signature"
#define NID_setAttr_SecDevSig		635
#define OBJ_setAttr_SecDevSig		OBJ_setAttr_IssCap_Sig,2L

#define SN_set_brand_IATA_ATA		"set-brand-IATA-ATA"
#define NID_set_brand_IATA_ATA		636
#define OBJ_set_brand_IATA_ATA		OBJ_set_brand,1L

#define SN_set_brand_Diners		"set-brand-Diners"
#define NID_set_brand_Diners		637
#define OBJ_set_brand_Diners		OBJ_set_brand,30L

#define SN_set_brand_AmericanExpress		"set-brand-AmericanExpress"
#define NID_set_brand_AmericanExpress		638
#define OBJ_set_brand_AmericanExpress		OBJ_set_brand,34L

#define SN_set_brand_JCB		"set-brand-JCB"
#define NID_set_brand_JCB		639
#define OBJ_set_brand_JCB		OBJ_set_brand,35L

#define SN_set_brand_Visa		"set-brand-Visa"
#define NID_set_brand_Visa		640
#define OBJ_set_brand_Visa		OBJ_set_brand,4L

#define SN_set_brand_MasterCard		"set-brand-MasterCard"
#define NID_set_brand_MasterCard		641
#define OBJ_set_brand_MasterCard		OBJ_set_brand,5L

#define SN_set_brand_Novus		"set-brand-Novus"
#define NID_set_brand_Novus		642
#define OBJ_set_brand_Novus		OBJ_set_brand,6011L

#define SN_des_cdmf		"DES-CDMF"
#define LN_des_cdmf		"des-cdmf"
#define NID_des_cdmf		643
#define OBJ_des_cdmf		OBJ_rsadsi,3L,10L

#define SN_rsaOAEPEncryptionSET		"rsaOAEPEncryptionSET"
#define NID_rsaOAEPEncryptionSET		644
#define OBJ_rsaOAEPEncryptionSET		OBJ_rsadsi,1L,1L,6L

#define SN_ipsec3		"Oakley-EC2N-3"
#define LN_ipsec3		"ipsec3"
#define NID_ipsec3		749

#define SN_ipsec4		"Oakley-EC2N-4"
#define LN_ipsec4		"ipsec4"
#define NID_ipsec4		750

#define SN_whirlpool		"whirlpool"
#define NID_whirlpool		804
#define OBJ_whirlpool		OBJ_iso,0L,10118L,3L,0L,55L

#define SN_cryptopro		"cryptopro"
#define NID_cryptopro		805
#define OBJ_cryptopro		OBJ_member_body,643L,2L,2L

#define SN_cryptocom		"cryptocom"
#define NID_cryptocom		806
#define OBJ_cryptocom		OBJ_member_body,643L,2L,9L

#define SN_id_GostR3411_94_with_GostR3410_2001		"id-GostR3411-94-with-GostR3410-2001"
#define LN_id_GostR3411_94_with_GostR3410_2001		"GOST R 34.11-94 with GOST R 34.10-2001"
#define NID_id_GostR3411_94_with_GostR3410_2001		807
#define OBJ_id_GostR3411_94_with_GostR3410_2001		OBJ_cryptopro,3L

#define SN_id_GostR3411_94_with_GostR3410_94		"id-GostR3411-94-with-GostR3410-94"
#define LN_id_GostR3411_94_with_GostR3410_94		"GOST R 34.11-94 with GOST R 34.10-94"
#define NID_id_GostR3411_94_with_GostR3410_94		808
#define OBJ_id_GostR3411_94_with_GostR3410_94		OBJ_cryptopro,4L

#define SN_id_GostR3411_94		"md_gost94"
#define LN_id_GostR3411_94		"GOST R 34.11-94"
#define NID_id_GostR3411_94		809
#define OBJ_id_GostR3411_94		OBJ_cryptopro,9L

#define SN_id_HMACGostR3411_94		"id-HMACGostR3411-94"
#define LN_id_HMACGostR3411_94		"HMAC GOST 34.11-94"
#define NID_id_HMACGostR3411_94		810
#define OBJ_id_HMACGostR3411_94		OBJ_cryptopro,10L

#define SN_id_GostR3410_2001		"gost2001"
#define LN_id_GostR3410_2001		"GOST R 34.10-2001"
#define NID_id_GostR3410_2001		811
#define OBJ_id_GostR3410_2001		OBJ_cryptopro,19L

#define SN_id_GostR3410_94		"gost94"
#define LN_id_GostR3410_94		"GOST R 34.10-94"
#define NID_id_GostR3410_94		812
#define OBJ_id_GostR3410_94		OBJ_cryptopro,20L

#define SN_id_Gost28147_89		"gost89"
#define LN_id_Gost28147_89		"GOST 28147-89"
#define NID_id_Gost28147_89		813
#define OBJ_id_Gost28147_89		OBJ_cryptopro,21L

#define SN_gost89_cnt		"gost89-cnt"
#define NID_gost89_cnt		814

#define SN_id_Gost28147_89_MAC		"gost-mac"
#define LN_id_Gost28147_89_MAC		"GOST 28147-89 MAC"
#define NID_id_Gost28147_89_MAC		815
#define OBJ_id_Gost28147_89_MAC		OBJ_cryptopro,22L

#define SN_id_GostR3411_94_prf		"prf-gostr3411-94"
#define LN_id_GostR3411_94_prf		"GOST R 34.11-94 PRF"
#define NID_id_GostR3411_94_prf		816
#define OBJ_id_GostR3411_94_prf		OBJ_cryptopro,23L

#define SN_id_GostR3410_2001DH		"id-GostR3410-2001DH"
#define LN_id_GostR3410_2001DH		"GOST R 34.10-2001 DH"
#define NID_id_GostR3410_2001DH		817
#define OBJ_id_GostR3410_2001DH		OBJ_cryptopro,98L

#define SN_id_GostR3410_94DH		"id-GostR3410-94DH"
#define LN_id_GostR3410_94DH		"GOST R 34.10-94 DH"
#define NID_id_GostR3410_94DH		818
#define OBJ_id_GostR3410_94DH		OBJ_cryptopro,99L

#define SN_id_Gost28147_89_CryptoPro_KeyMeshing		"id-Gost28147-89-CryptoPro-KeyMeshing"
#define NID_id_Gost28147_89_CryptoPro_KeyMeshing		819
#define OBJ_id_Gost28147_89_CryptoPro_KeyMeshing		OBJ_cryptopro,14L,1L

#define SN_id_Gost28147_89_None_KeyMeshing		"id-Gost28147-89-None-KeyMeshing"
#define NID_id_Gost28147_89_None_KeyMeshing		820
#define OBJ_id_Gost28147_89_None_KeyMeshing		OBJ_cryptopro,14L,0L

#define SN_id_GostR3411_94_TestParamSet		"id-GostR3411-94-TestParamSet"
#define NID_id_GostR3411_94_TestParamSet		821
#define OBJ_id_GostR3411_94_TestParamSet		OBJ_cryptopro,30L,0L

#define SN_id_GostR3411_94_CryptoProParamSet		"id-GostR3411-94-CryptoProParamSet"
#define NID_id_GostR3411_94_CryptoProParamSet		822
#define OBJ_id_GostR3411_94_CryptoProParamSet		OBJ_cryptopro,30L,1L

#define SN_id_Gost28147_89_TestParamSet		"id-Gost28147-89-TestParamSet"
#define NID_id_Gost28147_89_TestParamSet		823
#define OBJ_id_Gost28147_89_TestParamSet		OBJ_cryptopro,31L,0L

#define SN_id_Gost28147_89_CryptoPro_A_ParamSet		"id-Gost28147-89-CryptoPro-A-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_A_ParamSet		824
#define OBJ_id_Gost28147_89_CryptoPro_A_ParamSet		OBJ_cryptopro,31L,1L

#define SN_id_Gost28147_89_CryptoPro_B_ParamSet		"id-Gost28147-89-CryptoPro-B-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_B_ParamSet		825
#define OBJ_id_Gost28147_89_CryptoPro_B_ParamSet		OBJ_cryptopro,31L,2L

#define SN_id_Gost28147_89_CryptoPro_C_ParamSet		"id-Gost28147-89-CryptoPro-C-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_C_ParamSet		826
#define OBJ_id_Gost28147_89_CryptoPro_C_ParamSet		OBJ_cryptopro,31L,3L

#define SN_id_Gost28147_89_CryptoPro_D_ParamSet		"id-Gost28147-89-CryptoPro-D-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_D_ParamSet		827
#define OBJ_id_Gost28147_89_CryptoPro_D_ParamSet		OBJ_cryptopro,31L,4L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet		"id-Gost28147-89-CryptoPro-Oscar-1-1-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet		828
#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet		OBJ_cryptopro,31L,5L

#define SN_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet		"id-Gost28147-89-CryptoPro-Oscar-1-0-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet		829
#define OBJ_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet		OBJ_cryptopro,31L,6L

#define SN_id_Gost28147_89_CryptoPro_RIC_1_ParamSet		"id-Gost28147-89-CryptoPro-RIC-1-ParamSet"
#define NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet		830
#define OBJ_id_Gost28147_89_CryptoPro_RIC_1_ParamSet		OBJ_cryptopro,31L,7L

#define SN_id_GostR3410_94_TestParamSet		"id-GostR3410-94-TestParamSet"
#define NID_id_GostR3410_94_TestParamSet		831
#define OBJ_id_GostR3410_94_TestParamSet		OBJ_cryptopro,32L,0L

#define SN_id_GostR3410_94_CryptoPro_A_ParamSet		"id-GostR3410-94-CryptoPro-A-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_A_ParamSet		832
#define OBJ_id_GostR3410_94_CryptoPro_A_ParamSet		OBJ_cryptopro,32L,2L

#define SN_id_GostR3410_94_CryptoPro_B_ParamSet		"id-GostR3410-94-CryptoPro-B-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_B_ParamSet		833
#define OBJ_id_GostR3410_94_CryptoPro_B_ParamSet		OBJ_cryptopro,32L,3L

#define SN_id_GostR3410_94_CryptoPro_C_ParamSet		"id-GostR3410-94-CryptoPro-C-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_C_ParamSet		834
#define OBJ_id_GostR3410_94_CryptoPro_C_ParamSet		OBJ_cryptopro,32L,4L

#define SN_id_GostR3410_94_CryptoPro_D_ParamSet		"id-GostR3410-94-CryptoPro-D-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_D_ParamSet		835
#define OBJ_id_GostR3410_94_CryptoPro_D_ParamSet		OBJ_cryptopro,32L,5L

#define SN_id_GostR3410_94_CryptoPro_XchA_ParamSet		"id-GostR3410-94-CryptoPro-XchA-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_XchA_ParamSet		836
#define OBJ_id_GostR3410_94_CryptoPro_XchA_ParamSet		OBJ_cryptopro,33L,1L

#define SN_id_GostR3410_94_CryptoPro_XchB_ParamSet		"id-GostR3410-94-CryptoPro-XchB-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_XchB_ParamSet		837
#define OBJ_id_GostR3410_94_CryptoPro_XchB_ParamSet		OBJ_cryptopro,33L,2L

#define SN_id_GostR3410_94_CryptoPro_XchC_ParamSet		"id-GostR3410-94-CryptoPro-XchC-ParamSet"
#define NID_id_GostR3410_94_CryptoPro_XchC_ParamSet		838
#define OBJ_id_GostR3410_94_CryptoPro_XchC_ParamSet		OBJ_cryptopro,33L,3L

#define SN_id_GostR3410_2001_TestParamSet		"id-GostR3410-2001-TestParamSet"
#define NID_id_GostR3410_2001_TestParamSet		839
#define OBJ_id_GostR3410_2001_TestParamSet		OBJ_cryptopro,35L,0L

#define SN_id_GostR3410_2001_CryptoPro_A_ParamSet		"id-GostR3410-2001-CryptoPro-A-ParamSet"
#define NID_id_GostR3410_2001_CryptoPro_A_ParamSet		840
#define OBJ_id_GostR3410_2001_CryptoPro_A_ParamSet		OBJ_cryptopro,35L,1L

#define SN_id_GostR3410_2001_CryptoPro_B_ParamSet		"id-GostR3410-2001-CryptoPro-B-ParamSet"
#define NID_id_GostR3410_2001_CryptoPro_B_ParamSet		841
#define OBJ_id_GostR3410_2001_CryptoPro_B_ParamSet		OBJ_cryptopro,35L,2L

#define SN_id_GostR3410_2001_CryptoPro_C_ParamSet		"id-GostR3410-2001-CryptoPro-C-ParamSet"
#define NID_id_GostR3410_2001_CryptoPro_C_ParamSet		842
#define OBJ_id_GostR3410_2001_CryptoPro_C_ParamSet		OBJ_cryptopro,35L,3L

#define SN_id_GostR3410_2001_CryptoPro_XchA_ParamSet		"id-GostR3410-2001-CryptoPro-XchA-ParamSet"
#define NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet		843
#define OBJ_id_GostR3410_2001_CryptoPro_XchA_ParamSet		OBJ_cryptopro,36L,0L

#define SN_id_GostR3410_2001_CryptoPro_XchB_ParamSet		"id-GostR3410-2001-CryptoPro-XchB-ParamSet"
#define NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet		844
#define OBJ_id_GostR3410_2001_CryptoPro_XchB_ParamSet		OBJ_cryptopro,36L,1L

#define SN_id_GostR3410_94_a		"id-GostR3410-94-a"
#define NID_id_GostR3410_94_a		845
#define OBJ_id_GostR3410_94_a		OBJ_id_GostR3410_94,1L

#define SN_id_GostR3410_94_aBis		"id-GostR3410-94-aBis"
#define NID_id_GostR3410_94_aBis		846
#define OBJ_id_GostR3410_94_aBis		OBJ_id_GostR3410_94,2L

#define SN_id_GostR3410_94_b		"id-GostR3410-94-b"
#define NID_id_GostR3410_94_b		847
#define OBJ_id_GostR3410_94_b		OBJ_id_GostR3410_94,3L

#define SN_id_GostR3410_94_bBis		"id-GostR3410-94-bBis"
#define NID_id_GostR3410_94_bBis		848
#define OBJ_id_GostR3410_94_bBis		OBJ_id_GostR3410_94,4L

#define SN_id_Gost28147_89_cc		"id-Gost28147-89-cc"
#define LN_id_Gost28147_89_cc		"GOST 28147-89 Cryptocom ParamSet"
#define NID_id_Gost28147_89_cc		849
#define OBJ_id_Gost28147_89_cc		OBJ_cryptocom,1L,6L,1L

#define SN_id_GostR3410_94_cc		"gost94cc"
#define LN_id_GostR3410_94_cc		"GOST 34.10-94 Cryptocom"
#define NID_id_GostR3410_94_cc		850
#define OBJ_id_GostR3410_94_cc		OBJ_cryptocom,1L,5L,3L

#define SN_id_GostR3410_2001_cc		"gost2001cc"
#define LN_id_GostR3410_2001_cc		"GOST 34.10-2001 Cryptocom"
#define NID_id_GostR3410_2001_cc		851
#define OBJ_id_GostR3410_2001_cc		OBJ_cryptocom,1L,5L,4L

#define SN_id_GostR3411_94_with_GostR3410_94_cc		"id-GostR3411-94-with-GostR3410-94-cc"
#define LN_id_GostR3411_94_with_GostR3410_94_cc		"GOST R 34.11-94 with GOST R 34.10-94 Cryptocom"
#define NID_id_GostR3411_94_with_GostR3410_94_cc		852
#define OBJ_id_GostR3411_94_with_GostR3410_94_cc		OBJ_cryptocom,1L,3L,3L

#define SN_id_GostR3411_94_with_GostR3410_2001_cc		"id-GostR3411-94-with-GostR3410-2001-cc"
#define LN_id_GostR3411_94_with_GostR3410_2001_cc		"GOST R 34.11-94 with GOST R 34.10-2001 Cryptocom"
#define NID_id_GostR3411_94_with_GostR3410_2001_cc		853
#define OBJ_id_GostR3411_94_with_GostR3410_2001_cc		OBJ_cryptocom,1L,3L,4L

#define SN_id_GostR3410_2001_ParamSet_cc		"id-GostR3410-2001-ParamSet-cc"
#define LN_id_GostR3410_2001_ParamSet_cc		"GOST R 3410-2001 Parameter Set Cryptocom"
#define NID_id_GostR3410_2001_ParamSet_cc		854
#define OBJ_id_GostR3410_2001_ParamSet_cc		OBJ_cryptocom,1L,8L,1L

#define SN_camellia_128_cbc		"CAMELLIA-128-CBC"
#define LN_camellia_128_cbc		"camellia-128-cbc"
#define NID_camellia_128_cbc		751
#define OBJ_camellia_128_cbc		1L,2L,392L,200011L,61L,1L,1L,1L,2L

#define SN_camellia_192_cbc		"CAMELLIA-192-CBC"
#define LN_camellia_192_cbc		"camellia-192-cbc"
#define NID_camellia_192_cbc		752
#define OBJ_camellia_192_cbc		1L,2L,392L,200011L,61L,1L,1L,1L,3L

#define SN_camellia_256_cbc		"CAMELLIA-256-CBC"
#define LN_camellia_256_cbc		"camellia-256-cbc"
#define NID_camellia_256_cbc		753
#define OBJ_camellia_256_cbc		1L,2L,392L,200011L,61L,1L,1L,1L,4L

#define OBJ_ntt_ds		0L,3L,4401L,5L

#define OBJ_camellia		OBJ_ntt_ds,3L,1L,9L

#define SN_camellia_128_ecb		"CAMELLIA-128-ECB"
#define LN_camellia_128_ecb		"camellia-128-ecb"
#define NID_camellia_128_ecb		754
#define OBJ_camellia_128_ecb		OBJ_camellia,1L

#define SN_camellia_128_ofb128		"CAMELLIA-128-OFB"
#define LN_camellia_128_ofb128		"camellia-128-ofb"
#define NID_camellia_128_ofb128		766
#define OBJ_camellia_128_ofb128		OBJ_camellia,3L

#define SN_camellia_128_cfb128		"CAMELLIA-128-CFB"
#define LN_camellia_128_cfb128		"camellia-128-cfb"
#define NID_camellia_128_cfb128		757
#define OBJ_camellia_128_cfb128		OBJ_camellia,4L

#define SN_camellia_192_ecb		"CAMELLIA-192-ECB"
#define LN_camellia_192_ecb		"camellia-192-ecb"
#define NID_camellia_192_ecb		755
#define OBJ_camellia_192_ecb		OBJ_camellia,21L

#define SN_camellia_192_ofb128		"CAMELLIA-192-OFB"
#define LN_camellia_192_ofb128		"camellia-192-ofb"
#define NID_camellia_192_ofb128		767
#define OBJ_camellia_192_ofb128		OBJ_camellia,23L

#define SN_camellia_192_cfb128		"CAMELLIA-192-CFB"
#define LN_camellia_192_cfb128		"camellia-192-cfb"
#define NID_camellia_192_cfb128		758
#define OBJ_camellia_192_cfb128		OBJ_camellia,24L

#define SN_camellia_256_ecb		"CAMELLIA-256-ECB"
#define LN_camellia_256_ecb		"camellia-256-ecb"
#define NID_camellia_256_ecb		756
#define OBJ_camellia_256_ecb		OBJ_camellia,41L

#define SN_camellia_256_ofb128		"CAMELLIA-256-OFB"
#define LN_camellia_256_ofb128		"camellia-256-ofb"
#define NID_camellia_256_ofb128		768
#define OBJ_camellia_256_ofb128		OBJ_camellia,43L

#define SN_camellia_256_cfb128		"CAMELLIA-256-CFB"
#define LN_camellia_256_cfb128		"camellia-256-cfb"
#define NID_camellia_256_cfb128		759
#define OBJ_camellia_256_cfb128		OBJ_camellia,44L

#define SN_camellia_128_cfb1		"CAMELLIA-128-CFB1"
#define LN_camellia_128_cfb1		"camellia-128-cfb1"
#define NID_camellia_128_cfb1		760

#define SN_camellia_192_cfb1		"CAMELLIA-192-CFB1"
#define LN_camellia_192_cfb1		"camellia-192-cfb1"
#define NID_camellia_192_cfb1		761

#define SN_camellia_256_cfb1		"CAMELLIA-256-CFB1"
#define LN_camellia_256_cfb1		"camellia-256-cfb1"
#define NID_camellia_256_cfb1		762

#define SN_camellia_128_cfb8		"CAMELLIA-128-CFB8"
#define LN_camellia_128_cfb8		"camellia-128-cfb8"
#define NID_camellia_128_cfb8		763

#define SN_camellia_192_cfb8		"CAMELLIA-192-CFB8"
#define LN_camellia_192_cfb8		"camellia-192-cfb8"
#define NID_camellia_192_cfb8		764

#define SN_camellia_256_cfb8		"CAMELLIA-256-CFB8"
#define LN_camellia_256_cfb8		"camellia-256-cfb8"
#define NID_camellia_256_cfb8		765

#define SN_kisa		"KISA"
#define LN_kisa		"kisa"
#define NID_kisa		773
#define OBJ_kisa		OBJ_member_body,410L,200004L

#define SN_seed_ecb		"SEED-ECB"
#define LN_seed_ecb		"seed-ecb"
#define NID_seed_ecb		776
#define OBJ_seed_ecb		OBJ_kisa,1L,3L

#define SN_seed_cbc		"SEED-CBC"
#define LN_seed_cbc		"seed-cbc"
#define NID_seed_cbc		777
#define OBJ_seed_cbc		OBJ_kisa,1L,4L

#define SN_seed_cfb128		"SEED-CFB"
#define LN_seed_cfb128		"seed-cfb"
#define NID_seed_cfb128		779
#define OBJ_seed_cfb128		OBJ_kisa,1L,5L

#define SN_seed_ofb128		"SEED-OFB"
#define LN_seed_ofb128		"seed-ofb"
#define NID_seed_ofb128		778
#define OBJ_seed_ofb128		OBJ_kisa,1L,6L

#define SN_hmac		"HMAC"
#define LN_hmac		"hmac"
#define NID_hmac		855

#define USE_OBJ_MAC

#define SN_undef			"UNDEF"
#define LN_undef			"undefined"
#define NID_undef			0
#define OBJ_undef			0L

#define SN_Algorithm			"Algorithm"
#define LN_algorithm			"algorithm"
#define NID_algorithm			38
#define OBJ_algorithm			1L,3L,14L,3L,2L

#define LN_rsadsi			"rsadsi"
#define NID_rsadsi			1
#define OBJ_rsadsi			1L,2L,840L,113549L

#define LN_pkcs				"pkcs"
#define NID_pkcs			2
#define OBJ_pkcs			OBJ_rsadsi,1L

#define SN_md2				"MD2"
#define LN_md2				"md2"
#define NID_md2				3
#define OBJ_md2				OBJ_rsadsi,2L,2L

#define SN_md5				"MD5"
#define LN_md5				"md5"
#define NID_md5				4
#define OBJ_md5				OBJ_rsadsi,2L,5L

#define SN_rc4				"RC4"
#define LN_rc4				"rc4"
#define NID_rc4				5
#define OBJ_rc4				OBJ_rsadsi,3L,4L

#define LN_rsaEncryption		"rsaEncryption"
#define NID_rsaEncryption		1
#define OBJ_rsaEncryption		OBJ_pkcs,1L,1L

#define SN_md2WithRSAEncryption		"RSA-MD2"
#define LN_md2WithRSAEncryption		"md2WithRSAEncryption"
#define NID_md2WithRSAEncryption	7
#define OBJ_md2WithRSAEncryption	OBJ_pkcs,1L,2L

#define SN_md5WithRSAEncryption		"RSA-MD5"
#define LN_md5WithRSAEncryption		"md5WithRSAEncryption"
#define NID_md5WithRSAEncryption	8
#define OBJ_md5WithRSAEncryption	OBJ_pkcs,1L,4L

#define SN_pbeWithMD2AndDES_CBC		"PBE-MD2-DES"
#define LN_pbeWithMD2AndDES_CBC		"pbeWithMD2AndDES-CBC"
#define NID_pbeWithMD2AndDES_CBC	9
#define OBJ_pbeWithMD2AndDES_CBC	OBJ_pkcs,5L,1L

#define SN_pbeWithMD5AndDES_CBC		"PBE-MD5-DES"
#define LN_pbeWithMD5AndDES_CBC		"pbeWithMD5AndDES-CBC"
#define NID_pbeWithMD5AndDES_CBC	10
#define OBJ_pbeWithMD5AndDES_CBC	OBJ_pkcs,5L,3L

#define LN_X500				"X500"
#define NID_X500			11
#define OBJ_X500			2L,5L

#define LN_X509				"X509"
#define NID_X509			12
#define OBJ_X509			OBJ_X500,4L

#define SN_commonName			"CN"
#define LN_commonName			"commonName"
#define NID_commonName			13
#define OBJ_commonName			OBJ_X509,3L

#define SN_countryName			"C"
#define LN_countryName			"countryName"
#define NID_countryName			14
#define OBJ_countryName			OBJ_X509,6L

#define SN_localityName			"L"
#define LN_localityName			"localityName"
#define NID_localityName		15
#define OBJ_localityName		OBJ_X509,7L

/* Postal Address? PA */

/* should be "ST" (rfc1327) but MS uses 'S' */
#define SN_stateOrProvinceName		"ST"
#define LN_stateOrProvinceName		"stateOrProvinceName"
#define NID_stateOrProvinceName		16
#define OBJ_stateOrProvinceName		OBJ_X509,8L

#define SN_organizationName		"O"
#define LN_organizationName		"organizationName"
#define NID_organizationName		17
#define OBJ_organizationName		OBJ_X509,10L

#define SN_organizationalUnitName	"OU"
#define LN_organizationalUnitName	"organizationalUnitName"
#define NID_organizationalUnitName	18
#define OBJ_organizationalUnitName	OBJ_X509,11L

#define SN_rsa				"RSA"
#define LN_rsa				"rsa"
#define NID_rsa				19
#define OBJ_rsa				OBJ_X500,8L,1L,1L

#define LN_pkcs7			"pkcs7"
#define NID_pkcs7			20
#define OBJ_pkcs7			OBJ_pkcs,7L

#define LN_pkcs7_data			"pkcs7-data"
#define NID_pkcs7_data			21
#define OBJ_pkcs7_data			OBJ_pkcs7,1L

#define LN_pkcs7_signed			"pkcs7-signedData"
#define NID_pkcs7_signed		22
#define OBJ_pkcs7_signed		OBJ_pkcs7,2L

#define LN_pkcs7_enveloped		"pkcs7-envelopedData"
#define NID_pkcs7_enveloped		23
#define OBJ_pkcs7_enveloped		OBJ_pkcs7,3L

#define LN_pkcs7_signedAndEnveloped	"pkcs7-signedAndEnvelopedData"
#define NID_pkcs7_signedAndEnveloped	24
#define OBJ_pkcs7_signedAndEnveloped	OBJ_pkcs7,4L

#define LN_pkcs7_digest			"pkcs7-digestData"
#define NID_pkcs7_digest		25
#define OBJ_pkcs7_digest		OBJ_pkcs7,5L

#define LN_pkcs7_encrypted		"pkcs7-encryptedData"
#define NID_pkcs7_encrypted		26
#define OBJ_pkcs7_encrypted		OBJ_pkcs7,6L

#define LN_pkcs3			"pkcs3"
#define NID_pkcs3			27
#define OBJ_pkcs3			OBJ_pkcs,3L

#define LN_dhKeyAgreement		"dhKeyAgreement"
#define NID_dhKeyAgreement		28
#define OBJ_dhKeyAgreement		OBJ_pkcs3,1L

#define SN_des_ecb			"DES-ECB"
#define LN_des_ecb			"des-ecb"
#define NID_des_ecb			29
#define OBJ_des_ecb			OBJ_algorithm,6L

#define SN_des_cfb64			"DES-CFB"
#define LN_des_cfb64			"des-cfb"
#define NID_des_cfb64			30
/* IV + num */
#define OBJ_des_cfb64			OBJ_algorithm,9L

#define SN_des_cbc			"DES-CBC"
#define LN_des_cbc			"des-cbc"
#define NID_des_cbc			31
/* IV */
#define OBJ_des_cbc			OBJ_algorithm,7L

#define SN_des_ede			"DES-EDE"
#define LN_des_ede			"des-ede"
#define NID_des_ede			32
/* ?? */
#define OBJ_des_ede			OBJ_algorithm,17L

#define SN_des_ede3			"DES-EDE3"
#define LN_des_ede3			"des-ede3"
#define NID_des_ede3			33

#define SN_idea_cbc			"IDEA-CBC"
#define LN_idea_cbc			"idea-cbc"
#define NID_idea_cbc			34
#define OBJ_idea_cbc			1L,3L,6L,1L,4L,1L,188L,7L,1L,1L,2L

#define SN_idea_cfb64			"IDEA-CFB"
#define LN_idea_cfb64			"idea-cfb"
#define NID_idea_cfb64			35

#define SN_idea_ecb			"IDEA-ECB"
#define LN_idea_ecb			"idea-ecb"
#define NID_idea_ecb			36

#define SN_rc2_cbc			"RC2-CBC"
#define LN_rc2_cbc			"rc2-cbc"
#define NID_rc2_cbc			37
#define OBJ_rc2_cbc			OBJ_rsadsi,3L,2L

#define SN_rc2_ecb			"RC2-ECB"
#define LN_rc2_ecb			"rc2-ecb"
#define NID_rc2_ecb			38

#define SN_rc2_cfb64			"RC2-CFB"
#define LN_rc2_cfb64			"rc2-cfb"
#define NID_rc2_cfb64			39

#define SN_rc2_ofb64			"RC2-OFB"
#define LN_rc2_ofb64			"rc2-ofb"
#define NID_rc2_ofb64			40

#define SN_sha				"SHA"
#define LN_sha				"sha"
#define NID_sha				41
#define OBJ_sha				OBJ_algorithm,18L

#define SN_shaWithRSAEncryption		"RSA-SHA"
#define LN_shaWithRSAEncryption		"shaWithRSAEncryption"
#define NID_shaWithRSAEncryption	42
#define OBJ_shaWithRSAEncryption	OBJ_algorithm,15L

#define SN_des_ede_cbc			"DES-EDE-CBC"
#define LN_des_ede_cbc			"des-ede-cbc"
#define NID_des_ede_cbc			43

#define SN_des_ede3_cbc			"DES-EDE3-CBC"
#define LN_des_ede3_cbc			"des-ede3-cbc"
#define NID_des_ede3_cbc		44
#define OBJ_des_ede3_cbc		OBJ_rsadsi,3L,7L

#define SN_des_ofb64			"DES-OFB"
#define LN_des_ofb64			"des-ofb"
#define NID_des_ofb64			45
#define OBJ_des_ofb64			OBJ_algorithm,8L

#define SN_idea_ofb64			"IDEA-OFB"
#define LN_idea_ofb64			"idea-ofb"
#define NID_idea_ofb64			46

#define LN_pkcs9			"pkcs9"
#define NID_pkcs9			47
#define OBJ_pkcs9			OBJ_pkcs,9L

#define SN_pkcs9_emailAddress		"Email"
#define LN_pkcs9_emailAddress		"emailAddress"
#define NID_pkcs9_emailAddress		48
#define OBJ_pkcs9_emailAddress		OBJ_pkcs9,1L

#define LN_pkcs9_unstructuredName	"unstructuredName"
#define NID_pkcs9_unstructuredName	49
#define OBJ_pkcs9_unstructuredName	OBJ_pkcs9,2L

#define LN_pkcs9_contentType		"contentType"
#define NID_pkcs9_contentType		50
#define OBJ_pkcs9_contentType		OBJ_pkcs9,3L

#define LN_pkcs9_messageDigest		"messageDigest"
#define NID_pkcs9_messageDigest		51
#define OBJ_pkcs9_messageDigest		OBJ_pkcs9,4L

#define LN_pkcs9_signingTime		"signingTime"
#define NID_pkcs9_signingTime		52
#define OBJ_pkcs9_signingTime		OBJ_pkcs9,5L

#define LN_pkcs9_countersignature		"countersignature"
#define NID_pkcs9_countersignature		53
#define OBJ_pkcs9_countersignature		OBJ_pkcs9,6L

#define LN_pkcs9_challengePassword		"challengePassword"
#define NID_pkcs9_challengePassword	54
#define OBJ_pkcs9_challengePassword	OBJ_pkcs9,7L

#define LN_pkcs9_unstructuredAddress	"unstructuredAddress"
#define NID_pkcs9_unstructuredAddress	55
#define OBJ_pkcs9_unstructuredAddress	OBJ_pkcs9,8L

#define LN_pkcs9_extCertAttributes	"extendedCertificateAttributes"
#define NID_pkcs9_extCertAttributes	56
#define OBJ_pkcs9_extCertAttributes	OBJ_pkcs9,9L

#define SN_netscape			"Netscape"
#define LN_netscape			"Netscape Communications Corp."
#define NID_netscape			2
#define OBJ_netscape			2L,16L,840L,1L,113730L
#define SN_netscape_cert_extension		"nsCertExt"
#define LN_netscape_cert_extension		"Netscape Certificate Extension"
#define NID_netscape_cert_extension	3
#define OBJ_netscape_cert_extension	OBJ_netscape,1L

#define SN_netscape_data_type		"nsDataType"
#define LN_netscape_data_type		"Netscape Data Type"
#define NID_netscape_data_type		59
#define OBJ_netscape_data_type		OBJ_netscape,2L

#define SN_des_ede_cfb64		"DES-EDE-CFB"
#define LN_des_ede_cfb64		"des-ede-cfb"
#define NID_des_ede_cfb64		60

#define SN_des_ede3_cfb64		"DES-EDE3-CFB"
#define LN_des_ede3_cfb64		"des-ede3-cfb"
#define NID_des_ede3_cfb64		61

#define SN_des_ede_ofb64		"DES-EDE-OFB"
#define LN_des_ede_ofb64		"des-ede-ofb"
#define NID_des_ede_ofb64		62

#define SN_des_ede3_ofb64		"DES-EDE3-OFB"
#define LN_des_ede3_ofb64		"des-ede3-ofb"
#define NID_des_ede3_ofb64		63

/* I'm not sure about the object ID */
#define SN_sha1				"SHA1"
#define LN_sha1				"sha1"
#define NID_sha1			64
#define OBJ_sha1			OBJ_algorithm,26L
/* 28 Jun 1996 - eay */
/* #define OBJ_sha1			1L,3L,14L,2L,26L,05L <- wrong */

#define SN_sha1WithRSAEncryption	"RSA-SHA1"
#define LN_sha1WithRSAEncryption	"sha1WithRSAEncryption"
#define NID_sha1WithRSAEncryption	65
#define OBJ_sha1WithRSAEncryption	OBJ_pkcs,1L,5L

#define SN_dsaWithSHA			"DSA-SHA"
#define LN_dsaWithSHA			"dsaWithSHA"
#define NID_dsaWithSHA			66
#define OBJ_dsaWithSHA			OBJ_algorithm,13L

#define SN_dsa_2			"DSA-old"
#define LN_dsa_2			"dsaEncryption-old"
#define NID_dsa_2			67
#define OBJ_dsa_2			OBJ_algorithm,12L

/* proposed by microsoft to RSA */
#define SN_pbeWithSHA1AndRC2_CBC	"PBE-SHA1-RC2-64"
#define LN_pbeWithSHA1AndRC2_CBC	"pbeWithSHA1AndRC2-CBC"
#define NID_pbeWithSHA1AndRC2_CBC	68
#define OBJ_pbeWithSHA1AndRC2_CBC	OBJ_pkcs,5L,11L

/* proposed by microsoft to RSA as pbeWithSHA1AndRC4: it is now
 * defined explicitly in PKCS#5 v2.0 as id-PBKDF2 which is something
 * completely different.
 */
#define LN_id_pbkdf2			"PBKDF2"
#define NID_id_pbkdf2			69
#define OBJ_id_pbkdf2			OBJ_pkcs,5L,12L

#define SN_dsaWithSHA1_2		"DSA-SHA1-old"
#define LN_dsaWithSHA1_2		"dsaWithSHA1-old"
#define NID_dsaWithSHA1_2		70
/* Got this one from 'sdn706r20.pdf' which is actually an NSA document :-) */
#define OBJ_dsaWithSHA1_2		OBJ_algorithm,27L

#define SN_netscape_cert_type		"nsCertType"
#define LN_netscape_cert_type		"Netscape Cert Type"
#define NID_netscape_cert_type		4
#define OBJ_netscape_cert_type		OBJ_netscape_cert_extension,1L

#define SN_netscape_base_url		"samyang7"
#define LN_netscape_base_url		"test7"
#define NID_netscape_base_url		5
#define OBJ_netscape_base_url		OBJ_netscape_cert_extension,2L

#define SN_netscape_revocation_url		"samyang6"
#define LN_netscape_revocation_url		"test6"
#define NID_netscape_revocation_url	6
#define OBJ_netscape_revocation_url	OBJ_netscape_cert_extension,3L

#define SN_netscape_ca_revocation_url	"samyang5"
#define LN_netscape_ca_revocation_url	"test5"
#define NID_netscape_ca_revocation_url	7
#define OBJ_netscape_ca_revocation_url	OBJ_netscape_cert_extension,4L

#define SN_netscape_renewal_url		"samyang4"
#define LN_netscape_renewal_url		"test4"
#define NID_netscape_renewal_url		8
#define OBJ_netscape_renewal_url		OBJ_netscape_cert_extension,7L

#define SN_netscape_ca_policy_url	  	"samyang3"
#define LN_netscape_ca_policy_url	  	"test3"
#define NID_netscape_ca_policy_url		9
#define OBJ_netscape_ca_policy_url		OBJ_netscape_cert_extension,8L

#define SN_netscape_ssl_server_name	"samyang2"
#define LN_netscape_ssl_server_name	"test2"
#define NID_netscape_ssl_server_name	10
#define OBJ_netscape_ssl_server_name	OBJ_netscape_cert_extension,12L

#define SN_netscape_comment		"samyang1"
#define LN_netscape_comment		"test1"
#define NID_netscape_comment	11
#define OBJ_netscape_comment	OBJ_netscape_cert_extension,13L

//////////////////samyang modify/////////////////

#define SN_test_comment		"samyang8"
#define LN_test_comment		"My_comment"
#define NID_test_comment		12
#define OBJ_test_comment		OBJ_netscape_cert_extension,14L

#define SN_aw_cert_extension		"AW"
#define LN_aw_cert_extension		"ALLWINNER  EXTENSION"
#define NID_aw_cert_extension		13
#define OBJ_aw_cert_extension		2L,16L,840L,1L,113549L


#define SN_aw_comment1		"awcomment1"
#define LN_aw_comment1		"allwinner comment1"
#define NID_aw_comment1		14
#define OBJ_aw_comment1              OBJ_aw_cert_extension,1L


////////////////////////////////////////////////

#define SN_netscape_cert_sequence		"nsCertSequence"
#define LN_netscape_cert_sequence		"Netscape Certificate Sequence"
#define NID_netscape_cert_sequence		79
#define OBJ_netscape_cert_sequence		OBJ_netscape_data_type,5L

#define SN_desx_cbc			"DESX-CBC"
#define LN_desx_cbc			"desx-cbc"
#define NID_desx_cbc			80

#define SN_id_ce			"id-ce"
#define NID_id_ce			81
#define OBJ_id_ce			2L,5L,29L

#define SN_subject_key_identifier	"subjectKeyIdentifier"
#define LN_subject_key_identifier	"X509v3 Subject Key Identifier"
#define NID_subject_key_identifier	82
#define OBJ_subject_key_identifier	OBJ_id_ce,14L

#define SN_key_usage			"keyUsage"
#define LN_key_usage			"X509v3 Key Usage"
#define NID_key_usage			83
#define OBJ_key_usage			OBJ_id_ce,15L

#define SN_private_key_usage_period	"privateKeyUsagePeriod"
#define LN_private_key_usage_period	"X509v3 Private Key Usage Period"
#define NID_private_key_usage_period	84
#define OBJ_private_key_usage_period	OBJ_id_ce,16L

#define SN_subject_alt_name		"subjectAltName"
#define LN_subject_alt_name		"X509v3 Subject Alternative Name"
#define NID_subject_alt_name		85
#define OBJ_subject_alt_name		OBJ_id_ce,17L

#define SN_issuer_alt_name		"issuerAltName"
#define LN_issuer_alt_name		"X509v3 Issuer Alternative Name"
#define NID_issuer_alt_name		86
#define OBJ_issuer_alt_name		OBJ_id_ce,18L

#define SN_basic_constraints		"basicConstraints"
#define LN_basic_constraints		"X509v3 Basic Constraints"
#define NID_basic_constraints		87
#define OBJ_basic_constraints		OBJ_id_ce,19L

#define SN_crl_number			"crlNumber"
#define LN_crl_number			"X509v3 CRL Number"
#define NID_crl_number			88
#define OBJ_crl_number			OBJ_id_ce,20L

#define SN_certificate_policies		"certificatePolicies"
#define LN_certificate_policies		"X509v3 Certificate Policies"
#define NID_certificate_policies	89
#define OBJ_certificate_policies	OBJ_id_ce,32L

#define SN_authority_key_identifier	"authorityKeyIdentifier"
#define LN_authority_key_identifier	"X509v3 Authority Key Identifier"
#define NID_authority_key_identifier	90
#define OBJ_authority_key_identifier	OBJ_id_ce,35L

#define SN_bf_cbc			"BF-CBC"
#define LN_bf_cbc			"bf-cbc"
#define NID_bf_cbc			91
#define OBJ_bf_cbc			1L,3L,6L,1L,4L,1L,3029L,1L,2L

#define SN_bf_ecb			"BF-ECB"
#define LN_bf_ecb			"bf-ecb"
#define NID_bf_ecb			92

#define SN_bf_cfb64			"BF-CFB"
#define LN_bf_cfb64			"bf-cfb"
#define NID_bf_cfb64			93

#define SN_bf_ofb64			"BF-OFB"
#define LN_bf_ofb64			"bf-ofb"
#define NID_bf_ofb64			94

#define SN_mdc2				"MDC2"
#define LN_mdc2				"mdc2"
#define NID_mdc2			95
#define OBJ_mdc2			2L,5L,8L,3L,101L
/* An alternative?			1L,3L,14L,3L,2L,19L */

#define SN_mdc2WithRSA			"RSA-MDC2"
#define LN_mdc2WithRSA			"mdc2withRSA"
#define NID_mdc2WithRSA			96
#define OBJ_mdc2WithRSA			2L,5L,8L,3L,100L

#define SN_rc4_40			"RC4-40"
#define LN_rc4_40			"rc4-40"
#define NID_rc4_40			97

#define SN_rc2_40_cbc			"RC2-40-CBC"
#define LN_rc2_40_cbc			"rc2-40-cbc"
#define NID_rc2_40_cbc			98

#define SN_givenName			"G"
#define LN_givenName			"givenName"
#define NID_givenName			99
#define OBJ_givenName			OBJ_X509,42L

#define SN_surname			"S"
#define LN_surname			"surname"
#define NID_surname			100
#define OBJ_surname			OBJ_X509,4L

#define SN_initials			"I"
#define LN_initials			"initials"
#define NID_initials			101
#define OBJ_initials			OBJ_X509,43L

#define SN_uniqueIdentifier		"UID"
#define LN_uniqueIdentifier		"uniqueIdentifier"
#define NID_uniqueIdentifier		102
#define OBJ_uniqueIdentifier		OBJ_X509,45L

#define SN_crl_distribution_points	"crlDistributionPoints"
#define LN_crl_distribution_points	"X509v3 CRL Distribution Points"
#define NID_crl_distribution_points	103
#define OBJ_crl_distribution_points	OBJ_id_ce,31L

#define SN_md5WithRSA			"RSA-NP-MD5"
#define LN_md5WithRSA			"md5WithRSA"
#define NID_md5WithRSA			104
#define OBJ_md5WithRSA			OBJ_algorithm,3L

#define SN_serialNumber			"SN"
#define LN_serialNumber			"serialNumber"
#define NID_serialNumber		105
#define OBJ_serialNumber		OBJ_X509,5L

#define SN_title			"T"
#define LN_title			"title"
#define NID_title			106
#define OBJ_title			OBJ_X509,12L

#define SN_description			"D"
#define LN_description			"description"
#define NID_description			107
#define OBJ_description			OBJ_X509,13L

/* CAST5 is CAST-128, I'm just sticking with the documentation */
#define SN_cast5_cbc			"CAST5-CBC"
#define LN_cast5_cbc			"cast5-cbc"
#define NID_cast5_cbc			108
#define OBJ_cast5_cbc			1L,2L,840L,113533L,7L,66L,10L

#define SN_cast5_ecb			"CAST5-ECB"
#define LN_cast5_ecb			"cast5-ecb"
#define NID_cast5_ecb			109

#define SN_cast5_cfb64			"CAST5-CFB"
#define LN_cast5_cfb64			"cast5-cfb"
#define NID_cast5_cfb64			110

#define SN_cast5_ofb64			"CAST5-OFB"
#define LN_cast5_ofb64			"cast5-ofb"
#define NID_cast5_ofb64			111

#define LN_pbeWithMD5AndCast5_CBC	"pbeWithMD5AndCast5CBC"
#define NID_pbeWithMD5AndCast5_CBC	112
#define OBJ_pbeWithMD5AndCast5_CBC	1L,2L,840L,113533L,7L,66L,12L

/* This is one sun will soon be using :-(
 * id-dsa-with-sha1 ID  ::= {
 *   iso(1) member-body(2) us(840) x9-57 (10040) x9cm(4) 3 }
 */
#define SN_dsaWithSHA1			"DSA-SHA1"
#define LN_dsaWithSHA1			"dsaWithSHA1"
#define NID_dsaWithSHA1			113
#define OBJ_dsaWithSHA1			1L,2L,840L,10040L,4L,3L

#define NID_md5_sha1			114
#define SN_md5_sha1			"MD5-SHA1"
#define LN_md5_sha1			"md5-sha1"

#define SN_sha1WithRSA			"RSA-SHA1-2"
#define LN_sha1WithRSA			"sha1WithRSA"
#define NID_sha1WithRSA			115
#define OBJ_sha1WithRSA			OBJ_algorithm,29L

#define SN_dsa				"DSA"
#define LN_dsa				"dsaEncryption"
#define NID_dsa				116
#define OBJ_dsa				1L,2L,840L,10040L,4L,1L

#define SN_ripemd160			"RIPEMD160"
#define LN_ripemd160			"ripemd160"
#define NID_ripemd160			117
#define OBJ_ripemd160			1L,3L,36L,3L,2L,1L

/* The name should actually be rsaSignatureWithripemd160, but I'm going
 * to continue using the convention I'm using with the other ciphers */
#define SN_ripemd160WithRSA		"RSA-RIPEMD160"
#define LN_ripemd160WithRSA		"ripemd160WithRSA"
#define NID_ripemd160WithRSA		119
#define OBJ_ripemd160WithRSA		1L,3L,36L,3L,3L,1L,2L

/* Taken from rfc2040
 *  RC5_CBC_Parameters ::= SEQUENCE {
 *	version           INTEGER (v1_0(16)),
 *	rounds            INTEGER (8..127),
 *	blockSizeInBits   INTEGER (64, 128),
 *	iv                OCTET STRING OPTIONAL
 *	}
 */
#define SN_rc5_cbc			"RC5-CBC"
#define LN_rc5_cbc			"rc5-cbc"
#define NID_rc5_cbc			120
#define OBJ_rc5_cbc			OBJ_rsadsi,3L,8L

#define SN_rc5_ecb			"RC5-ECB"
#define LN_rc5_ecb			"rc5-ecb"
#define NID_rc5_ecb			121

#define SN_rc5_cfb64			"RC5-CFB"
#define LN_rc5_cfb64			"rc5-cfb"
#define NID_rc5_cfb64			122

#define SN_rc5_ofb64			"RC5-OFB"
#define LN_rc5_ofb64			"rc5-ofb"
#define NID_rc5_ofb64			123

#define SN_rle_compression		"RLE"
#define LN_rle_compression		"run length compression"
#define NID_rle_compression		124
#define OBJ_rle_compression		1L,1L,1L,1L,666L,1L

#define SN_zlib_compression		"ZLIB"
#define LN_zlib_compression		"zlib compression"
#define NID_zlib_compression		125
#define OBJ_zlib_compression		1L,1L,1L,1L,666L,2L

#define SN_ext_key_usage		"extendedKeyUsage"
#define LN_ext_key_usage		"X509v3 Extended Key Usage"
#define NID_ext_key_usage		126
#define OBJ_ext_key_usage		OBJ_id_ce,37

#define SN_id_pkix			"PKIX"
#define NID_id_pkix			127
#define OBJ_id_pkix			1L,3L,6L,1L,5L,5L,7L

#define SN_id_kp			"id-kp"
#define NID_id_kp			128
#define OBJ_id_kp			OBJ_id_pkix,3L

/* PKIX extended key usage OIDs */

#define SN_server_auth			"serverAuth"
#define LN_server_auth			"TLS Web Server Authentication"
#define NID_server_auth			129
#define OBJ_server_auth			OBJ_id_kp,1L

#define SN_client_auth			"clientAuth"
#define LN_client_auth			"TLS Web Client Authentication"
#define NID_client_auth			130
#define OBJ_client_auth			OBJ_id_kp,2L

#define SN_code_sign			"codeSigning"
#define LN_code_sign			"Code Signing"
#define NID_code_sign			131
#define OBJ_code_sign			OBJ_id_kp,3L

#define SN_email_protect		"emailProtection"
#define LN_email_protect		"E-mail Protection"
#define NID_email_protect		132
#define OBJ_email_protect		OBJ_id_kp,4L

#define SN_time_stamp			"timeStamping"
#define LN_time_stamp			"Time Stamping"
#define NID_time_stamp			133
#define OBJ_time_stamp			OBJ_id_kp,8L

/* Additional extended key usage OIDs: Microsoft */

#define SN_ms_code_ind			"msCodeInd"
#define LN_ms_code_ind			"Microsoft Individual Code Signing"
#define NID_ms_code_ind			134
#define OBJ_ms_code_ind			1L,3L,6L,1L,4L,1L,311L,2L,1L,21L

#define SN_ms_code_com			"msCodeCom"
#define LN_ms_code_com			"Microsoft Commercial Code Signing"
#define NID_ms_code_com			135
#define OBJ_ms_code_com			1L,3L,6L,1L,4L,1L,311L,2L,1L,22L

#define SN_ms_ctl_sign			"msCTLSign"
#define LN_ms_ctl_sign			"Microsoft Trust List Signing"
#define NID_ms_ctl_sign			136
#define OBJ_ms_ctl_sign			1L,3L,6L,1L,4L,1L,311L,10L,3L,1L

#define SN_ms_sgc			"msSGC"
#define LN_ms_sgc			"Microsoft Server Gated Crypto"
#define NID_ms_sgc			137
#define OBJ_ms_sgc			1L,3L,6L,1L,4L,1L,311L,10L,3L,3L

#define SN_ms_efs			"msEFS"
#define LN_ms_efs			"Microsoft Encrypted File System"
#define NID_ms_efs			138
#define OBJ_ms_efs			1L,3L,6L,1L,4L,1L,311L,10L,3L,4L

/* Additional usage: Netscape */

#define SN_ns_sgc			"nsSGC"
#define LN_ns_sgc			"Netscape Server Gated Crypto"
#define NID_ns_sgc			139
#define OBJ_ns_sgc			OBJ_netscape,4L,1L

#define SN_delta_crl			"deltaCRL"
#define LN_delta_crl			"X509v3 Delta CRL Indicator"
#define NID_delta_crl			140
#define OBJ_delta_crl			OBJ_id_ce,27L

#define SN_crl_reason			"CRLReason"
#define LN_crl_reason			"CRL Reason Code"
#define NID_crl_reason			141
#define OBJ_crl_reason			OBJ_id_ce,21L

#define SN_invalidity_date		"invalidityDate"
#define LN_invalidity_date		"Invalidity Date"
#define NID_invalidity_date		142
#define OBJ_invalidity_date		OBJ_id_ce,24L

#define SN_sxnet			"SXNetID"
#define LN_sxnet			"Strong Extranet ID"
#define NID_sxnet			143
#define OBJ_sxnet			1L,3L,101L,1L,4L,1L

/* PKCS12 and related OBJECT IDENTIFIERS */

#define OBJ_pkcs12			OBJ_pkcs,12L
#define OBJ_pkcs12_pbeids		OBJ_pkcs12, 1

#define SN_pbe_WithSHA1And128BitRC4	"PBE-SHA1-RC4-128"
#define LN_pbe_WithSHA1And128BitRC4	"pbeWithSHA1And128BitRC4"
#define NID_pbe_WithSHA1And128BitRC4	144
#define OBJ_pbe_WithSHA1And128BitRC4	OBJ_pkcs12_pbeids, 1L

#define SN_pbe_WithSHA1And40BitRC4	"PBE-SHA1-RC4-40"
#define LN_pbe_WithSHA1And40BitRC4	"pbeWithSHA1And40BitRC4"
#define NID_pbe_WithSHA1And40BitRC4	145
#define OBJ_pbe_WithSHA1And40BitRC4	OBJ_pkcs12_pbeids, 2L

#define SN_pbe_WithSHA1And3_Key_TripleDES_CBC	"PBE-SHA1-3DES"
#define LN_pbe_WithSHA1And3_Key_TripleDES_CBC	"pbeWithSHA1And3-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And3_Key_TripleDES_CBC	146
#define OBJ_pbe_WithSHA1And3_Key_TripleDES_CBC	OBJ_pkcs12_pbeids, 3L

#define SN_pbe_WithSHA1And2_Key_TripleDES_CBC	"PBE-SHA1-2DES"
#define LN_pbe_WithSHA1And2_Key_TripleDES_CBC	"pbeWithSHA1And2-KeyTripleDES-CBC"
#define NID_pbe_WithSHA1And2_Key_TripleDES_CBC	147
#define OBJ_pbe_WithSHA1And2_Key_TripleDES_CBC	OBJ_pkcs12_pbeids, 4L

#define SN_pbe_WithSHA1And128BitRC2_CBC		"PBE-SHA1-RC2-128"
#define LN_pbe_WithSHA1And128BitRC2_CBC		"pbeWithSHA1And128BitRC2-CBC"
#define NID_pbe_WithSHA1And128BitRC2_CBC	148
#define OBJ_pbe_WithSHA1And128BitRC2_CBC	OBJ_pkcs12_pbeids, 5L

#define SN_pbe_WithSHA1And40BitRC2_CBC	"PBE-SHA1-RC2-40"
#define LN_pbe_WithSHA1And40BitRC2_CBC	"pbeWithSHA1And40BitRC2-CBC"
#define NID_pbe_WithSHA1And40BitRC2_CBC	149
#define OBJ_pbe_WithSHA1And40BitRC2_CBC	OBJ_pkcs12_pbeids, 6L

#define OBJ_pkcs12_Version1	OBJ_pkcs12, 10L

#define OBJ_pkcs12_BagIds	OBJ_pkcs12_Version1, 1L

#define LN_keyBag		"keyBag"
#define NID_keyBag		150
#define OBJ_keyBag		OBJ_pkcs12_BagIds, 1L

#define LN_pkcs8ShroudedKeyBag	"pkcs8ShroudedKeyBag"
#define NID_pkcs8ShroudedKeyBag	151
#define OBJ_pkcs8ShroudedKeyBag	OBJ_pkcs12_BagIds, 2L

#define LN_certBag		"certBag"
#define NID_certBag		152
#define OBJ_certBag		OBJ_pkcs12_BagIds, 3L

#define LN_crlBag		"crlBag"
#define NID_crlBag		153
#define OBJ_crlBag		OBJ_pkcs12_BagIds, 4L

#define LN_secretBag		"secretBag"
#define NID_secretBag		154
#define OBJ_secretBag		OBJ_pkcs12_BagIds, 5L

#define LN_safeContentsBag	"safeContentsBag"
#define NID_safeContentsBag	155
#define OBJ_safeContentsBag	OBJ_pkcs12_BagIds, 6L

#define LN_friendlyName		"friendlyName"
#define	NID_friendlyName	156
#define OBJ_friendlyName	OBJ_pkcs9, 20L

#define LN_localKeyID		"localKeyID"
#define	NID_localKeyID		157
#define OBJ_localKeyID		OBJ_pkcs9, 21L

#define OBJ_certTypes		OBJ_pkcs9, 22L

#define LN_x509Certificate	"x509Certificate"
#define	NID_x509Certificate	158
#define OBJ_x509Certificate	OBJ_certTypes, 1L

#define LN_sdsiCertificate	"sdsiCertificate"
#define	NID_sdsiCertificate	159
#define OBJ_sdsiCertificate	OBJ_certTypes, 2L

#define OBJ_crlTypes		OBJ_pkcs9, 23L

#define LN_x509Crl		"x509Crl"
#define	NID_x509Crl		160
#define OBJ_x509Crl		OBJ_crlTypes, 1L

/* PKCS#5 v2 OIDs */

#define LN_pbes2		"PBES2"
#define NID_pbes2		161
#define OBJ_pbes2		OBJ_pkcs,5L,13L

#define LN_pbmac1		"PBMAC1"
#define NID_pbmac1		162
#define OBJ_pbmac1		OBJ_pkcs,5L,14L

#define LN_hmacWithSHA1		"hmacWithSHA1"
#define NID_hmacWithSHA1	163
#define OBJ_hmacWithSHA1	OBJ_rsadsi,2L,7L

/* Policy Qualifier Ids */

#define LN_id_qt_cps		"Policy Qualifier CPS"
#define SN_id_qt_cps		"id-qt-cps"
#define NID_id_qt_cps		164
#define OBJ_id_qt_cps		OBJ_id_pkix,2L,1L

#define LN_id_qt_unotice	"Policy Qualifier User Notice"
#define SN_id_qt_unotice	"id-qt-unotice"
#define NID_id_qt_unotice	165
#define OBJ_id_qt_unotice	OBJ_id_pkix,2L,2L

#define SN_rc2_64_cbc			"RC2-64-CBC"
#define LN_rc2_64_cbc			"rc2-64-cbc"
#define NID_rc2_64_cbc			166

#define SN_SMIMECapabilities		"SMIME-CAPS"
#define LN_SMIMECapabilities		"S/MIME Capabilities"
#define NID_SMIMECapabilities		167
#define OBJ_SMIMECapabilities		OBJ_pkcs9,15L

#define SN_pbeWithMD2AndRC2_CBC		"PBE-MD2-RC2-64"
#define LN_pbeWithMD2AndRC2_CBC		"pbeWithMD2AndRC2-CBC"
#define NID_pbeWithMD2AndRC2_CBC	168
#define OBJ_pbeWithMD2AndRC2_CBC	OBJ_pkcs,5L,4L

#define SN_pbeWithMD5AndRC2_CBC		"PBE-MD5-RC2-64"
#define LN_pbeWithMD5AndRC2_CBC		"pbeWithMD5AndRC2-CBC"
#define NID_pbeWithMD5AndRC2_CBC	169
#define OBJ_pbeWithMD5AndRC2_CBC	OBJ_pkcs,5L,6L

#define SN_pbeWithSHA1AndDES_CBC	"PBE-SHA1-DES"
#define LN_pbeWithSHA1AndDES_CBC	"pbeWithSHA1AndDES-CBC"
#define NID_pbeWithSHA1AndDES_CBC	170
#define OBJ_pbeWithSHA1AndDES_CBC	OBJ_pkcs,5L,10L

/* Extension request OIDs */

#define LN_ms_ext_req			"Microsoft Extension Request"
#define SN_ms_ext_req			"msExtReq"
#define NID_ms_ext_req			171
#define OBJ_ms_ext_req			1L,3L,6L,1L,4L,1L,311L,2L,1L,14L

#define LN_ext_req			"Extension Request"
#define SN_ext_req			"extReq"
#define NID_ext_req			172
#define OBJ_ext_req			OBJ_pkcs9,14L

#define SN_name				"name"
#define LN_name				"name"
#define NID_name			173
#define OBJ_name			OBJ_X509,41L

#define SN_dnQualifier			"dnQualifier"
#define LN_dnQualifier			"dnQualifier"
#define NID_dnQualifier			174
#define OBJ_dnQualifier			OBJ_X509,46L

#define SN_id_pe			"id-pe"
#define NID_id_pe			175
#define OBJ_id_pe			OBJ_id_pkix,1L

#define SN_id_ad			"id-ad"
#define NID_id_ad			176
#define OBJ_id_ad			OBJ_id_pkix,48L

#define SN_info_access			"authorityInfoAccess"
#define LN_info_access			"Authority Information Access"
#define NID_info_access			177
#define OBJ_info_access			OBJ_id_pe,1L

#define SN_ad_OCSP			"OCSP"
#define LN_ad_OCSP			"OCSP"
#define NID_ad_OCSP			178
#define OBJ_ad_OCSP			OBJ_id_ad,1L

#define SN_ad_ca_issuers		"caIssuers"
#define LN_ad_ca_issuers		"CA Issuers"
#define NID_ad_ca_issuers		179
#define OBJ_ad_ca_issuers		OBJ_id_ad,2L

#define SN_OCSP_sign			"OCSPSigning"
#define LN_OCSP_sign			"OCSP Signing"
#define NID_OCSP_sign			180
#define OBJ_OCSP_sign			OBJ_id_kp,9L
#endif /* USE_OBJ_MAC */

#define	OBJ_NAME_TYPE_UNDEF		0x00
#define	OBJ_NAME_TYPE_MD_METH		0x01
#define	OBJ_NAME_TYPE_CIPHER_METH	0x02
#define	OBJ_NAME_TYPE_PKEY_METH		0x03
#define	OBJ_NAME_TYPE_COMP_METH		0x04
#define	OBJ_NAME_TYPE_NUM		0x05

#define	OBJ_NAME_ALIAS			0x8000

#define OBJ_BSEARCH_VALUE_ON_NOMATCH		0x01
#define OBJ_BSEARCH_FIRST_VALUE_ON_MATCH	0x02


typedef struct obj_name_st
{
    int type;
    int alias;
    const char *name;
    const char *data;
} OBJ_NAME;

#define		OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)


int OBJ_NAME_init(void);
int OBJ_NAME_new_index(unsigned long (*hash_func)(const char *),
                       int (*cmp_func)(const char *, const char *),
                       void (*free_func)(const char *, int, const char *));
const char *OBJ_NAME_get(const char *name,int type);
int OBJ_NAME_add(const char *name,int type,const char *data);
int OBJ_NAME_remove(const char *name,int type);
void OBJ_NAME_cleanup(int type); /* -1 for everything */
void OBJ_NAME_do_all(int type,void (*fn)(const OBJ_NAME *,void *arg),
                     void *arg);
void OBJ_NAME_do_all_sorted(int type,void (*fn)(const OBJ_NAME *,void *arg),
                            void *arg);

ASN1_OBJECT *	OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT *	OBJ_nid2obj(int n);
const char *	OBJ_nid2ln(int n);
const char *	OBJ_nid2sn(int n);
int		OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT *	OBJ_txt2obj(const char *s, int no_name);
int	OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int		OBJ_txt2nid(const char *s);
int		OBJ_ln2nid(const char *s);
int		OBJ_sn2nid(const char *s);
int		OBJ_cmp(const ASN1_OBJECT *a,const ASN1_OBJECT *b);
const char *	OBJ_bsearch(const char *key,const char *base,int num,int size,
                            int (*cmp)(const void *, const void *));
const char *	OBJ_bsearch_ex(const char *key,const char *base,int num,
                               int size, int (*cmp)(const void *, const void *), int flags);

int		OBJ_new_nid(int num);
int		OBJ_add_object(const ASN1_OBJECT *obj);
int		OBJ_create(const char *oid,const char *sn,const char *ln);
void		OBJ_cleanup(void );
int		OBJ_create_objects(BIO *in);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_OBJ_strings(void);

/* Error codes for the OBJ functions. */

/* Function codes. */
#define OBJ_F_OBJ_ADD_OBJECT				 105
#define OBJ_F_OBJ_CREATE				 100
#define OBJ_F_OBJ_DUP					 101
#define OBJ_F_OBJ_NAME_NEW_INDEX			 106
#define OBJ_F_OBJ_NID2LN				 102
#define OBJ_F_OBJ_NID2OBJ				 103
#define OBJ_F_OBJ_NID2SN				 104

/* Reason codes. */
#define OBJ_R_MALLOC_FAILURE				 100
#define OBJ_R_UNKNOWN_NID				 101


#ifdef OPENSSL_ALGORITHM_DEFINES
#else
# define OPENSSL_ALGORITHM_DEFINES
# undef OPENSSL_ALGORITHM_DEFINES
#endif

/*
#define EVP_RC2_KEY_SIZE		16
#define EVP_RC4_KEY_SIZE		16
#define EVP_BLOWFISH_KEY_SIZE		16
#define EVP_CAST5_KEY_SIZE		16
#define EVP_RC5_32_12_16_KEY_SIZE	16
*/
#define EVP_MAX_MD_SIZE			64	/* longest known is SHA512 */
#define EVP_MAX_KEY_LENGTH		32
#define EVP_MAX_IV_LENGTH		16
#define EVP_MAX_BLOCK_LENGTH		32

#define PKCS5_SALT_LEN			8
/* Default PKCS#5 iteration count */
#define PKCS5_DEFAULT_ITER		2048


#define EVP_PK_RSA	0x0001
#define EVP_PK_DSA	0x0002
#define EVP_PK_DH	0x0004
#define EVP_PK_EC	0x0008
#define EVP_PKT_SIGN	0x0010
#define EVP_PKT_ENC	0x0020
#define EVP_PKT_EXCH	0x0040
#define EVP_PKS_RSA	0x0100
#define EVP_PKS_DSA	0x0200
#define EVP_PKS_EC	0x0400
#define EVP_PKT_EXP	0x1000 /* <= 512 bit key */

#define EVP_PKEY_NONE	NID_undef
#define EVP_PKEY_RSA	NID_rsaEncryption
#define EVP_PKEY_RSA2	NID_rsa
#define EVP_PKEY_DSA	NID_dsa
#define EVP_PKEY_DSA1	NID_dsa_2
#define EVP_PKEY_DSA2	NID_dsaWithSHA
#define EVP_PKEY_DSA3	NID_dsaWithSHA1
#define EVP_PKEY_DSA4	NID_dsaWithSHA1_2
#define EVP_PKEY_DH	NID_dhKeyAgreement
#define EVP_PKEY_EC	NID_X9_62_id_ecPublicKey

#ifdef	__cplusplus
extern "C" {
#endif

/* Type needs to be a bit field
 * Sub-type needs to be for variations on the method, as in, can it do
 * arbitrary encryption.... */
struct evp_pkey_st
{
    int type;
    int save_type;
    int references;
    const struct evp_pkey_asn1_method_st *ameth;
    ENGINE *engine;
    union	{
        char *ptr;
#ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;	/* RSA */
#endif
#ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;	/* DSA */
#endif
#ifndef OPENSSL_NO_DH
        struct dh_st *dh;	/* DH */
#endif
#ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;	/* ECC */
#endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} /* EVP_PKEY */;

#define EVP_PKEY_MO_SIGN	0x0001
#define EVP_PKEY_MO_VERIFY	0x0002
#define EVP_PKEY_MO_ENCRYPT	0x0004
#define EVP_PKEY_MO_DECRYPT	0x0008

#if 0
/* This structure is required to tie the message digest and signing together.
 * The lookup can be done by md/pkey_method, oid, oid/pkey_method, or
 * oid, md and pkey.
 * This is required because for various smart-card perform the digest and
 * signing/verification on-board.  To handle this case, the specific
 * EVP_MD and EVP_PKEY_METHODs need to be closely associated.
 * When a PKEY is created, it will have a EVP_PKEY_METHOD associated with it.
 * This can either be software or a token to provide the required low level
 * routines.
 */
typedef struct evp_pkey_md_st
	{
	int oid;
	EVP_MD *md;
	EVP_PKEY_METHOD *pkey;
	} EVP_PKEY_MD;

#define EVP_rsa_md2() \
		EVP_PKEY_MD_add(NID_md2WithRSAEncryption,\
			EVP_rsa_pkcs1(),EVP_md2())
#define EVP_rsa_md5() \
		EVP_PKEY_MD_add(NID_md5WithRSAEncryption,\
			EVP_rsa_pkcs1(),EVP_md5())
#define EVP_rsa_sha0() \
		EVP_PKEY_MD_add(NID_shaWithRSAEncryption,\
			EVP_rsa_pkcs1(),EVP_sha())
#define EVP_rsa_sha1() \
		EVP_PKEY_MD_add(NID_sha1WithRSAEncryption,\
			EVP_rsa_pkcs1(),EVP_sha1())
#define EVP_rsa_ripemd160() \
		EVP_PKEY_MD_add(NID_ripemd160WithRSA,\
			EVP_rsa_pkcs1(),EVP_ripemd160())
#define EVP_rsa_mdc2() \
		EVP_PKEY_MD_add(NID_mdc2WithRSA,\
			EVP_rsa_octet_string(),EVP_mdc2())
#define EVP_dsa_sha() \
		EVP_PKEY_MD_add(NID_dsaWithSHA,\
			EVP_dsa(),EVP_sha())
#define EVP_dsa_sha1() \
		EVP_PKEY_MD_add(NID_dsaWithSHA1,\
			EVP_dsa(),EVP_sha1())

typedef struct evp_pkey_method_st
	{
	char *name;
	int flags;
	int type;		/* RSA, DSA, an SSLeay specific constant */
	int oid;		/* For the pub-key type */
	int encrypt_oid;	/* pub/priv key encryption */

	int (*sign)();
	int (*verify)();
	struct	{
		int (*set)();	/* get and/or set the underlying type */
		int (*get)();
		int (*encrypt)();
		int (*decrypt)();
		int (*i2d)();
		int (*d2i)();
		int (*dup)();
		} pub,priv;
	int (*set_asn1_parameters)();
	int (*get_asn1_parameters)();
	} EVP_PKEY_METHOD;
#endif

#ifndef EVP_MD
struct env_md_st
{
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init)(EVP_MD_CTX *ctx);
    int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
    int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
    int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
    int (*cleanup)(EVP_MD_CTX *ctx);

    /* FIXME: prototype these some day */
    int (*sign)(int type, const unsigned char *m, unsigned int m_length,
                unsigned char *sigret, unsigned int *siglen, void *key);
    int (*verify)(int type, const unsigned char *m, unsigned int m_length,
                  const unsigned char *sigbuf, unsigned int siglen,
                  void *key);
    int required_pkey_type[5]; /*EVP_PKEY_xxx */
    int block_size;
    int ctx_size; /* how big does the ctx->md_data need to be */
} /* EVP_MD */;

typedef int evp_sign_method(int type,const unsigned char *m,
                            unsigned int m_length,unsigned char *sigret,
                            unsigned int *siglen, void *key);
typedef int evp_verify_method(int type,const unsigned char *m,
                              unsigned int m_length,const unsigned char *sigbuf,
                              unsigned int siglen, void *key);

typedef struct
{
    EVP_MD_CTX *mctx;
    void *key;
} EVP_MD_SVCTX;

#define EVP_MD_FLAG_ONESHOT	0x0001 /* digest can only handle a single
					* block */

#define EVP_MD_FLAG_FIPS	0x0400 /* Note if suitable for use in FIPS mode */

#define EVP_MD_FLAG_SVCTX	0x0800 /* pass EVP_MD_SVCTX to sign/verify */

#define EVP_PKEY_NULL_method	NULL,NULL,{0,0,0,0}

#ifndef OPENSSL_NO_DSA
#define EVP_PKEY_DSA_method	(evp_sign_method *)DSA_sign, \
				(evp_verify_method *)DSA_verify, \
				{EVP_PKEY_DSA,EVP_PKEY_DSA2,EVP_PKEY_DSA3, \
					EVP_PKEY_DSA4,0}
#else
#define EVP_PKEY_DSA_method	EVP_PKEY_NULL_method
#endif

#ifndef OPENSSL_NO_ECDSA
#define EVP_PKEY_ECDSA_method   (evp_sign_method *)ECDSA_sign, \
				(evp_verify_method *)ECDSA_verify, \
                                 {EVP_PKEY_EC,0,0,0}
#else
#define EVP_PKEY_ECDSA_method   EVP_PKEY_NULL_method
#endif

#ifndef OPENSSL_NO_RSA
#define EVP_PKEY_RSA_method	(evp_sign_method *)RSA_sign, \
				(evp_verify_method *)RSA_verify, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#define EVP_PKEY_RSA_ASN1_OCTET_STRING_method \
				(evp_sign_method *)RSA_sign_ASN1_OCTET_STRING, \
				(evp_verify_method *)RSA_verify_ASN1_OCTET_STRING, \
				{EVP_PKEY_RSA,EVP_PKEY_RSA2,0,0}
#else
#define EVP_PKEY_RSA_method	EVP_PKEY_NULL_method
#define EVP_PKEY_RSA_ASN1_OCTET_STRING_method EVP_PKEY_NULL_method
#endif

#endif /* !EVP_MD */

struct env_md_ctx_st
{
    const EVP_MD *digest;
    ENGINE *engine; /* functional reference if 'digest' is ENGINE-provided */
    unsigned long flags;
    void *md_data;
} /* EVP_MD_CTX */;

/* values for EVP_MD_CTX flags */

#define EVP_MD_CTX_FLAG_ONESHOT		0x0001 /* digest update will be called
						* once only */
#define EVP_MD_CTX_FLAG_CLEANED		0x0002 /* context has already been
						* cleaned */
#define EVP_MD_CTX_FLAG_REUSE		0x0004 /* Don't free up ctx->md_data
						* in EVP_MD_CTX_cleanup */
#define EVP_MD_CTX_FLAG_NON_FIPS_ALLOW	0x0008	/* Allow use of non FIPS digest
						 * in FIPS mode */

#define EVP_MD_CTX_FLAG_PAD_MASK	0xF0	/* RSA mode to use */
#define EVP_MD_CTX_FLAG_PAD_PKCS1	0x00	/* PKCS#1 v1.5 mode */
#define EVP_MD_CTX_FLAG_PAD_X931	0x10	/* X9.31 mode */
#define EVP_MD_CTX_FLAG_PAD_PSS		0x20	/* PSS mode */
#define M_EVP_MD_CTX_FLAG_PSS_SALT(ctx) \
		((ctx->flags>>16) &0xFFFF) /* seed length */
#define EVP_MD_CTX_FLAG_PSS_MDLEN	0xFFFF	/* salt len same as digest */
#define EVP_MD_CTX_FLAG_PSS_MREC	0xFFFE	/* salt max or auto recovered */

struct evp_cipher_st
{
    int nid;
    int block_size;
    int key_len;		/* Default value for variable length ciphers */
    int iv_len;
    unsigned long flags;	/* Various flags */
    int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                const unsigned char *iv, int enc);	/* init key */
    int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     const unsigned char *in, unsigned int inl);/* encrypt/decrypt data */
    int (*cleanup)(EVP_CIPHER_CTX *); /* cleanup ctx */
    int ctx_size;		/* how big ctx->cipher_data needs to be */
    int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); /* Populate a ASN1_TYPE with parameters */
    int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *); /* Get parameters from a ASN1_TYPE */
    int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr); /* Miscellaneous operations */
    void *app_data;		/* Application data */
} /* EVP_CIPHER */;

/* Values for cipher flags */

/* Modes for ciphers */

#define		EVP_CIPH_STREAM_CIPHER		0x0
#define		EVP_CIPH_ECB_MODE		0x1
#define		EVP_CIPH_CBC_MODE		0x2
#define		EVP_CIPH_CFB_MODE		0x3
#define		EVP_CIPH_OFB_MODE		0x4
#define 	EVP_CIPH_MODE			0x7
/* Set if variable length cipher */
#define 	EVP_CIPH_VARIABLE_LENGTH	0x8
/* Set if the iv handling should be done by the cipher itself */
#define 	EVP_CIPH_CUSTOM_IV		0x10
/* Set if the cipher's init() function should be called if key is NULL */
#define 	EVP_CIPH_ALWAYS_CALL_INIT	0x20
/* Call ctrl() to init cipher parameters */
#define 	EVP_CIPH_CTRL_INIT		0x40
/* Don't use standard key length function */
#define 	EVP_CIPH_CUSTOM_KEY_LENGTH	0x80
/* Don't use standard block padding */
#define 	EVP_CIPH_NO_PADDING		0x100
/* cipher handles random key generation */
#define 	EVP_CIPH_RAND_KEY		0x200
/* Note if suitable for use in FIPS mode */
#define		EVP_CIPH_FLAG_FIPS		0x400
/* Allow non FIPS cipher in FIPS mode */
#define		EVP_CIPH_FLAG_NON_FIPS_ALLOW	0x800
/* Allow use default ASN1 get/set iv */
#define		EVP_CIPH_FLAG_DEFAULT_ASN1	0x1000
/* Buffer length in bits not bytes: CFB1 mode only */
#define		EVP_CIPH_FLAG_LENGTH_BITS	0x2000

/* ctrl() values */

#define		EVP_CTRL_INIT			0x0
#define 	EVP_CTRL_SET_KEY_LENGTH		0x1
#define 	EVP_CTRL_GET_RC2_KEY_BITS	0x2
#define 	EVP_CTRL_SET_RC2_KEY_BITS	0x3
#define 	EVP_CTRL_GET_RC5_ROUNDS		0x4
#define 	EVP_CTRL_SET_RC5_ROUNDS		0x5
#define 	EVP_CTRL_RAND_KEY		0x6

typedef struct evp_cipher_info_st
{
    const EVP_CIPHER *cipher;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;

struct evp_cipher_ctx_st
{
    const EVP_CIPHER *cipher;
    ENGINE *engine;	/* functional reference if 'cipher' is ENGINE-provided */
    int encrypt;		/* encrypt or decrypt */
    int buf_len;		/* number we have left */

    unsigned char  oiv[EVP_MAX_IV_LENGTH];	/* original iv */
    unsigned char  iv[EVP_MAX_IV_LENGTH];	/* working iv */
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];/* saved partial block */
    int num;				/* used by cfb/ofb mode */

    void *app_data;		/* application stuff */
    int key_len;		/* May change for variable length cipher */
    unsigned long flags;	/* Various flags */
    void *cipher_data; /* per EVP data */
    int final_used;
    int block_mask;
    unsigned char final[EVP_MAX_BLOCK_LENGTH];/* possible final block */
} /* EVP_CIPHER_CTX */;

typedef struct evp_Encode_Ctx_st
{
    int num;	/* number saved in a partial encode/decode */
    int length;	/* The length is either the output line length
			 * (in input bytes) or the shortest input line
			 * length that is ok.  Once decoding begins,
			 * the length is adjusted up each time a longer
			 * line is decoded */
    unsigned char enc_data[80];	/* data to encode */
    int line_num;	/* number read on current line */
    int expect_nl;
} EVP_ENCODE_CTX;

/* Password based encryption function */
typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                             ASN1_TYPE *param, const EVP_CIPHER *cipher,
                             const EVP_MD *md, int en_de);

#ifndef OPENSSL_NO_RSA
#define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
					(char *)(rsa))
#endif

#ifndef OPENSSL_NO_DSA
#define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA,\
					(char *)(dsa))
#endif

#ifndef OPENSSL_NO_DH
#define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH,\
					(char *)(dh))
#endif

#ifndef OPENSSL_NO_EC
#define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC,\
                                        (char *)(eckey))
#endif

/* Add some extra combinations */
#define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))
#define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))
#define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
#define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))

/* Macros to reduce FIPS dependencies: do NOT use in applications */
#define M_EVP_MD_size(e)		((e)->md_size)
#define M_EVP_MD_block_size(e)		((e)->block_size)
#define M_EVP_MD_CTX_set_flags(ctx,flgs) ((ctx)->flags|=(flgs))
#define M_EVP_MD_CTX_clear_flags(ctx,flgs) ((ctx)->flags&=~(flgs))
#define M_EVP_MD_CTX_test_flags(ctx,flgs) ((ctx)->flags&(flgs))
#define M_EVP_MD_type(e)			((e)->type)
#define M_EVP_MD_CTX_type(e)		M_EVP_MD_type(M_EVP_MD_CTX_md(e))
#define M_EVP_MD_CTX_md(e)			((e)->digest)

#define M_EVP_CIPHER_CTX_set_flags(ctx,flgs) ((ctx)->flags|=(flgs))

int EVP_MD_type(const EVP_MD *md);
#define EVP_MD_nid(e)			EVP_MD_type(e)
#define EVP_MD_name(e)			OBJ_nid2sn(EVP_MD_nid(e))
int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);

const EVP_MD * EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
#define EVP_MD_CTX_size(e)		EVP_MD_size(EVP_MD_CTX_md(e))
#define EVP_MD_CTX_block_size(e)	EVP_MD_block_size(EVP_MD_CTX_md(e))
#define EVP_MD_CTX_type(e)		EVP_MD_type(EVP_MD_CTX_md(e))

int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
#define EVP_CIPHER_name(e)		OBJ_nid2sn(EVP_CIPHER_nid(e))
int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);
#define EVP_CIPHER_mode(e)		(EVP_CIPHER_flags(e) & EVP_CIPH_MODE)

const EVP_CIPHER * EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
void * EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
#define EVP_CIPHER_CTX_type(c)         EVP_CIPHER_type(EVP_CIPHER_CTX_cipher(c))
unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx);
#define EVP_CIPHER_CTX_mode(e)		(EVP_CIPHER_CTX_flags(e) & EVP_CIPH_MODE)

#define EVP_ENCODE_LENGTH(l)	(((l+2)/3*4)+(l/48+1)*2+80)
#define EVP_DECODE_LENGTH(l)	((l+3)/4*3+80)

#define EVP_SignInit_ex(a,b,c)		EVP_DigestInit_ex(a,b,c)
#define EVP_SignInit(a,b)		EVP_DigestInit(a,b)
#define EVP_SignUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
#define	EVP_VerifyInit_ex(a,b,c)	EVP_DigestInit_ex(a,b,c)
#define	EVP_VerifyInit(a,b)		EVP_DigestInit(a,b)
#define	EVP_VerifyUpdate(a,b,c)		EVP_DigestUpdate(a,b,c)
#define EVP_OpenUpdate(a,b,c,d,e)	EVP_DecryptUpdate(a,b,c,d,e)
#define EVP_SealUpdate(a,b,c,d,e)	EVP_EncryptUpdate(a,b,c,d,e)

#ifdef CONST_STRICT
void BIO_set_md(BIO *,const EVP_MD *md);
#else
# define BIO_set_md(b,md)		BIO_ctrl(b,BIO_C_SET_MD,0,(char *)md)
#endif
#define BIO_get_md(b,mdp)		BIO_ctrl(b,BIO_C_GET_MD,0,(char *)mdp)
#define BIO_get_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_GET_MD_CTX,0,(char *)mdcp)
#define BIO_set_md_ctx(b,mdcp)     BIO_ctrl(b,BIO_C_SET_MD_CTX,0,(char *)mdcp)
#define BIO_get_cipher_status(b)	BIO_ctrl(b,BIO_C_GET_CIPHER_STATUS,0,NULL)
#define BIO_get_cipher_ctx(b,c_pp)	BIO_ctrl(b,BIO_C_GET_CIPHER_CTX,0,(char *)c_pp)

int EVP_Cipher(EVP_CIPHER_CTX *c,
               unsigned char *out,
               const unsigned char *in,
               unsigned int inl);

#define EVP_add_cipher_alias(n,alias) \
	OBJ_NAME_add((alias),OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS,(n))
#define EVP_add_digest_alias(n,alias) \
	OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS,(n))
#define EVP_delete_cipher_alias(alias) \
	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_CIPHER_METH|OBJ_NAME_ALIAS);
#define EVP_delete_digest_alias(alias) \
	OBJ_NAME_remove(alias,OBJ_NAME_TYPE_MD_METH|OBJ_NAME_ALIAS);

void	EVP_MD_CTX_init(EVP_MD_CTX *ctx);
int	EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_create(void);
void	EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
int     EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,const EVP_MD_CTX *in);
void	EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void	EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int 	EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx,int flags);
int	EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int	EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d,
                        size_t cnt);
int	EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int	EVP_Digest(const void *data, size_t count,
                  unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);

int     EVP_MD_CTX_copy(EVP_MD_CTX *out,const EVP_MD_CTX *in);
int	EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int	EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);

int	EVP_read_pw_string(char *buf,int length,const char *prompt,int verify);
void	EVP_set_pw_prompt(const char *prompt);
char *	EVP_get_pw_prompt(void);

int	EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
                      const unsigned char *salt, const unsigned char *data,
                      int datal, int count, unsigned char *key,unsigned char *iv);

void	EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void	EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int 	EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx,int flags);

int	EVP_EncryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
                       const unsigned char *key, const unsigned char *iv);
int	EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                          const unsigned char *key, const unsigned char *iv);
int	EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         int *outl, const unsigned char *in, int inl);
int	EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int	EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int	EVP_DecryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
                       const unsigned char *key, const unsigned char *iv);
int	EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                          const unsigned char *key, const unsigned char *iv);
int	EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         int *outl, const unsigned char *in, int inl);
int	EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int	EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int	EVP_CipherInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
                      const unsigned char *key,const unsigned char *iv,
                      int enc);
int	EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
                         const unsigned char *key,const unsigned char *iv,
                         int enc);
int	EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                        int *outl, const unsigned char *in, int inl);
int	EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int	EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

int	EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s,
                     EVP_PKEY *pkey);

int	EVP_VerifyFinal(EVP_MD_CTX *ctx,const unsigned char *sigbuf,
                       unsigned int siglen,EVP_PKEY *pkey);

int	EVP_OpenInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *type,
                    const unsigned char *ek, int ekl, const unsigned char *iv,
                    EVP_PKEY *priv);
int	EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

int	EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                    unsigned char **ek, int *ekl, unsigned char *iv,
                    EVP_PKEY **pubk, int npubk);
int	EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);

void	EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void	EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
                         const unsigned char *in,int inl);
void	EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int	EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

void	EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int	EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
                        const unsigned char *in, int inl);
int	EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
char *out, int *outl);
int	EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

#ifndef OPENSSL_NO_BIO
BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
BIO_METHOD *BIO_f_reliable(void);
void BIO_set_cipher(BIO *b,const EVP_CIPHER *c,const unsigned char *k,
                    const unsigned char *i, int enc);
#endif

const EVP_MD *EVP_md_null(void);
#ifndef OPENSSL_NO_MD2
const EVP_MD *EVP_md2(void);
#endif
#ifndef OPENSSL_NO_MD4
const EVP_MD *EVP_md4(void);
#endif
#ifndef OPENSSL_NO_MD5
const EVP_MD *EVP_md5(void);
#endif
#ifndef OPENSSL_NO_SHA
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_dss(void);
const EVP_MD *EVP_dss1(void);
const EVP_MD *EVP_ecdsa(void);
#endif
#ifndef OPENSSL_NO_SHA256
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
#endif
#ifndef OPENSSL_NO_SHA512
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
#endif
#ifndef OPENSSL_NO_MDC2
const EVP_MD *EVP_mdc2(void);
#endif
#ifndef OPENSSL_NO_RIPEMD
const EVP_MD *EVP_ripemd160(void);
#endif
const EVP_CIPHER *EVP_enc_null(void);		/* does nothing :-) */
#ifndef OPENSSL_NO_DES
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);
# define EVP_des_cfb EVP_des_cfb64
const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
# define EVP_des_ede_cfb EVP_des_ede_cfb64
#if 0
const EVP_CIPHER *EVP_des_ede_cfb1(void);
const EVP_CIPHER *EVP_des_ede_cfb8(void);
#endif
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
# define EVP_des_ede3_cfb EVP_des_ede3_cfb64
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
/* This should now be supported through the dev_crypto ENGINE. But also, why are
 * rc4 and md5 declarations made here inside a "NO_DES" precompiler branch? */
#if 0
# ifdef OPENSSL_OPENBSD_DEV_CRYPTO
const EVP_CIPHER *EVP_dev_crypto_des_ede3_cbc(void);
const EVP_CIPHER *EVP_dev_crypto_rc4(void);
const EVP_MD *EVP_dev_crypto_md5(void);
# endif
#endif
#endif
#ifndef OPENSSL_NO_RC4
const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);
#endif
#ifndef OPENSSL_NO_IDEA
const EVP_CIPHER *EVP_idea_ecb(void);
const EVP_CIPHER *EVP_idea_cfb64(void);
# define EVP_idea_cfb EVP_idea_cfb64
const EVP_CIPHER *EVP_idea_ofb(void);
const EVP_CIPHER *EVP_idea_cbc(void);
#endif
#ifndef OPENSSL_NO_RC2
const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);
# define EVP_rc2_cfb EVP_rc2_cfb64
const EVP_CIPHER *EVP_rc2_ofb(void);
#endif
#ifndef OPENSSL_NO_BF
const EVP_CIPHER *EVP_bf_ecb(void);
const EVP_CIPHER *EVP_bf_cbc(void);
const EVP_CIPHER *EVP_bf_cfb64(void);
# define EVP_bf_cfb EVP_bf_cfb64
const EVP_CIPHER *EVP_bf_ofb(void);
#endif
#ifndef OPENSSL_NO_CAST
const EVP_CIPHER *EVP_cast5_ecb(void);
const EVP_CIPHER *EVP_cast5_cbc(void);
const EVP_CIPHER *EVP_cast5_cfb64(void);
# define EVP_cast5_cfb EVP_cast5_cfb64
const EVP_CIPHER *EVP_cast5_ofb(void);
#endif
#ifndef OPENSSL_NO_RC5
const EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);
const EVP_CIPHER *EVP_rc5_32_12_16_ecb(void);
const EVP_CIPHER *EVP_rc5_32_12_16_cfb64(void);
# define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64
const EVP_CIPHER *EVP_rc5_32_12_16_ofb(void);
#endif
#ifndef OPENSSL_NO_AES
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
# define EVP_aes_128_cfb EVP_aes_128_cfb128
const EVP_CIPHER *EVP_aes_128_ofb(void);
#if 0
const EVP_CIPHER *EVP_aes_128_ctr(void);
#endif
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
# define EVP_aes_192_cfb EVP_aes_192_cfb128
const EVP_CIPHER *EVP_aes_192_ofb(void);
#if 0
const EVP_CIPHER *EVP_aes_192_ctr(void);
#endif
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
# define EVP_aes_256_cfb EVP_aes_256_cfb128
const EVP_CIPHER *EVP_aes_256_ofb(void);
#if 0
const EVP_CIPHER *EVP_aes_256_ctr(void);
#endif
#endif
#ifndef OPENSSL_NO_CAMELLIA
const EVP_CIPHER *EVP_camellia_128_ecb(void);
const EVP_CIPHER *EVP_camellia_128_cbc(void);
const EVP_CIPHER *EVP_camellia_128_cfb1(void);
const EVP_CIPHER *EVP_camellia_128_cfb8(void);
const EVP_CIPHER *EVP_camellia_128_cfb128(void);
# define EVP_camellia_128_cfb EVP_camellia_128_cfb128
const EVP_CIPHER *EVP_camellia_128_ofb(void);
const EVP_CIPHER *EVP_camellia_192_ecb(void);
const EVP_CIPHER *EVP_camellia_192_cbc(void);
const EVP_CIPHER *EVP_camellia_192_cfb1(void);
const EVP_CIPHER *EVP_camellia_192_cfb8(void);
const EVP_CIPHER *EVP_camellia_192_cfb128(void);
# define EVP_camellia_192_cfb EVP_camellia_192_cfb128
const EVP_CIPHER *EVP_camellia_192_ofb(void);
const EVP_CIPHER *EVP_camellia_256_ecb(void);
const EVP_CIPHER *EVP_camellia_256_cbc(void);
const EVP_CIPHER *EVP_camellia_256_cfb1(void);
const EVP_CIPHER *EVP_camellia_256_cfb8(void);
const EVP_CIPHER *EVP_camellia_256_cfb128(void);
# define EVP_camellia_256_cfb EVP_camellia_256_cfb128
const EVP_CIPHER *EVP_camellia_256_ofb(void);
#endif

#ifndef OPENSSL_NO_SEED
const EVP_CIPHER *EVP_seed_ecb(void);
const EVP_CIPHER *EVP_seed_cbc(void);
const EVP_CIPHER *EVP_seed_cfb128(void);
# define EVP_seed_cfb EVP_seed_cfb128
const EVP_CIPHER *EVP_seed_ofb(void);
#endif

void OPENSSL_add_all_algorithms_noconf(void);
void OPENSSL_add_all_algorithms_conf(void);

#ifdef OPENSSL_LOAD_CONF
#define OpenSSL_add_all_algorithms() \
		OPENSSL_add_all_algorithms_conf()
#else
#define OpenSSL_add_all_algorithms() \
		OPENSSL_add_all_algorithms_noconf()
#endif

void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);
#define SSLeay_add_all_algorithms() OpenSSL_add_all_algorithms()
#define SSLeay_add_all_ciphers() OpenSSL_add_all_ciphers()
#define SSLeay_add_all_digests() OpenSSL_add_all_digests()

int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
void EVP_cleanup(void);

int		EVP_PKEY_decrypt(unsigned char *dec_key,
                            const unsigned char *enc_key,int enc_key_len,
                            EVP_PKEY *private_key);
int		EVP_PKEY_encrypt(unsigned char *enc_key,
                            const unsigned char *key,int key_len,
                            EVP_PKEY *pub_key);
int		EVP_PKEY_type(int type);
int		EVP_PKEY_bits(EVP_PKEY *pkey);
int		EVP_PKEY_size(EVP_PKEY *pkey);
int 		EVP_PKEY_assign(EVP_PKEY *pkey,int type,char *key);

#ifndef OPENSSL_NO_RSA
struct rsa_st;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,struct rsa_st *key);
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
#endif
#ifndef OPENSSL_NO_DSA
struct dsa_st;
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,struct dsa_st *key);
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
#endif
#ifndef OPENSSL_NO_DH
struct dh_st;
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,struct dh_st *key);
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
#endif
#ifndef OPENSSL_NO_EC
struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,struct ec_key_st *key);
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
#endif

EVP_PKEY *	EVP_PKEY_new(void);
void		EVP_PKEY_free(EVP_PKEY *pkey);

EVP_PKEY *	d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
                            long length);
int		i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);

EVP_PKEY *	d2i_PrivateKey(int type,EVP_PKEY **a, const unsigned char **pp,
                             long length);
EVP_PKEY *	d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
                                 long length);
int		i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);

int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);

int EVP_CIPHER_type(const EVP_CIPHER *ctx);

/* calls methods */
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);

/* These are used by EVP_CIPHER methods */
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);

/* PKCS5 password based encryption */
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                       ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
                       int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
                          int en_de);

void PKCS5_PBE_add(void);

int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
                        ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
                    EVP_PBE_KEYGEN *keygen);
void EVP_PBE_cleanup(void);

#ifdef OPENSSL_FIPS
#ifndef OPENSSL_NO_ENGINE
void int_EVP_MD_set_engine_callbacks(
	int (*eng_md_init)(ENGINE *impl),
	int (*eng_md_fin)(ENGINE *impl),
	int (*eng_md_evp)
		(EVP_MD_CTX *ctx, const EVP_MD **ptype, ENGINE *impl));
void int_EVP_MD_init_engine_callbacks(void);
void int_EVP_CIPHER_set_engine_callbacks(
	int (*eng_ciph_fin)(ENGINE *impl),
	int (*eng_ciph_evp)
		(EVP_CIPHER_CTX *ctx, const EVP_CIPHER **pciph, ENGINE *impl));
void int_EVP_CIPHER_init_engine_callbacks(void);
#endif
#endif

void EVP_add_alg_module(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_EVP_strings(void);

/* Error codes for the EVP functions. */

/* Function codes. */
#define EVP_F_AES_INIT_KEY				 133
#define EVP_F_ALG_MODULE_INIT				 138
#define EVP_F_CAMELLIA_INIT_KEY				 159
#define EVP_F_D2I_PKEY					 100
#define EVP_F_DO_EVP_ENC_ENGINE				 140
#define EVP_F_DO_EVP_ENC_ENGINE_FULL			 141
#define EVP_F_DO_EVP_MD_ENGINE				 139
#define EVP_F_DO_EVP_MD_ENGINE_FULL			 142
#define EVP_F_DSAPKEY2PKCS8				 134
#define EVP_F_DSA_PKEY2PKCS8				 135
#define EVP_F_ECDSA_PKEY2PKCS8				 129
#define EVP_F_ECKEY_PKEY2PKCS8				 132
#define EVP_F_EVP_CIPHERINIT				 137
#define EVP_F_EVP_CIPHERINIT_EX				 123
#define EVP_F_EVP_CIPHER_CTX_CTRL			 124
#define EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH		 122
#define EVP_F_EVP_DECRYPTFINAL_EX			 101
#define EVP_F_EVP_DIGESTINIT				 136
#define EVP_F_EVP_DIGESTINIT_EX				 128
#define EVP_F_EVP_ENCRYPTFINAL_EX			 127
#define EVP_F_EVP_MD_CTX_COPY_EX			 110
#define EVP_F_EVP_OPENINIT				 102
#define EVP_F_EVP_PBE_ALG_ADD				 115
#define EVP_F_EVP_PBE_CIPHERINIT			 116
#define EVP_F_EVP_PKCS82PKEY				 111
#define EVP_F_EVP_PKEY2PKCS8_BROKEN			 113
#define EVP_F_EVP_PKEY_COPY_PARAMETERS			 103
#define EVP_F_EVP_PKEY_DECRYPT				 104
#define EVP_F_EVP_PKEY_ENCRYPT				 105
#define EVP_F_EVP_PKEY_GET1_DH				 119
#define EVP_F_EVP_PKEY_GET1_DSA				 120
#define EVP_F_EVP_PKEY_GET1_ECDSA			 130
#define EVP_F_EVP_PKEY_GET1_EC_KEY			 131
#define EVP_F_EVP_PKEY_GET1_RSA				 121
#define EVP_F_EVP_PKEY_NEW				 106
#define EVP_F_EVP_RIJNDAEL				 126
#define EVP_F_EVP_SIGNFINAL				 107
#define EVP_F_EVP_VERIFYFINAL				 108
#define EVP_F_PKCS5_PBE_KEYIVGEN			 117
#define EVP_F_PKCS5_V2_PBE_KEYIVGEN			 118
#define EVP_F_PKCS8_SET_BROKEN				 112
#define EVP_F_RC2_MAGIC_TO_METH				 109
#define EVP_F_RC5_CTRL					 125

/* Reason codes. */
#define EVP_R_AES_KEY_SETUP_FAILED			 143
#define EVP_R_ASN1_LIB					 140
#define EVP_R_BAD_BLOCK_LENGTH				 136
#define EVP_R_BAD_DECRYPT				 100
#define EVP_R_BAD_KEY_LENGTH				 137
#define EVP_R_BN_DECODE_ERROR				 112
#define EVP_R_BN_PUBKEY_ERROR				 113
#define EVP_R_CAMELLIA_KEY_SETUP_FAILED			 157
#define EVP_R_CIPHER_PARAMETER_ERROR			 122
#define EVP_R_CTRL_NOT_IMPLEMENTED			 132
#define EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED		 133
#define EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH		 138
#define EVP_R_DECODE_ERROR				 114
#define EVP_R_DIFFERENT_KEY_TYPES			 101
#define EVP_R_DISABLED_FOR_FIPS				 144
#define EVP_R_ENCODE_ERROR				 115
#define EVP_R_ERROR_LOADING_SECTION			 145
#define EVP_R_ERROR_SETTING_FIPS_MODE			 146
#define EVP_R_EVP_PBE_CIPHERINIT_ERROR			 119
#define EVP_R_EXPECTING_AN_RSA_KEY			 127
#define EVP_R_EXPECTING_A_DH_KEY			 128
#define EVP_R_EXPECTING_A_DSA_KEY			 129
#define EVP_R_EXPECTING_A_ECDSA_KEY			 141
#define EVP_R_EXPECTING_A_EC_KEY			 142
#define EVP_R_FIPS_MODE_NOT_SUPPORTED			 147
#define EVP_R_INITIALIZATION_ERROR			 134
#define EVP_R_INPUT_NOT_INITIALIZED			 111
#define EVP_R_INVALID_FIPS_MODE				 148
#define EVP_R_INVALID_KEY_LENGTH			 130
#define EVP_R_IV_TOO_LARGE				 102
#define EVP_R_KEYGEN_FAILURE				 120
#define EVP_R_MISSING_PARAMETERS			 103
#define EVP_R_NO_CIPHER_SET				 131
#define EVP_R_NO_DIGEST_SET				 139
#define EVP_R_NO_DSA_PARAMETERS				 116
#define EVP_R_NO_SIGN_FUNCTION_CONFIGURED		 104
#define EVP_R_NO_VERIFY_FUNCTION_CONFIGURED		 105
#define EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE			 117
#define EVP_R_PUBLIC_KEY_NOT_RSA			 106
#define EVP_R_UNKNOWN_OPTION				 149
#define EVP_R_UNKNOWN_PBE_ALGORITHM			 121
#define EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS		 135
#define EVP_R_UNSUPPORTED_CIPHER			 107
#define EVP_R_UNSUPPORTED_KEYLENGTH			 123
#define EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION	 124
#define EVP_R_UNSUPPORTED_KEY_SIZE			 108
#define EVP_R_UNSUPPORTED_PRF				 125
#define EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM		 118
#define EVP_R_UNSUPPORTED_SALT_TYPE			 126
#define EVP_R_WRONG_FINAL_BLOCK_LENGTH			 109
#define EVP_R_WRONG_PUBLIC_KEY_TYPE			 110
#define EVP_R_SEED_KEY_SETUP_FAILED			 162



#ifdef OPENSSL_NO_RSA
#error RSA is disabled.
#endif


#define RSA_FLAG_FIPS_METHOD			0x0400


#define RSA_FLAG_NON_FIPS_ALLOW			0x0400

#ifdef OPENSSL_FIPS
#define FIPS_RSA_SIZE_T	int
#endif


/* Declared already in ossl_typ.h */
/* typedef struct rsa_st RSA; */
/* typedef struct rsa_meth_st RSA_METHOD; */

struct rsa_meth_st
{
const char *name;
int (*rsa_pub_enc)(int flen,const unsigned char *from,
unsigned char *to,
RSA *rsa,int padding);
int (*rsa_pub_dec)(int flen,const unsigned char *from,
unsigned char *to,
RSA *rsa,int padding);
int (*rsa_priv_enc)(int flen,const unsigned char *from,
unsigned char *to,
RSA *rsa,int padding);
int (*rsa_priv_dec)(int flen,const unsigned char *from,
unsigned char *to,
RSA *rsa,int padding);
int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa,BN_CTX *ctx); /* Can be null */
int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
const BIGNUM *m, BN_CTX *ctx,
BN_MONT_CTX *m_ctx); /* Can be null */
int (*init)(RSA *rsa);		/* called at new */
int (*finish)(RSA *rsa);	/* called at free */
int flags;			/* RSA_METHOD_FLAG_* things */
char *app_data;			/* may be needed! */
/* New sign and verify functions: some libraries don't allow arbitrary data
 * to be signed/verified: this allows them to be used. Note: for this to work
 * the RSA_public_decrypt() and RSA_private_encrypt() should *NOT* be used
 * RSA_sign(), RSA_verify() should be used instead. Note: for backwards
 * compatibility this functionality is only enabled if the RSA_FLAG_SIGN_VER
 * option is set in 'flags'.
 */
int (*rsa_sign)(int type,
const unsigned char *m, unsigned int m_length,
unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
int (*rsa_verify)(int dtype,
const unsigned char *m, unsigned int m_length,
unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
/* If this callback is NULL, the builtin software RSA key-gen will be used. This
 * is for behavioural compatibility whilst the code gets rewired, but one day
 * it would be nice to assume there are no such things as "builtin software"
 * implementations. */
int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
};

struct rsa_st
{
/* The first parameter is used to pickup errors where
 * this is passed instead of aEVP_PKEY, it is set to 0 */
int pad;
long version;
const RSA_METHOD *meth;
/* functional reference if 'meth' is ENGINE-provided */
ENGINE *engine;
BIGNUM *n;
BIGNUM *e;
BIGNUM *d;
BIGNUM *p;
BIGNUM *q;
BIGNUM *dmp1;
BIGNUM *dmq1;
BIGNUM *iqmp;
/* be careful using this if the RSA structure is shared */
CRYPTO_EX_DATA ex_data;
int references;
int flags;

/* Used to cache montgomery values */
BN_MONT_CTX *_method_mod_n;
BN_MONT_CTX *_method_mod_p;
BN_MONT_CTX *_method_mod_q;

/* all BIGNUM values are actually in the following data, if it is not
 * NULL */
char *bignum_data;
BN_BLINDING *blinding;
BN_BLINDING *mt_blinding;
};

#ifndef OPENSSL_RSA_MAX_MODULUS_BITS
# define OPENSSL_RSA_MAX_MODULUS_BITS	16384
#endif

#define OPENSSL_RSA_FIPS_MIN_MODULUS_BITS 1024

#ifndef OPENSSL_RSA_SMALL_MODULUS_BITS
# define OPENSSL_RSA_SMALL_MODULUS_BITS	3072
#endif
#ifndef OPENSSL_RSA_MAX_PUBEXP_BITS
# define OPENSSL_RSA_MAX_PUBEXP_BITS	64 /* exponent limit enforced for "large" modulus only */
#endif

#define RSA_3	0x3L
#define RSA_F4	0x10001L

#define RSA_METHOD_FLAG_NO_CHECK	0x0001 /* don't check pub/private match */

#define RSA_FLAG_CACHE_PUBLIC		0x0002
#define RSA_FLAG_CACHE_PRIVATE		0x0004
#define RSA_FLAG_BLINDING		0x0008
#define RSA_FLAG_THREAD_SAFE		0x0010
/* This flag means the private key operations will be handled by rsa_mod_exp
 * and that they do not depend on the private key components being present:
 * for example a key stored in external hardware. Without this flag bn_mod_exp
 * gets called when private key components are absent.
 */
#define RSA_FLAG_EXT_PKEY		0x0020

/* This flag in the RSA_METHOD enables the new rsa_sign, rsa_verify functions.
 */
#define RSA_FLAG_SIGN_VER		0x0040

#define RSA_FLAG_NO_BLINDING		0x0080 /* new with 0.9.6j and 0.9.7b; the built-in
                                                * RSA implementation now uses blinding by
                                                * default (ignoring RSA_FLAG_BLINDING),
                                                * but other engines might not need it
                                                */
#define RSA_FLAG_NO_CONSTTIME		0x0100 /* new with 0.9.8f; the built-in RSA
						* implementation now uses constant time
						* operations by default in private key operations,
						* e.g., constant time modular exponentiation,
                                                * modular inverse without leaking branches,
                                                * division without leaking branches. This
                                                * flag disables these constant time
                                                * operations and results in faster RSA
                                                * private key operations.
                                                */
#ifndef OPENSSL_NO_DEPRECATED
#define RSA_FLAG_NO_EXP_CONSTTIME RSA_FLAG_NO_CONSTTIME /* deprecated name for the flag*/
/* new with 0.9.7h; the built-in RSA
* implementation now uses constant time
* modular exponentiation for secret exponents
* by default. This flag causes the
* faster variable sliding window method to
* be used for all exponents.
*/
#endif


#define RSA_PKCS1_PADDING	1
#define RSA_SSLV23_PADDING	2
#define RSA_NO_PADDING		3
#define RSA_PKCS1_OAEP_PADDING	4
#define RSA_X931_PADDING	5

#define RSA_PKCS1_PADDING_SIZE	11

#define RSA_set_app_data(s,arg)         RSA_set_ex_data(s,0,arg)
#define RSA_get_app_data(s)             RSA_get_ex_data(s,0)

RSA *	RSA_new(void);
RSA *	RSA_new_method(ENGINE *engine);
int	RSA_size(const RSA *);

/* Deprecated version */
#ifndef OPENSSL_NO_DEPRECATED
RSA *	RSA_generate_key(int bits, unsigned long e,void
(*callback)(int,int,void *),void *cb_arg);
#endif /* !defined(OPENSSL_NO_DEPRECATED) */

/* New version */
int	RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2,
const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *Xp,
const BIGNUM *Xq1, const BIGNUM *Xq2, const BIGNUM *Xq,
const BIGNUM *e, BN_GENCB *cb);
int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb);

int	RSA_check_key(const RSA *);
/* next 4 return -1 on error */
int	RSA_public_encrypt(int flen, const unsigned char *from,
unsigned char *to, RSA *rsa,int padding);
int	RSA_private_encrypt(int flen, const unsigned char *from,
unsigned char *to, RSA *rsa,int padding);
int	RSA_public_decrypt(int flen, const unsigned char *from,
unsigned char *to, RSA *rsa,int padding);
int	RSA_private_decrypt(int flen, const unsigned char *from,
unsigned char *to, RSA *rsa,int padding);
void	RSA_free (RSA *r);
/* "up" the RSA object's reference count */
int	RSA_up_ref(RSA *r);

int	RSA_flags(const RSA *r);

#ifdef OPENSSL_FIPS
RSA *FIPS_rsa_new(void);
void FIPS_rsa_free(RSA *r);
#endif

void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);

/* This function needs the memory locking malloc callbacks to be installed */
int RSA_memory_lock(RSA *r);

/* these are the actual SSLeay RSA functions */
const RSA_METHOD *RSA_PKCS1_SSLeay(void);

const RSA_METHOD *RSA_null_method(void);

DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

#ifdef OPENSSL_NO_FP_API
int	RSA_print_fp(FILE *fp, const RSA *r,int offset);
#endif

#ifndef OPENSSL_NO_BIO
int	RSA_print(BIO *bp, const RSA *r,int offset);
#endif

#ifndef OPENSSL_NO_RC4
int i2d_RSA_NET(const RSA *a, unsigned char **pp,
int (*cb)(char *buf, int len, const char *prompt, int verify),
int sgckey);
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length,
int (*cb)(char *buf, int len, const char *prompt, int verify),
int sgckey);

int i2d_Netscape_RSA(const RSA *a, unsigned char **pp,
int (*cb)(char *buf, int len, const char *prompt,
int verify));
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length,
int (*cb)(char *buf, int len, const char *prompt,
int verify));
#endif

/* The following 2 functions sign and verify a X509_SIG ASN1 object
 * inside PKCS#1 padded RSA encryption */
int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

/* The following 2 function sign and verify a ASN1_OCTET_STRING
 * object inside PKCS#1 padded RSA encryption */
int RSA_sign_ASN1_OCTET_STRING(int type,
const unsigned char *m, unsigned int m_length,
unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
const unsigned char *m, unsigned int m_length,
unsigned char *sigbuf, unsigned int siglen, RSA *rsa);

int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);

int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen,
const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len,
const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen,
const unsigned char *f,int fl,
const unsigned char *p,int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len,
const unsigned char *p,int pl);
int RSA_padding_add_SSLv23(unsigned char *to,int tlen,
const unsigned char *f,int fl);
int RSA_padding_check_SSLv23(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_none(unsigned char *to,int tlen,
const unsigned char *f,int fl);
int RSA_padding_check_none(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_X931(unsigned char *to,int tlen,
const unsigned char *f,int fl);
int RSA_padding_check_X931(unsigned char *to,int tlen,
const unsigned char *f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);

int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
const unsigned char *mHash,
const EVP_MD *Hash, int sLen);

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);

RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_RSA_strings(void);

/* Error codes for the RSA functions. */

/* Function codes. */
#define RSA_F_FIPS_RSA_SIGN				 140
#define RSA_F_FIPS_RSA_VERIFY				 141
#define RSA_F_MEMORY_LOCK				 100
#define RSA_F_RSA_BUILTIN_KEYGEN			 129
#define RSA_F_RSA_CHECK_KEY				 123
#define RSA_F_RSA_EAY_PRIVATE_DECRYPT			 101
#define RSA_F_RSA_EAY_PRIVATE_ENCRYPT			 102
#define RSA_F_RSA_EAY_PUBLIC_DECRYPT			 103
#define RSA_F_RSA_EAY_PUBLIC_ENCRYPT			 104
#define RSA_F_RSA_GENERATE_KEY				 105
#define RSA_F_RSA_MEMORY_LOCK				 130
#define RSA_F_RSA_NEW_METHOD				 106
#define RSA_F_RSA_NULL					 124
#define RSA_F_RSA_NULL_MOD_EXP				 131
#define RSA_F_RSA_NULL_PRIVATE_DECRYPT			 132
#define RSA_F_RSA_NULL_PRIVATE_ENCRYPT			 133
#define RSA_F_RSA_NULL_PUBLIC_DECRYPT			 134
#define RSA_F_RSA_NULL_PUBLIC_ENCRYPT			 135
#define RSA_F_RSA_PADDING_ADD_NONE			 107
#define RSA_F_RSA_PADDING_ADD_PKCS1_OAEP		 121
#define RSA_F_RSA_PADDING_ADD_PKCS1_PSS			 125
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1		 108
#define RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2		 109
#define RSA_F_RSA_PADDING_ADD_SSLV23			 110
#define RSA_F_RSA_PADDING_ADD_X931			 127
#define RSA_F_RSA_PADDING_CHECK_NONE			 111
#define RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP		 122
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1		 112
#define RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2		 113
#define RSA_F_RSA_PADDING_CHECK_SSLV23			 114
#define RSA_F_RSA_PADDING_CHECK_X931			 128
#define RSA_F_RSA_PRINT					 115
#define RSA_F_RSA_PRINT_FP				 116
#define RSA_F_RSA_PRIVATE_ENCRYPT			 137
#define RSA_F_RSA_PUBLIC_DECRYPT			 138
#define RSA_F_RSA_SETUP_BLINDING			 136
#define RSA_F_RSA_SET_DEFAULT_METHOD			 139
#define RSA_F_RSA_SET_METHOD				 142
#define RSA_F_RSA_SIGN					 117
#define RSA_F_RSA_SIGN_ASN1_OCTET_STRING		 118
#define RSA_F_RSA_VERIFY				 119
#define RSA_F_RSA_VERIFY_ASN1_OCTET_STRING		 120
#define RSA_F_RSA_VERIFY_PKCS1_PSS			 126

/* Reason codes. */
#define RSA_R_ALGORITHM_MISMATCH			 100
#define RSA_R_BAD_E_VALUE				 101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT			 102
#define RSA_R_BAD_PAD_BYTE_COUNT			 103
#define RSA_R_BAD_SIGNATURE				 104
#define RSA_R_BLOCK_TYPE_IS_NOT_01			 106
#define RSA_R_BLOCK_TYPE_IS_NOT_02			 107
#define RSA_R_DATA_GREATER_THAN_MOD_LEN			 108
#define RSA_R_DATA_TOO_LARGE				 109
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE		 110
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS		 132
#define RSA_R_DATA_TOO_SMALL				 111
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE		 122
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY		 112
#define RSA_R_DMP1_NOT_CONGRUENT_TO_D			 124
#define RSA_R_DMQ1_NOT_CONGRUENT_TO_D			 125
#define RSA_R_D_E_NOT_CONGRUENT_TO_1			 123
#define RSA_R_FIRST_OCTET_INVALID			 133
#define RSA_R_INVALID_HEADER				 137
#define RSA_R_INVALID_MESSAGE_LENGTH			 131
#define RSA_R_INVALID_PADDING				 138
#define RSA_R_INVALID_TRAILER				 139
#define RSA_R_IQMP_NOT_INVERSE_OF_Q			 126
#define RSA_R_KEY_SIZE_TOO_SMALL			 120
#define RSA_R_LAST_OCTET_INVALID			 134
#define RSA_R_MODULUS_TOO_LARGE				 105
#define RSA_R_NON_FIPS_METHOD				 141
#define RSA_R_NO_PUBLIC_EXPONENT			 140
#define RSA_R_NULL_BEFORE_BLOCK_MISSING			 113
#define RSA_R_N_DOES_NOT_EQUAL_P_Q			 127
#define RSA_R_OAEP_DECODING_ERROR			 121
#define RSA_R_OPERATION_NOT_ALLOWED_IN_FIPS_MODE	 142
#define RSA_R_PADDING_CHECK_FAILED			 114
#define RSA_R_P_NOT_PRIME				 128
#define RSA_R_Q_NOT_PRIME				 129
#define RSA_R_RSA_OPERATIONS_NOT_SUPPORTED		 130
#define RSA_R_SLEN_CHECK_FAILED				 136
#define RSA_R_SLEN_RECOVERY_FAILED			 135
#define RSA_R_SSLV3_ROLLBACK_ATTACK			 115
#define RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD 116
#define RSA_R_UNKNOWN_ALGORITHM_TYPE			 117
#define RSA_R_UNKNOWN_PADDING_TYPE			 118
#define RSA_R_WRONG_SIGNATURE_LENGTH			 119


#if defined(OPENSSL_NO_SHA) || (defined(OPENSSL_NO_SHA0) && defined(OPENSSL_NO_SHA1))
#error SHA is disabled.
#endif

#if defined(OPENSSL_FIPS)
#define FIPS_SHA_SIZE_T size_t
#endif

/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide. If it's wider, then !
 * ! SHA_LONG_LOG2 has to be defined along.                        !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */

#if defined(OPENSSL_SYS_WIN16) || defined(__LP32__)
#define SHA_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#define SHA_LONG unsigned long
#define SHA_LONG_LOG2 3
#else
#define SHA_LONG unsigned int
#endif

#define SHA_LBLOCK	16
#define SHA_CBLOCK	(SHA_LBLOCK*4)	/* SHA treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
#define SHA_DIGEST_LENGTH 20

typedef struct SHAstate_st
{
SHA_LONG h0,h1,h2,h3,h4;
SHA_LONG Nl,Nh;
SHA_LONG data[SHA_LBLOCK];
unsigned int num;
} SHA_CTX;

#ifndef OPENSSL_NO_SHA0
#ifdef OPENSSL_FIPS
int private_SHA_Init(SHA_CTX *c);
#endif
int SHA_Init(SHA_CTX *c);
int SHA_Update(SHA_CTX *c, const void *data, size_t len);
int SHA_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);
void SHA_Transform(SHA_CTX *c, const unsigned char *data);
#endif
#ifndef OPENSSL_NO_SHA1
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
#endif

#define SHA256_CBLOCK	(SHA_LBLOCK*4)	/* SHA-256 treats input data as a
					 * contiguous array of 32 bit
					 * wide big-endian values. */
#define SHA224_DIGEST_LENGTH	28
#define SHA256_DIGEST_LENGTH	32

typedef struct SHA256state_st
{
SHA_LONG h[8];
SHA_LONG Nl,Nh;
SHA_LONG data[SHA_LBLOCK];
unsigned int num,md_len;
} SHA256_CTX;

#ifndef OPENSSL_NO_SHA256
int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n,unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);
#endif

#define SHA384_DIGEST_LENGTH	48
#define SHA512_DIGEST_LENGTH	64

#ifndef OPENSSL_NO_SHA512
/*
 * Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
 * being exactly 64-bit wide. See Implementation Notes in sha512.c
 * for further details.
 */
#define SHA512_CBLOCK	(SHA_LBLOCK*8)	/* SHA-512 treats input data as a
					 * contiguous array of 64 bit
					 * wide big-endian values. */
#if (defined(_WIN32) || defined(_WIN64)) && !defined(__MINGW32__)
#define SHA_LONG64 unsigned __int64
#define U64(C)     C##UI64
#elif defined(__arch64__)
#define SHA_LONG64 unsigned long
#define U64(C)     C##UL
#else
#define SHA_LONG64 unsigned long long
#define U64(C)     C##ULL
#endif

typedef struct SHA512state_st
{
SHA_LONG64 h[8];
SHA_LONG64 Nl,Nh;
union {
SHA_LONG64	d[SHA_LBLOCK];
unsigned char	p[SHA512_CBLOCK];
} u;
unsigned int num,md_len;
} SHA512_CTX;
#endif

#ifndef OPENSSL_NO_SHA512
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);
#endif



#ifdef OPENSSL_NO_EC
#error EC is disabled.
#endif

#ifndef OPENSSL_ECC_MAX_FIELD_BITS
# define OPENSSL_ECC_MAX_FIELD_BITS 661
#endif

typedef enum {
/* values as defined in X9.62 (ECDSA) and elsewhere */
POINT_CONVERSION_COMPRESSED = 2,
POINT_CONVERSION_UNCOMPRESSED = 4,
POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


typedef struct ec_method_st EC_METHOD;

typedef struct ec_group_st
/*
 EC_METHOD *meth;
 -- field definition
 -- curve coefficients
 -- optional generator with associated information (order, cofactor)
 -- optional extra data (precomputed table for fast computation of multiples of generator)
 -- ASN1 stuff
*/
EC_GROUP;

typedef struct ec_point_st EC_POINT;


/* EC_METHODs for curves over GF(p).
 * EC_GFp_simple_method provides the basis for the optimized methods.
 */
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
const EC_METHOD *EC_GFp_nist_method(void);

/* EC_METHOD for curves over GF(2^m).
 */
const EC_METHOD *EC_GF2m_simple_method(void);


EC_GROUP *EC_GROUP_new(const EC_METHOD *);
void EC_GROUP_free(EC_GROUP *);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_copy(EC_GROUP *, const EC_GROUP *);
EC_GROUP *EC_GROUP_dup(const EC_GROUP *);

const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
int EC_METHOD_get_field_type(const EC_METHOD *);

int EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);

void EC_GROUP_set_curve_name(EC_GROUP *, int nid);
int EC_GROUP_get_curve_name(const EC_GROUP *);

void EC_GROUP_set_asn1_flag(EC_GROUP *, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *);

void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);

unsigned char *EC_GROUP_get0_seed(const EC_GROUP *);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);

int EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int EC_GROUP_set_curve_GF2m(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GF2m(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

/* returns the number of bits needed to represent a field element */
int EC_GROUP_get_degree(const EC_GROUP *);

/* EC_GROUP_check() returns 1 if 'group' defines a valid group, 0 otherwise */
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
/* EC_GROUP_check_discriminant() returns 1 if the discriminant of the
 * elliptic curve is not zero, 0 otherwise */
int EC_GROUP_check_discriminant(const EC_GROUP *, BN_CTX *);

/* EC_GROUP_cmp() returns 0 if both groups are equal and 1 otherwise */
int EC_GROUP_cmp(const EC_GROUP *, const EC_GROUP *, BN_CTX *);

/* EC_GROUP_new_GF*() calls EC_GROUP_new() and EC_GROUP_set_GF*()
 * after choosing an appropriate EC_METHOD */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

/* EC_GROUP_new_by_curve_name() creates a EC_GROUP structure
 * specified by a curve name (in form of a NID) */
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
/* handling of internal curves */
typedef struct {
int nid;
const char *comment;
} EC_builtin_curve;
/* EC_builtin_curves(EC_builtin_curve *r, size_t size) returns number
 * of all available curves or zero if a error occurred.
 * In case r ist not zero nitems EC_builtin_curve structures
 * are filled with the data of the first nitems internal groups */
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);


/* EC_POINT functions */

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

const EC_METHOD *EC_POINT_method_of(const EC_POINT *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *, EC_POINT *,
const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *, EC_POINT *,
const BIGNUM *x, int y_bit, BN_CTX *);

int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *, const EC_POINT *,
BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
const BIGNUM *x, int y_bit, BN_CTX *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
const unsigned char *buf, size_t len, BN_CTX *);

/* other interfaces to point2oct/oct2point: */
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
EC_POINT *, BN_CTX *);

int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);



/* ASN1 stuff */

/* EC_GROUP_get_basis_type() returns the NID of the basis type
 * used to represent the field elements */
int EC_GROUP_get_basis_type(const EC_GROUP *);
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
unsigned int *k2, unsigned int *k3);

#define OPENSSL_EC_NAMED_CURVE	0x001

typedef struct ecpk_parameters_st ECPKPARAMETERS;

EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);

#define d2i_ECPKParameters_bio(bp,x) ASN1_d2i_bio_of(EC_GROUP,NULL,d2i_ECPKParameters,bp,x)
#define i2d_ECPKParameters_bio(bp,x) ASN1_i2d_bio_of_const(EC_GROUP,i2d_ECPKParameters,bp,x)
#define d2i_ECPKParameters_fp(fp,x) (EC_GROUP *)ASN1_d2i_fp(NULL, \
                (char *(*)())d2i_ECPKParameters,(fp),(unsigned char **)(x))
#define i2d_ECPKParameters_fp(fp,x) ASN1_i2d_fp(i2d_ECPKParameters,(fp), \
		(unsigned char *)(x))

#ifndef OPENSSL_NO_BIO
int     ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
#endif
#ifdef OPENSSL_NO_FP_API
int     ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);
#endif

/* the EC_KEY stuff */
typedef struct ec_key_st EC_KEY;

/* some values for the encoding_flag */
#define EC_PKEY_NO_PARAMETERS	0x001
#define EC_PKEY_NO_PUBKEY	0x002

EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);

int EC_KEY_up_ref(EC_KEY *);

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);
unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *);
void EC_KEY_set_conv_form(EC_KEY *, point_conversion_form_t);
/* functions to set/get method specific data  */
void *EC_KEY_get_key_method_data(EC_KEY *,
void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
void EC_KEY_insert_key_method_data(EC_KEY *, void *data,
void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
/* wrapper functions for the underlying EC_GROUP object */
void EC_KEY_set_asn1_flag(EC_KEY *, int);
int EC_KEY_precompute_mult(EC_KEY *, BN_CTX *ctx);

/* EC_KEY_generate_key() creates a ec private (public) key */
int EC_KEY_generate_key(EC_KEY *);
/* EC_KEY_check_key() */
int EC_KEY_check_key(const EC_KEY *);

/* de- and encoding functions for SEC1 ECPrivateKey */
EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECPrivateKey(EC_KEY *a, unsigned char **out);
/* de- and encoding functions for EC parameters */
EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECParameters(EC_KEY *a, unsigned char **out);
/* de- and encoding functions for EC public key
 * (octet string, not DER -- hence 'o2i' and 'i2o') */
EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len);
int i2o_ECPublicKey(EC_KEY *a, unsigned char **out);

#ifndef OPENSSL_NO_BIO
int	ECParameters_print(BIO *bp, const EC_KEY *x);
int	EC_KEY_print(BIO *bp, const EC_KEY *x, int off);
#endif
#ifdef OPENSSL_NO_FP_API
int	ECParameters_print_fp(FILE *fp, const EC_KEY *x);
int	EC_KEY_print_fp(FILE *fp, const EC_KEY *x, int off);
#endif

#define ECParameters_dup(x) ASN1_dup_of(EC_KEY,i2d_ECParameters,d2i_ECParameters,x)

#ifndef __cplusplus
#if defined(__SUNPRO_C)
#  if __SUNPRO_C >= 0x520
# pragma error_messages (default,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
#  endif
# endif
#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_EC_strings(void);

/* Error codes for the EC functions. */

/* Function codes. */
#define EC_F_COMPUTE_WNAF				 143
#define EC_F_D2I_ECPARAMETERS				 144
#define EC_F_D2I_ECPKPARAMETERS				 145
#define EC_F_D2I_ECPRIVATEKEY				 146
#define EC_F_ECPARAMETERS_PRINT				 147
#define EC_F_ECPARAMETERS_PRINT_FP			 148
#define EC_F_ECPKPARAMETERS_PRINT			 149
#define EC_F_ECPKPARAMETERS_PRINT_FP			 150
#define EC_F_ECP_NIST_MOD_192				 203
#define EC_F_ECP_NIST_MOD_224				 204
#define EC_F_ECP_NIST_MOD_256				 205
#define EC_F_ECP_NIST_MOD_521				 206
#define EC_F_EC_ASN1_GROUP2CURVE			 153
#define EC_F_EC_ASN1_GROUP2FIELDID			 154
#define EC_F_EC_ASN1_GROUP2PARAMETERS			 155
#define EC_F_EC_ASN1_GROUP2PKPARAMETERS			 156
#define EC_F_EC_ASN1_PARAMETERS2GROUP			 157
#define EC_F_EC_ASN1_PKPARAMETERS2GROUP			 158
#define EC_F_EC_EX_DATA_SET_DATA			 211
#define EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY		 208
#define EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT	 159
#define EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE		 195
#define EC_F_EC_GF2M_SIMPLE_OCT2POINT			 160
#define EC_F_EC_GF2M_SIMPLE_POINT2OCT			 161
#define EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES 162
#define EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES 163
#define EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES	 164
#define EC_F_EC_GFP_MONT_FIELD_DECODE			 133
#define EC_F_EC_GFP_MONT_FIELD_ENCODE			 134
#define EC_F_EC_GFP_MONT_FIELD_MUL			 131
#define EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE		 209
#define EC_F_EC_GFP_MONT_FIELD_SQR			 132
#define EC_F_EC_GFP_MONT_GROUP_SET_CURVE		 189
#define EC_F_EC_GFP_MONT_GROUP_SET_CURVE_GFP		 135
#define EC_F_EC_GFP_NIST_FIELD_MUL			 200
#define EC_F_EC_GFP_NIST_FIELD_SQR			 201
#define EC_F_EC_GFP_NIST_GROUP_SET_CURVE		 202
#define EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT	 165
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE		 166
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE_GFP		 100
#define EC_F_EC_GFP_SIMPLE_GROUP_SET_GENERATOR		 101
#define EC_F_EC_GFP_SIMPLE_MAKE_AFFINE			 102
#define EC_F_EC_GFP_SIMPLE_OCT2POINT			 103
#define EC_F_EC_GFP_SIMPLE_POINT2OCT			 104
#define EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE		 137
#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES	 167
#define EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES_GFP 105
#define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES	 168
#define EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES_GFP 128
#define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES	 169
#define EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES_GFP 129
#define EC_F_EC_GROUP_CHECK				 170
#define EC_F_EC_GROUP_CHECK_DISCRIMINANT		 171
#define EC_F_EC_GROUP_COPY				 106
#define EC_F_EC_GROUP_GET0_GENERATOR			 139
#define EC_F_EC_GROUP_GET_COFACTOR			 140
#define EC_F_EC_GROUP_GET_CURVE_GF2M			 172
#define EC_F_EC_GROUP_GET_CURVE_GFP			 130
#define EC_F_EC_GROUP_GET_DEGREE			 173
#define EC_F_EC_GROUP_GET_ORDER				 141
#define EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS		 193
#define EC_F_EC_GROUP_GET_TRINOMIAL_BASIS		 194
#define EC_F_EC_GROUP_NEW				 108
#define EC_F_EC_GROUP_NEW_BY_CURVE_NAME			 174
#define EC_F_EC_GROUP_NEW_FROM_DATA			 175
#define EC_F_EC_GROUP_PRECOMPUTE_MULT			 142
#define EC_F_EC_GROUP_SET_CURVE_GF2M			 176
#define EC_F_EC_GROUP_SET_CURVE_GFP			 109
#define EC_F_EC_GROUP_SET_EXTRA_DATA			 110
#define EC_F_EC_GROUP_SET_GENERATOR			 111
#define EC_F_EC_KEY_CHECK_KEY				 177
#define EC_F_EC_KEY_COPY				 178
#define EC_F_EC_KEY_GENERATE_KEY			 179
#define EC_F_EC_KEY_NEW					 182
#define EC_F_EC_KEY_PRINT				 180
#define EC_F_EC_KEY_PRINT_FP				 181
#define EC_F_EC_POINTS_MAKE_AFFINE			 136
#define EC_F_EC_POINTS_MUL				 138
#define EC_F_EC_POINT_ADD				 112
#define EC_F_EC_POINT_CMP				 113
#define EC_F_EC_POINT_COPY				 114
#define EC_F_EC_POINT_DBL				 115
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M	 183
#define EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP	 116
#define EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP	 117
#define EC_F_EC_POINT_INVERT				 210
#define EC_F_EC_POINT_IS_AT_INFINITY			 118
#define EC_F_EC_POINT_IS_ON_CURVE			 119
#define EC_F_EC_POINT_MAKE_AFFINE			 120
#define EC_F_EC_POINT_MUL				 184
#define EC_F_EC_POINT_NEW				 121
#define EC_F_EC_POINT_OCT2POINT				 122
#define EC_F_EC_POINT_POINT2OCT				 123
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M	 185
#define EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP	 124
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M	 186
#define EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP	 125
#define EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP	 126
#define EC_F_EC_POINT_SET_TO_INFINITY			 127
#define EC_F_EC_PRE_COMP_DUP				 207
#define EC_F_EC_PRE_COMP_NEW				 196
#define EC_F_EC_WNAF_MUL				 187
#define EC_F_EC_WNAF_PRECOMPUTE_MULT			 188
#define EC_F_I2D_ECPARAMETERS				 190
#define EC_F_I2D_ECPKPARAMETERS				 191
#define EC_F_I2D_ECPRIVATEKEY				 192
#define EC_F_I2O_ECPUBLICKEY				 151
#define EC_F_O2I_ECPUBLICKEY				 152

/* Reason codes. */
#define EC_R_ASN1_ERROR					 115
#define EC_R_ASN1_UNKNOWN_FIELD				 116
#define EC_R_BUFFER_TOO_SMALL				 100
#define EC_R_D2I_ECPKPARAMETERS_FAILURE			 117
#define EC_R_DISCRIMINANT_IS_ZERO			 118
#define EC_R_EC_GROUP_NEW_BY_NAME_FAILURE		 119
#define EC_R_FIELD_TOO_LARGE				 138
#define EC_R_GROUP2PKPARAMETERS_FAILURE			 120
#define EC_R_I2D_ECPKPARAMETERS_FAILURE			 121
#define EC_R_INCOMPATIBLE_OBJECTS			 101
#define EC_R_INVALID_ARGUMENT				 112
#define EC_R_INVALID_COMPRESSED_POINT			 110
#define EC_R_INVALID_COMPRESSION_BIT			 109
#define EC_R_INVALID_ENCODING				 102
#define EC_R_INVALID_FIELD				 103
#define EC_R_INVALID_FORM				 104
#define EC_R_INVALID_GROUP_ORDER			 122
#define EC_R_INVALID_PENTANOMIAL_BASIS			 132
#define EC_R_INVALID_PRIVATE_KEY			 123
#define EC_R_INVALID_TRINOMIAL_BASIS			 137
#define EC_R_MISSING_PARAMETERS				 124
#define EC_R_MISSING_PRIVATE_KEY			 125
#define EC_R_NOT_A_NIST_PRIME				 135
#define EC_R_NOT_A_SUPPORTED_NIST_PRIME			 136
#define EC_R_NOT_IMPLEMENTED				 126
#define EC_R_NOT_INITIALIZED				 111
#define EC_R_NO_FIELD_MOD				 133
#define EC_R_PASSED_NULL_PARAMETER			 134
#define EC_R_PKPARAMETERS2GROUP_FAILURE			 127
#define EC_R_POINT_AT_INFINITY				 106
#define EC_R_POINT_IS_NOT_ON_CURVE			 107
#define EC_R_SLOT_FULL					 108
#define EC_R_UNDEFINED_GENERATOR			 113
#define EC_R_UNDEFINED_ORDER				 128
#define EC_R_UNKNOWN_GROUP				 129
#define EC_R_UNKNOWN_ORDER				 114
#define EC_R_UNSUPPORTED_FIELD				 131
#define EC_R_WRONG_ORDER				 130


//#include <stddef.h>
typedef unsigned int size_t;
//#define offsetof(s,m)   (size_t)&(((s *)0)->m)

/* Already declared in ossl_typ.h */
/* typedef struct buf_mem_st BUF_MEM; */

struct buf_mem_st
{
int length;	/* current number of bytes */
char *data;
int max;	/* size of buffer */
};

BUF_MEM *BUF_MEM_new(void);
void	BUF_MEM_free(BUF_MEM *a);
int	BUF_MEM_grow(BUF_MEM *str, int len);
int	BUF_MEM_grow_clean(BUF_MEM *str, int len);
char *	BUF_strdup(const char *str);
char *	BUF_strndup(const char *str, size_t siz);
void *	BUF_memdup(const void *data, size_t siz);

/* safe string functions */
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
size_t BUF_strlcat(char *dst,const char *src,size_t siz);


/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_BUF_strings(void);

/* Error codes for the BUF functions. */

/* Function codes. */
#define BUF_F_BUF_MEMDUP				 103
#define BUF_F_BUF_MEM_GROW				 100
#define BUF_F_BUF_MEM_GROW_CLEAN			 105
#define BUF_F_BUF_MEM_NEW				 101
#define BUF_F_BUF_STRDUP				 102
#define BUF_F_BUF_STRNDUP				 104


#ifdef OPENSSL_SYS_WIN32
/* Under Win32 these are defined in wincrypt.h */
#undef X509_NAME
#undef X509_CERT_PAIR
#undef X509_EXTENSIONS
#endif

#define X509_FILETYPE_PEM	1
#define X509_FILETYPE_ASN1	2
#define X509_FILETYPE_DEFAULT	3

#define X509v3_KU_DIGITAL_SIGNATURE	0x0080
#define X509v3_KU_NON_REPUDIATION	0x0040
#define X509v3_KU_KEY_ENCIPHERMENT	0x0020
#define X509v3_KU_DATA_ENCIPHERMENT	0x0010
#define X509v3_KU_KEY_AGREEMENT		0x0008
#define X509v3_KU_KEY_CERT_SIGN		0x0004
#define X509v3_KU_CRL_SIGN		0x0002
#define X509v3_KU_ENCIPHER_ONLY		0x0001
#define X509v3_KU_DECIPHER_ONLY		0x8000
#define X509v3_KU_UNDEF			0xffff

typedef struct X509_objects_st
{
int nid;
int (*a2i)(void);
int (*i2a)(void);
} X509_OBJECTS;

struct X509_algor_st
{
ASN1_OBJECT *algorithm;
ASN1_TYPE *parameter;
} /* X509_ALGOR */;

DECLARE_ASN1_SET_OF(X509_ALGOR)

typedef STACK_OF(X509_ALGOR) X509_ALGORS;

typedef struct X509_val_st
{
ASN1_TIME *notBefore;
ASN1_TIME *notAfter;
} X509_VAL;

typedef struct X509_pubkey_st
{
X509_ALGOR *algor;
ASN1_BIT_STRING *public_key;
EVP_PKEY *pkey;
} X509_PUBKEY;

typedef struct X509_sig_st
{
X509_ALGOR *algor;
ASN1_OCTET_STRING *digest;
} X509_SIG;

typedef struct X509_name_entry_st
{
ASN1_OBJECT *object;
ASN1_STRING *value;
int set;
int size; 	/* temp variable */
} X509_NAME_ENTRY;

DECLARE_STACK_OF(X509_NAME_ENTRY)
DECLARE_ASN1_SET_OF(X509_NAME_ENTRY)

/* we always keep X509_NAMEs in 2 forms. */
struct X509_name_st
{
STACK_OF(X509_NAME_ENTRY) *entries;
int modified;	/* true if 'bytes' needs to be built */
#ifndef OPENSSL_NO_BUFFER
BUF_MEM *bytes;
#else
char *bytes;
#endif
unsigned long hash; /* Keep the hash around for lookups */
} /* X509_NAME */;

DECLARE_STACK_OF(X509_NAME)

#define X509_EX_V_NETSCAPE_HACK		0x8000
#define X509_EX_V_INIT			0x0001
typedef struct X509_extension_st
{
ASN1_OBJECT *object;
ASN1_BOOLEAN critical;
ASN1_OCTET_STRING *value;
} X509_EXTENSION;

typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;

DECLARE_STACK_OF(X509_EXTENSION)
DECLARE_ASN1_SET_OF(X509_EXTENSION)

/* a sequence of these are used */
typedef struct x509_attributes_st
{
ASN1_OBJECT *object;
int single; /* 0 for a set, 1 for a single item (which is wrong) */
union	{
char		*ptr;
/* 0 */		STACK_OF(ASN1_TYPE) *set;
/* 1 */		ASN1_TYPE	*single;
} value;
} X509_ATTRIBUTE;

DECLARE_STACK_OF(X509_ATTRIBUTE)
DECLARE_ASN1_SET_OF(X509_ATTRIBUTE)


typedef struct X509_req_info_st
{
ASN1_ENCODING enc;
ASN1_INTEGER *version;
X509_NAME *subject;
X509_PUBKEY *pubkey;
/*  d=2 hl=2 l=  0 cons: cont: 00 */
STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} X509_REQ_INFO;

typedef struct X509_req_st
{
X509_REQ_INFO *req_info;
X509_ALGOR *sig_alg;
ASN1_BIT_STRING *signature;
int references;
} X509_REQ;

typedef struct x509_cinf_st
{
ASN1_INTEGER *version;		/* [ 0 ] default of v1 */
ASN1_INTEGER *serialNumber;
X509_ALGOR *signature;
X509_NAME *issuer;
X509_VAL *validity;
X509_NAME *subject;
X509_PUBKEY *key;
ASN1_BIT_STRING *issuerUID;		/* [ 1 ] optional in v2 */
ASN1_BIT_STRING *subjectUID;		/* [ 2 ] optional in v2 */
STACK_OF(X509_EXTENSION) *extensions;	/* [ 3 ] optional in v3 */
ASN1_ENCODING enc;
} X509_CINF;

/* This stuff is certificate "auxiliary info"
 * it contains details which are useful in certificate
 * stores and databases. When used this is tagged onto
 * the end of the certificate itself
 */

typedef struct x509_cert_aux_st
{
STACK_OF(ASN1_OBJECT) *trust;		/* trusted uses */
STACK_OF(ASN1_OBJECT) *reject;		/* rejected uses */
ASN1_UTF8STRING *alias;			/* "friendly name" */
ASN1_OCTET_STRING *keyid;		/* key id of private key */
STACK_OF(X509_ALGOR) *other;		/* other unspecified info */
} X509_CERT_AUX;

struct x509_st
{
X509_CINF *cert_info;
X509_ALGOR *sig_alg;
ASN1_BIT_STRING *signature;
int valid;
int references;
char *name;
CRYPTO_EX_DATA ex_data;
/* These contain copies of various extension values */
long ex_pathlen;
long ex_pcpathlen;
unsigned long ex_flags;
unsigned long ex_kusage;
unsigned long ex_xkusage;
unsigned long ex_nscert;
ASN1_OCTET_STRING *skid;
struct AUTHORITY_KEYID_st *akid;
X509_POLICY_CACHE *policy_cache;
#ifndef OPENSSL_NO_RFC3779
STACK_OF(IPAddressFamily) *rfc3779_addr;
struct ASIdentifiers_st *rfc3779_asid;
#endif
#ifndef OPENSSL_NO_SHA
unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
X509_CERT_AUX *aux;
} /* X509 */;

DECLARE_STACK_OF(X509)
DECLARE_ASN1_SET_OF(X509)

/* This is used for a table of trust checking functions */

typedef struct x509_trust_st {
int trust;
int flags;
int (*check_trust)(struct x509_trust_st *, X509 *, int);
char *name;
int arg1;
void *arg2;
} X509_TRUST;

DECLARE_STACK_OF(X509_TRUST)

typedef struct x509_cert_pair_st {
X509 *forward;
X509 *reverse;
} X509_CERT_PAIR;

/* standard trust ids */

#define X509_TRUST_DEFAULT	-1	/* Only valid in purpose settings */

#define X509_TRUST_COMPAT	1
#define X509_TRUST_SSL_CLIENT	2
#define X509_TRUST_SSL_SERVER	3
#define X509_TRUST_EMAIL	4
#define X509_TRUST_OBJECT_SIGN	5
#define X509_TRUST_OCSP_SIGN	6
#define X509_TRUST_OCSP_REQUEST	7

/* Keep these up to date! */
#define X509_TRUST_MIN		1
#define X509_TRUST_MAX		7


/* trust_flags values */
#define	X509_TRUST_DYNAMIC 	1
#define	X509_TRUST_DYNAMIC_NAME	2

/* check_trust return codes */

#define X509_TRUST_TRUSTED	1
#define X509_TRUST_REJECTED	2
#define X509_TRUST_UNTRUSTED	3

/* Flags for X509_print_ex() */

#define	X509_FLAG_COMPAT		0
#define	X509_FLAG_NO_HEADER		1L
#define	X509_FLAG_NO_VERSION		(1L << 1)
#define	X509_FLAG_NO_SERIAL		(1L << 2)
#define	X509_FLAG_NO_SIGNAME		(1L << 3)
#define	X509_FLAG_NO_ISSUER		(1L << 4)
#define	X509_FLAG_NO_VALIDITY		(1L << 5)
#define	X509_FLAG_NO_SUBJECT		(1L << 6)
#define	X509_FLAG_NO_PUBKEY		(1L << 7)
#define	X509_FLAG_NO_EXTENSIONS		(1L << 8)
#define	X509_FLAG_NO_SIGDUMP		(1L << 9)
#define	X509_FLAG_NO_AUX		(1L << 10)
#define	X509_FLAG_NO_ATTRIBUTES		(1L << 11)

/* Flags specific to X509_NAME_print_ex() */

/* The field separator information */

#define XN_FLAG_SEP_MASK	(0xf << 16)

#define XN_FLAG_COMPAT		0		/* Traditional SSLeay: use old X509_NAME_print */
#define XN_FLAG_SEP_COMMA_PLUS	(1 << 16)	/* RFC2253 ,+ */
#define XN_FLAG_SEP_CPLUS_SPC	(2 << 16)	/* ,+ spaced: more readable */
#define XN_FLAG_SEP_SPLUS_SPC	(3 << 16)	/* ;+ spaced */
#define XN_FLAG_SEP_MULTILINE	(4 << 16)	/* One line per field */

#define XN_FLAG_DN_REV		(1 << 20)	/* Reverse DN order */

/* How the field name is shown */

#define XN_FLAG_FN_MASK		(0x3 << 21)

#define XN_FLAG_FN_SN		0		/* Object short name */
#define XN_FLAG_FN_LN		(1 << 21)	/* Object long name */
#define XN_FLAG_FN_OID		(2 << 21)	/* Always use OIDs */
#define XN_FLAG_FN_NONE		(3 << 21)	/* No field names */

#define XN_FLAG_SPC_EQ		(1 << 23)	/* Put spaces round '=' */

/* This determines if we dump fields we don't recognise:
 * RFC2253 requires this.
 */

#define XN_FLAG_DUMP_UNKNOWN_FIELDS (1 << 24)

#define XN_FLAG_FN_ALIGN	(1 << 25)	/* Align field names to 20 characters */

/* Complete set of RFC2253 flags */

#define XN_FLAG_RFC2253 (ASN1_STRFLGS_RFC2253 | \
			XN_FLAG_SEP_COMMA_PLUS | \
			XN_FLAG_DN_REV | \
			XN_FLAG_FN_SN | \
			XN_FLAG_DUMP_UNKNOWN_FIELDS)

/* readable oneline form */

#define XN_FLAG_ONELINE (ASN1_STRFLGS_RFC2253 | \
			ASN1_STRFLGS_ESC_QUOTE | \
			XN_FLAG_SEP_CPLUS_SPC | \
			XN_FLAG_SPC_EQ | \
			XN_FLAG_FN_SN)

/* readable multiline form */

#define XN_FLAG_MULTILINE (ASN1_STRFLGS_ESC_CTRL | \
			ASN1_STRFLGS_ESC_MSB | \
			XN_FLAG_SEP_MULTILINE | \
			XN_FLAG_SPC_EQ | \
			XN_FLAG_FN_LN | \
			XN_FLAG_FN_ALIGN)

typedef struct X509_revoked_st
{
ASN1_INTEGER *serialNumber;
ASN1_TIME *revocationDate;
STACK_OF(X509_EXTENSION) /* optional */ *extensions;
int sequence; /* load sequence */
} X509_REVOKED;

DECLARE_STACK_OF(X509_REVOKED)
DECLARE_ASN1_SET_OF(X509_REVOKED)

typedef struct X509_crl_info_st
{
ASN1_INTEGER *version;
X509_ALGOR *sig_alg;
X509_NAME *issuer;
ASN1_TIME *lastUpdate;
ASN1_TIME *nextUpdate;
STACK_OF(X509_REVOKED) *revoked;
STACK_OF(X509_EXTENSION) /* [0] */ *extensions;
ASN1_ENCODING enc;
} X509_CRL_INFO;

struct X509_crl_st
{
/* actual signature */
X509_CRL_INFO *crl;
X509_ALGOR *sig_alg;
ASN1_BIT_STRING *signature;
int references;
} /* X509_CRL */;

DECLARE_STACK_OF(X509_CRL)
DECLARE_ASN1_SET_OF(X509_CRL)

typedef struct private_key_st
{
int version;
/* The PKCS#8 data types */
X509_ALGOR *enc_algor;
ASN1_OCTET_STRING *enc_pkey;	/* encrypted pub key */

/* When decrypted, the following will not be NULL */
EVP_PKEY *dec_pkey;

/* used to encrypt and decrypt */
int key_length;
char *key_data;
int key_free;	/* true if we should auto free key_data */

/* expanded version of 'enc_algor' */
EVP_CIPHER_INFO cipher;

int references;
} X509_PKEY;

#ifndef OPENSSL_NO_EVP
typedef struct X509_info_st
{
X509 *x509;
X509_CRL *crl;
X509_PKEY *x_pkey;

EVP_CIPHER_INFO enc_cipher;
int enc_len;
char *enc_data;

int references;
} X509_INFO;

DECLARE_STACK_OF(X509_INFO)
#endif

/* The next 2 structures and their 8 routines were sent to me by
 * Pat Richard <patr@x509.com> and are used to manipulate
 * Netscapes spki structures - useful if you are writing a CA web page
 */
typedef struct Netscape_spkac_st
{
X509_PUBKEY *pubkey;
ASN1_IA5STRING *challenge;	/* challenge sent in atlas >= PR2 */
} NETSCAPE_SPKAC;

typedef struct Netscape_spki_st
{
NETSCAPE_SPKAC *spkac;	/* signed public key and challenge */
X509_ALGOR *sig_algor;
ASN1_BIT_STRING *signature;
} NETSCAPE_SPKI;

/* Netscape certificate sequence structure */
typedef struct Netscape_certificate_sequence
{
ASN1_OBJECT *type;
STACK_OF(X509) *certs;
} NETSCAPE_CERT_SEQUENCE;

/* Unused (and iv length is wrong)
typedef struct CBCParameter_st
	{
	unsigned char iv[8];
	} CBC_PARAM;
*/

/* Password based encryption structure */

typedef struct PBEPARAM_st {
ASN1_OCTET_STRING *salt;
ASN1_INTEGER *iter;
} PBEPARAM;

/* Password based encryption V2 structures */

typedef struct PBE2PARAM_st {
X509_ALGOR *keyfunc;
X509_ALGOR *encryption;
} PBE2PARAM;

typedef struct PBKDF2PARAM_st {
ASN1_TYPE *salt;	/* Usually OCTET STRING but could be anything */
ASN1_INTEGER *iter;
ASN1_INTEGER *keylength;
X509_ALGOR *prf;
} PBKDF2PARAM;


/* PKCS#8 private key info structure */

typedef struct pkcs8_priv_key_info_st
{
int broken;     /* Flag for various broken formats */
#define PKCS8_OK		0
#define PKCS8_NO_OCTET		1
#define PKCS8_EMBEDDED_PARAM	2
#define PKCS8_NS_DB		3
ASN1_INTEGER *version;
X509_ALGOR *pkeyalg;
ASN1_TYPE *pkey; /* Should be OCTET STRING but some are broken */
STACK_OF(X509_ATTRIBUTE) *attributes;
} PKCS8_PRIV_KEY_INFO;

#ifdef  __cplusplus
}
#endif

#include "x509_vfy.h"
#include "pkcs7.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef SSLEAY_MACROS
#define X509_verify(a,r) ASN1_verify((int (*)())i2d_X509_CINF,a->sig_alg,\
	a->signature,(char *)a->cert_info,r)
#define X509_REQ_verify(a,r) ASN1_verify((int (*)())i2d_X509_REQ_INFO, \
	a->sig_alg,a->signature,(char *)a->req_info,r)
#define X509_CRL_verify(a,r) ASN1_verify((int (*)())i2d_X509_CRL_INFO, \
	a->sig_alg, a->signature,(char *)a->crl,r)

#define X509_sign(x,pkey,md) \
	ASN1_sign((int (*)())i2d_X509_CINF, x->cert_info->signature, \
		x->sig_alg, x->signature, (char *)x->cert_info,pkey,md)
#define X509_REQ_sign(x,pkey,md) \
	ASN1_sign((int (*)())i2d_X509_REQ_INFO,x->sig_alg, NULL, \
		x->signature, (char *)x->req_info,pkey,md)
#define X509_CRL_sign(x,pkey,md) \
	ASN1_sign((int (*)())i2d_X509_CRL_INFO,x->crl->sig_alg,x->sig_alg, \
		x->signature, (char *)x->crl,pkey,md)
#define NETSCAPE_SPKI_sign(x,pkey,md) \
	ASN1_sign((int (*)())i2d_NETSCAPE_SPKAC, x->sig_algor,NULL, \
		x->signature, (char *)x->spkac,pkey,md)

#define X509_dup(x509) (X509 *)ASN1_dup((int (*)())i2d_X509, \
		(char *(*)())d2i_X509,(char *)x509)
#define X509_ATTRIBUTE_dup(xa) (X509_ATTRIBUTE *)ASN1_dup(\
		(int (*)())i2d_X509_ATTRIBUTE, \
		(char *(*)())d2i_X509_ATTRIBUTE,(char *)xa)
#define X509_EXTENSION_dup(ex) (X509_EXTENSION *)ASN1_dup( \
		(int (*)())i2d_X509_EXTENSION, \
		(char *(*)())d2i_X509_EXTENSION,(char *)ex)
#define d2i_X509_fp(fp,x509) (X509 *)ASN1_d2i_fp((char *(*)())X509_new, \
		(char *(*)())d2i_X509, (fp),(unsigned char **)(x509))
#define i2d_X509_fp(fp,x509) ASN1_i2d_fp(i2d_X509,fp,(unsigned char *)x509)
#define d2i_X509_bio(bp,x509) (X509 *)ASN1_d2i_bio((char *(*)())X509_new, \
		(char *(*)())d2i_X509, (bp),(unsigned char **)(x509))
#define i2d_X509_bio(bp,x509) ASN1_i2d_bio(i2d_X509,bp,(unsigned char *)x509)

#define X509_CRL_dup(crl) (X509_CRL *)ASN1_dup((int (*)())i2d_X509_CRL, \
		(char *(*)())d2i_X509_CRL,(char *)crl)
#define d2i_X509_CRL_fp(fp,crl) (X509_CRL *)ASN1_d2i_fp((char *(*)()) \
		X509_CRL_new,(char *(*)())d2i_X509_CRL, (fp),\
		(unsigned char **)(crl))
#define i2d_X509_CRL_fp(fp,crl) ASN1_i2d_fp(i2d_X509_CRL,fp,\
		(unsigned char *)crl)
#define d2i_X509_CRL_bio(bp,crl) (X509_CRL *)ASN1_d2i_bio((char *(*)()) \
		X509_CRL_new,(char *(*)())d2i_X509_CRL, (bp),\
		(unsigned char **)(crl))
#define i2d_X509_CRL_bio(bp,crl) ASN1_i2d_bio(i2d_X509_CRL,bp,\
		(unsigned char *)crl)

#define PKCS7_dup(p7) (PKCS7 *)ASN1_dup((int (*)())i2d_PKCS7, \
		(char *(*)())d2i_PKCS7,(char *)p7)
#define d2i_PKCS7_fp(fp,p7) (PKCS7 *)ASN1_d2i_fp((char *(*)()) \
		PKCS7_new,(char *(*)())d2i_PKCS7, (fp),\
		(unsigned char **)(p7))
#define i2d_PKCS7_fp(fp,p7) ASN1_i2d_fp(i2d_PKCS7,fp,\
		(unsigned char *)p7)
#define d2i_PKCS7_bio(bp,p7) (PKCS7 *)ASN1_d2i_bio((char *(*)()) \
		PKCS7_new,(char *(*)())d2i_PKCS7, (bp),\
		(unsigned char **)(p7))
#define i2d_PKCS7_bio(bp,p7) ASN1_i2d_bio(i2d_PKCS7,bp,\
		(unsigned char *)p7)

#define X509_REQ_dup(req) (X509_REQ *)ASN1_dup((int (*)())i2d_X509_REQ, \
		(char *(*)())d2i_X509_REQ,(char *)req)
#define d2i_X509_REQ_fp(fp,req) (X509_REQ *)ASN1_d2i_fp((char *(*)())\
		X509_REQ_new, (char *(*)())d2i_X509_REQ, (fp),\
		(unsigned char **)(req))
#define i2d_X509_REQ_fp(fp,req) ASN1_i2d_fp(i2d_X509_REQ,fp,\
		(unsigned char *)req)
#define d2i_X509_REQ_bio(bp,req) (X509_REQ *)ASN1_d2i_bio((char *(*)())\
		X509_REQ_new, (char *(*)())d2i_X509_REQ, (bp),\
		(unsigned char **)(req))
#define i2d_X509_REQ_bio(bp,req) ASN1_i2d_bio(i2d_X509_REQ,bp,\
		(unsigned char *)req)

#define RSAPublicKey_dup(rsa) (RSA *)ASN1_dup((int (*)())i2d_RSAPublicKey, \
		(char *(*)())d2i_RSAPublicKey,(char *)rsa)
#define RSAPrivateKey_dup(rsa) (RSA *)ASN1_dup((int (*)())i2d_RSAPrivateKey, \
		(char *(*)())d2i_RSAPrivateKey,(char *)rsa)

#define d2i_RSAPrivateKey_fp(fp,rsa) (RSA *)ASN1_d2i_fp((char *(*)())\
		RSA_new,(char *(*)())d2i_RSAPrivateKey, (fp), \
		(unsigned char **)(rsa))
#define i2d_RSAPrivateKey_fp(fp,rsa) ASN1_i2d_fp(i2d_RSAPrivateKey,fp, \
		(unsigned char *)rsa)
#define d2i_RSAPrivateKey_bio(bp,rsa) (RSA *)ASN1_d2i_bio((char *(*)())\
		RSA_new,(char *(*)())d2i_RSAPrivateKey, (bp), \
		(unsigned char **)(rsa))
#define i2d_RSAPrivateKey_bio(bp,rsa) ASN1_i2d_bio(i2d_RSAPrivateKey,bp, \
		(unsigned char *)rsa)

#define d2i_RSAPublicKey_fp(fp,rsa) (RSA *)ASN1_d2i_fp((char *(*)())\
		RSA_new,(char *(*)())d2i_RSAPublicKey, (fp), \
		(unsigned char **)(rsa))
#define i2d_RSAPublicKey_fp(fp,rsa) ASN1_i2d_fp(i2d_RSAPublicKey,fp, \
		(unsigned char *)rsa)
#define d2i_RSAPublicKey_bio(bp,rsa) (RSA *)ASN1_d2i_bio((char *(*)())\
		RSA_new,(char *(*)())d2i_RSAPublicKey, (bp), \
		(unsigned char **)(rsa))
#define i2d_RSAPublicKey_bio(bp,rsa) ASN1_i2d_bio(i2d_RSAPublicKey,bp, \
		(unsigned char *)rsa)

#define d2i_DSAPrivateKey_fp(fp,dsa) (DSA *)ASN1_d2i_fp((char *(*)())\
		DSA_new,(char *(*)())d2i_DSAPrivateKey, (fp), \
		(unsigned char **)(dsa))
#define i2d_DSAPrivateKey_fp(fp,dsa) ASN1_i2d_fp(i2d_DSAPrivateKey,fp, \
		(unsigned char *)dsa)
#define d2i_DSAPrivateKey_bio(bp,dsa) (DSA *)ASN1_d2i_bio((char *(*)())\
		DSA_new,(char *(*)())d2i_DSAPrivateKey, (bp), \
		(unsigned char **)(dsa))
#define i2d_DSAPrivateKey_bio(bp,dsa) ASN1_i2d_bio(i2d_DSAPrivateKey,bp, \
		(unsigned char *)dsa)

#define d2i_ECPrivateKey_fp(fp,ecdsa) (EC_KEY *)ASN1_d2i_fp((char *(*)())\
		EC_KEY_new,(char *(*)())d2i_ECPrivateKey, (fp), \
		(unsigned char **)(ecdsa))
#define i2d_ECPrivateKey_fp(fp,ecdsa) ASN1_i2d_fp(i2d_ECPrivateKey,fp, \
		(unsigned char *)ecdsa)
#define d2i_ECPrivateKey_bio(bp,ecdsa) (EC_KEY *)ASN1_d2i_bio((char *(*)())\
		EC_KEY_new,(char *(*)())d2i_ECPrivateKey, (bp), \
		(unsigned char **)(ecdsa))
#define i2d_ECPrivateKey_bio(bp,ecdsa) ASN1_i2d_bio(i2d_ECPrivateKey,bp, \
		(unsigned char *)ecdsa)

#define X509_ALGOR_dup(xn) (X509_ALGOR *)ASN1_dup((int (*)())i2d_X509_ALGOR,\
		(char *(*)())d2i_X509_ALGOR,(char *)xn)

#define X509_NAME_dup(xn) (X509_NAME *)ASN1_dup((int (*)())i2d_X509_NAME, \
		(char *(*)())d2i_X509_NAME,(char *)xn)
#define X509_NAME_ENTRY_dup(ne) (X509_NAME_ENTRY *)ASN1_dup( \
		(int (*)())i2d_X509_NAME_ENTRY, \
		(char *(*)())d2i_X509_NAME_ENTRY,\
		(char *)ne)

#define X509_digest(data,type,md,len) \
	ASN1_digest((int (*)())i2d_X509,type,(char *)data,md,len)
#define X509_NAME_digest(data,type,md,len) \
	ASN1_digest((int (*)())i2d_X509_NAME,type,(char *)data,md,len)
#ifndef PKCS7_ISSUER_AND_SERIAL_digest
#define PKCS7_ISSUER_AND_SERIAL_digest(data,type,md,len) \
	ASN1_digest((int (*)())i2d_PKCS7_ISSUER_AND_SERIAL,type,\
		(char *)data,md,len)
#endif
#endif

#define X509_EXT_PACK_UNKNOWN	1
#define X509_EXT_PACK_STRING	2

#define		X509_get_version(x) ASN1_INTEGER_get((x)->cert_info->version)
/*#define	X509_get_serialNumber(x) ((x)->cert_info->serialNumber) */
#define		X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define		X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)
#define		X509_extract_key(x)	X509_get_pubkey(x) /*****/
#define		X509_REQ_get_version(x) ASN1_INTEGER_get((x)->req_info->version)
#define		X509_REQ_get_subject_name(x) ((x)->req_info->subject)
#define		X509_REQ_extract_key(a)	X509_REQ_get_pubkey(a)
#define		X509_name_cmp(a,b)	X509_NAME_cmp((a),(b))
#define		X509_get_signature_type(x) EVP_PKEY_type(OBJ_obj2nid((x)->sig_alg->algorithm))

#define		X509_CRL_get_version(x) ASN1_INTEGER_get((x)->crl->version)
#define 	X509_CRL_get_lastUpdate(x) ((x)->crl->lastUpdate)
#define 	X509_CRL_get_nextUpdate(x) ((x)->crl->nextUpdate)
#define		X509_CRL_get_issuer(x) ((x)->crl->issuer)
#define		X509_CRL_get_REVOKED(x) ((x)->crl->revoked)

/* This one is only used so that a binary form can output, as in
 * i2d_X509_NAME(X509_get_X509_PUBKEY(x),&buf) */
#define 	X509_get_X509_PUBKEY(x) ((x)->cert_info->key)


const char *X509_verify_cert_error_string(long n);

#ifndef SSLEAY_MACROS
#ifndef OPENSSL_NO_EVP
int X509_verify(X509 *a, EVP_PKEY *r);

int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);

NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode(const char *str, int len);
char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);

int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);

int X509_signature_print(BIO *bp,X509_ALGOR *alg, ASN1_STRING *sig);

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md);

int X509_pubkey_digest(const X509 *data,const EVP_MD *type,
unsigned char *md, unsigned int *len);
int X509_digest(const X509 *data,const EVP_MD *type,
unsigned char *md, unsigned int *len);
int X509_CRL_digest(const X509_CRL *data,const EVP_MD *type,
unsigned char *md, unsigned int *len);
int X509_REQ_digest(const X509_REQ *data,const EVP_MD *type,
unsigned char *md, unsigned int *len);
int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type,
unsigned char *md, unsigned int *len);
#endif

#ifdef OPENSSL_NO_FP_API
X509 *d2i_X509_fp(FILE *fp, X509 **x509);
int i2d_X509_fp(FILE *fp,X509 *x509);
X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req);
#ifndef OPENSSL_NO_RSA
RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa);
#endif
#ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
#endif
#ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int   i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int   i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
#endif
X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
#endif

#ifndef OPENSSL_NO_BIO
X509 *d2i_X509_bio(BIO *bp,X509 **x509);
int i2d_X509_bio(BIO *bp,X509 *x509);
X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);
int i2d_X509_CRL_bio(BIO *bp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);
int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req);
#ifndef OPENSSL_NO_RSA
RSA *d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp,RSA *rsa);
#endif
#ifndef OPENSSL_NO_DSA
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
#endif
#ifndef OPENSSL_NO_EC
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int   i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int   i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
#endif
X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
#endif

X509 *X509_dup(X509 *x509);
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa);
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);
X509_CRL *X509_CRL_dup(X509_CRL *crl);
X509_REQ *X509_REQ_dup(X509_REQ *req);
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval);
void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
X509_ALGOR *algor);

X509_NAME *X509_NAME_dup(X509_NAME *xn);
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);

#endif /* !SSLEAY_MACROS */

int		X509_cmp_time(ASN1_TIME *s, time_t *t);
int		X509_cmp_current_time(ASN1_TIME *s);
ASN1_TIME *	X509_time_adj(ASN1_TIME *s, long adj, time_t *t);
ASN1_TIME *	X509_gmtime_adj(ASN1_TIME *s, long adj);

const char *	X509_get_default_cert_area(void );
const char *	X509_get_default_cert_dir(void );
const char *	X509_get_default_cert_file(void );
const char *	X509_get_default_cert_dir_env(void );
const char *	X509_get_default_cert_file_env(void );
const char *	X509_get_default_private_dir(void );

X509_REQ *	X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
X509 *		X509_REQ_to_X509(X509_REQ *r, int days,EVP_PKEY *pkey);

DECLARE_ASN1_FUNCTIONS(X509_ALGOR)
DECLARE_ASN1_ENCODE_FUNCTIONS(X509_ALGORS, X509_ALGORS, X509_ALGORS)
DECLARE_ASN1_FUNCTIONS(X509_VAL)

DECLARE_ASN1_FUNCTIONS(X509_PUBKEY)

int		X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
EVP_PKEY *	X509_PUBKEY_get(X509_PUBKEY *key);
int		X509_get_pubkey_parameters(EVP_PKEY *pkey,
STACK_OF(X509) *chain);
int		i2d_PUBKEY(EVP_PKEY *a,unsigned char **pp);
EVP_PKEY *	d2i_PUBKEY(EVP_PKEY **a,const unsigned char **pp,
long length);
#ifndef OPENSSL_NO_RSA
int		i2d_RSA_PUBKEY(RSA *a,unsigned char **pp);
RSA *		d2i_RSA_PUBKEY(RSA **a,const unsigned char **pp,
long length);
#endif
#ifndef OPENSSL_NO_DSA
int		i2d_DSA_PUBKEY(DSA *a,unsigned char **pp);
DSA *		d2i_DSA_PUBKEY(DSA **a,const unsigned char **pp,
long length);
#endif
#ifndef OPENSSL_NO_EC
int		i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY 		*d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
long length);
#endif

DECLARE_ASN1_FUNCTIONS(X509_SIG)
DECLARE_ASN1_FUNCTIONS(X509_REQ_INFO)
DECLARE_ASN1_FUNCTIONS(X509_REQ)

DECLARE_ASN1_FUNCTIONS(X509_ATTRIBUTE)
X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value);

DECLARE_ASN1_FUNCTIONS(X509_EXTENSION)
DECLARE_ASN1_ENCODE_FUNCTIONS(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)

DECLARE_ASN1_FUNCTIONS(X509_NAME_ENTRY)

DECLARE_ASN1_FUNCTIONS(X509_NAME)

int		X509_NAME_set(X509_NAME **xn, X509_NAME *name);

DECLARE_ASN1_FUNCTIONS(X509_CINF)

DECLARE_ASN1_FUNCTIONS(X509)
DECLARE_ASN1_FUNCTIONS(X509_CERT_AUX)

DECLARE_ASN1_FUNCTIONS(X509_CERT_PAIR)

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *r, int idx, void *arg);
void *X509_get_ex_data(X509 *r, int idx);
int		i2d_X509_AUX(X509 *a,unsigned char **pp);
X509 *		d2i_X509_AUX(X509 **a,const unsigned char **pp,long length);

int X509_alias_set1(X509 *x, unsigned char *name, int len);
int X509_keyid_set1(X509 *x, unsigned char *id, int len);
unsigned char * X509_alias_get0(X509 *x, int *len);
unsigned char * X509_keyid_get0(X509 *x, int *len);
int (*X509_TRUST_set_default(int (*trust)(int , X509 *, int)))(int, X509 *, int);
int X509_TRUST_set(int *t, int trust);
int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);

DECLARE_ASN1_FUNCTIONS(X509_REVOKED)
DECLARE_ASN1_FUNCTIONS(X509_CRL_INFO)
DECLARE_ASN1_FUNCTIONS(X509_CRL)

int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);

X509_PKEY *	X509_PKEY_new(void );
void		X509_PKEY_free(X509_PKEY *a);
int		i2d_X509_PKEY(X509_PKEY *a,unsigned char **pp);
X509_PKEY *	d2i_X509_PKEY(X509_PKEY **a,const unsigned char **pp,long length);

DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKI)
DECLARE_ASN1_FUNCTIONS(NETSCAPE_SPKAC)
DECLARE_ASN1_FUNCTIONS(NETSCAPE_CERT_SEQUENCE)

#ifndef OPENSSL_NO_EVP
X509_INFO *	X509_INFO_new(void);
void		X509_INFO_free(X509_INFO *a);
char *		X509_NAME_oneline(X509_NAME *a,char *buf,int size);

int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *algor1,
ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);

int ASN1_digest(i2d_of_void *i2d,const EVP_MD *type,char *data,
unsigned char *md,unsigned int *len);

int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
char *data,EVP_PKEY *pkey, const EVP_MD *type);

int ASN1_item_digest(const ASN1_ITEM *it,const EVP_MD *type,void *data,
unsigned char *md,unsigned int *len);

int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *algor1,
ASN1_BIT_STRING *signature,void *data,EVP_PKEY *pkey);

int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
ASN1_BIT_STRING *signature,
void *data, EVP_PKEY *pkey, const EVP_MD *type);
#endif

int 		X509_set_version(X509 *x,long version);
int 		X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
ASN1_INTEGER *	X509_get_serialNumber(X509 *x);
int 		X509_set_issuer_name(X509 *x, X509_NAME *name);
X509_NAME *	X509_get_issuer_name(X509 *a);
int 		X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME *	X509_get_subject_name(X509 *a);
int 		X509_set_notBefore(X509 *x, ASN1_TIME *tm);
int 		X509_set_notAfter(X509 *x, ASN1_TIME *tm);
int 		X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
EVP_PKEY *	X509_get_pubkey(X509 *x);
ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
int		X509_certificate_type(X509 *x,EVP_PKEY *pubkey /* optional */);

int		X509_REQ_set_version(X509_REQ *x,long version);
int		X509_REQ_set_subject_name(X509_REQ *req,X509_NAME *name);
int		X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
EVP_PKEY *	X509_REQ_get_pubkey(X509_REQ *req);
int		X509_REQ_extension_nid(int nid);
int *		X509_REQ_get_extension_nids(void);
void		X509_REQ_set_extension_nids(int *nids);
STACK_OF(X509_EXTENSION) *X509_REQ_get_extensions(X509_REQ *req);
int X509_REQ_add_extensions_nid(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts,
int nid);
int X509_REQ_add_extensions(X509_REQ *req, STACK_OF(X509_EXTENSION) *exts);
int X509_REQ_get_attr_count(const X509_REQ *req);
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid,
int lastpos);
int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, ASN1_OBJECT *obj,
int lastpos);
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
const ASN1_OBJECT *obj, int type,
const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_NID(X509_REQ *req,
int nid, int type,
const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_txt(X509_REQ *req,
const char *attrname, int type,
const unsigned char *bytes, int len);

int X509_CRL_set_version(X509_CRL *x, long version);
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
int X509_CRL_set_lastUpdate(X509_CRL *x, ASN1_TIME *tm);
int X509_CRL_set_nextUpdate(X509_CRL *x, ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *crl);

int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);

int		X509_REQ_check_private_key(X509_REQ *x509,EVP_PKEY *pkey);

int		X509_check_private_key(X509 *x509,EVP_PKEY *pkey);

int		X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long	X509_issuer_and_serial_hash(X509 *a);

int		X509_issuer_name_cmp(const X509 *a, const X509 *b);
unsigned long	X509_issuer_name_hash(X509 *a);

int		X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long	X509_subject_name_hash(X509 *x);

int		X509_cmp(const X509 *a, const X509 *b);
int		X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
unsigned long	X509_NAME_hash(X509_NAME *x);

int		X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
#ifdef OPENSSL_NO_FP_API
int		X509_print_ex_fp(FILE *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int		X509_print_fp(FILE *bp,X509 *x);
int		X509_CRL_print_fp(FILE *bp,X509_CRL *x);
int		X509_REQ_print_fp(FILE *bp,X509_REQ *req);
int X509_NAME_print_ex_fp(FILE *fp, X509_NAME *nm, int indent, unsigned long flags);
#endif

#ifndef OPENSSL_NO_BIO
int		X509_NAME_print(BIO *bp, X509_NAME *name, int obase);
int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
int		X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int		X509_print(BIO *bp,X509 *x);
int		X509_ocspid_print(BIO *bp,X509 *x);
int		X509_CERT_AUX_print(BIO *bp,X509_CERT_AUX *x, int indent);
int		X509_CRL_print(BIO *bp,X509_CRL *x);
int		X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag);
int		X509_REQ_print(BIO *bp,X509_REQ *req);
#endif

int 		X509_NAME_entry_count(X509_NAME *name);
int 		X509_NAME_get_text_by_NID(X509_NAME *name, int nid,
char *buf,int len);
int		X509_NAME_get_text_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj,
char *buf,int len);

/* NOTE: you should be passsing -1, not 0 as lastpos.  The functions that use
 * lastpos, search after that position on. */
int 		X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos);
int 		X509_NAME_get_index_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,
int lastpos);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
int 		X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
int loc, int set);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj, int type,
unsigned char *bytes, int len, int loc, int set);
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type,
unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
const char *field, int type, const unsigned char *bytes, int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
int type,unsigned char *bytes, int len);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
const unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
ASN1_OBJECT *obj, int type,const unsigned char *bytes,
int len);
int 		X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
ASN1_OBJECT *obj);
int 		X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
const unsigned char *bytes, int len);
ASN1_OBJECT *	X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING *	X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);

int		X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x);
int		X509v3_get_ext_by_NID(const STACK_OF(X509_EXTENSION) *x,
int nid, int lastpos);
int		X509v3_get_ext_by_OBJ(const STACK_OF(X509_EXTENSION) *x,
ASN1_OBJECT *obj,int lastpos);
int		X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
int crit, int lastpos);
X509_EXTENSION *X509v3_get_ext(const STACK_OF(X509_EXTENSION) *x, int loc);
X509_EXTENSION *X509v3_delete_ext(STACK_OF(X509_EXTENSION) *x, int loc);
STACK_OF(X509_EXTENSION) *X509v3_add_ext(STACK_OF(X509_EXTENSION) **x,
X509_EXTENSION *ex, int loc);

int		X509_get_ext_count(X509 *x);
int		X509_get_ext_by_NID(X509 *x, int nid, int lastpos);
int		X509_get_ext_by_OBJ(X509 *x,ASN1_OBJECT *obj,int lastpos);
int		X509_get_ext_by_critical(X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(X509 *x, int loc);
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
int		X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void	*	X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx);
int		X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
unsigned long flags);

int		X509_CRL_get_ext_count(X509_CRL *x);
int		X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos);
int		X509_CRL_get_ext_by_OBJ(X509_CRL *x,ASN1_OBJECT *obj,int lastpos);
int		X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos);
X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc);
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
int		X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
void	*	X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx);
int		X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
unsigned long flags);

int		X509_REVOKED_get_ext_count(X509_REVOKED *x);
int		X509_REVOKED_get_ext_by_NID(X509_REVOKED *x, int nid, int lastpos);
int		X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x,ASN1_OBJECT *obj,int lastpos);
int		X509_REVOKED_get_ext_by_critical(X509_REVOKED *x, int crit, int lastpos);
X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc);
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int		X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
void	*	X509_REVOKED_get_ext_d2i(X509_REVOKED *x, int nid, int *crit, int *idx);
int		X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
unsigned long flags);

X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
int nid, int crit, ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data);
int		X509_EXTENSION_set_object(X509_EXTENSION *ex,ASN1_OBJECT *obj);
int		X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
int		X509_EXTENSION_set_data(X509_EXTENSION *ex,
ASN1_OCTET_STRING *data);
ASN1_OBJECT *	X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
int		X509_EXTENSION_get_critical(X509_EXTENSION *ex);

int X509at_get_attr_count(const STACK_OF(X509_ATTRIBUTE) *x);
int X509at_get_attr_by_NID(const STACK_OF(X509_ATTRIBUTE) *x, int nid,
int lastpos);
int X509at_get_attr_by_OBJ(const STACK_OF(X509_ATTRIBUTE) *sk, ASN1_OBJECT *obj,
int lastpos);
X509_ATTRIBUTE *X509at_get_attr(const STACK_OF(X509_ATTRIBUTE) *x, int loc);
X509_ATTRIBUTE *X509at_delete_attr(STACK_OF(X509_ATTRIBUTE) *x, int loc);
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr(STACK_OF(X509_ATTRIBUTE) **x,
X509_ATTRIBUTE *attr);
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_OBJ(STACK_OF(X509_ATTRIBUTE) **x,
const ASN1_OBJECT *obj, int type,
const unsigned char *bytes, int len);
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_NID(STACK_OF(X509_ATTRIBUTE) **x,
int nid, int type,
const unsigned char *bytes, int len);
STACK_OF(X509_ATTRIBUTE) *X509at_add1_attr_by_txt(STACK_OF(X509_ATTRIBUTE) **x,
const char *attrname, int type,
const unsigned char *bytes, int len);
void *X509at_get0_data_by_OBJ(STACK_OF(X509_ATTRIBUTE) *x,
ASN1_OBJECT *obj, int lastpos, int type);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
const ASN1_OBJECT *obj, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
const char *atrname, int type, const unsigned char *bytes, int len);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype, const void *data, int len);
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx,
int atrtype, void *data);
int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);

int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid,
int lastpos);
int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, ASN1_OBJECT *obj,
int lastpos);
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
const ASN1_OBJECT *obj, int type,
const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
int nid, int type,
const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
const char *attrname, int type,
const unsigned char *bytes, int len);

int		X509_verify_cert(X509_STORE_CTX *ctx);

/* lookup a cert from a X509 STACK */
X509 *X509_find_by_issuer_and_serial(STACK_OF(X509) *sk,X509_NAME *name,
ASN1_INTEGER *serial);
X509 *X509_find_by_subject(STACK_OF(X509) *sk,X509_NAME *name);

DECLARE_ASN1_FUNCTIONS(PBEPARAM)
DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)

X509_ALGOR *PKCS5_pbe_set(int alg, int iter, unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
unsigned char *salt, int saltlen);

/* PKCS#8 utilities */

DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken);
PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken);

int X509_check_trust(X509 *x, int id, int flags);
int X509_TRUST_get_count(void);
X509_TRUST * X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
char *name, int arg1, void *arg2);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(X509_TRUST *xp);
char *X509_TRUST_get0_name(X509_TRUST *xp);
int X509_TRUST_get_trust(X509_TRUST *xp);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_X509_strings(void);

/* Error codes for the X509 functions. */

/* Function codes. */
#define X509_F_ADD_CERT_DIR				 100
#define X509_F_BY_FILE_CTRL				 101
#define X509_F_CHECK_POLICY				 145
#define X509_F_DIR_CTRL					 102
#define X509_F_GET_CERT_BY_SUBJECT			 103
#define X509_F_NETSCAPE_SPKI_B64_DECODE			 129
#define X509_F_NETSCAPE_SPKI_B64_ENCODE			 130
#define X509_F_X509AT_ADD1_ATTR				 135
#define X509_F_X509V3_ADD_EXT				 104
#define X509_F_X509_ATTRIBUTE_CREATE_BY_NID		 136
#define X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ		 137
#define X509_F_X509_ATTRIBUTE_CREATE_BY_TXT		 140
#define X509_F_X509_ATTRIBUTE_GET0_DATA			 139
#define X509_F_X509_ATTRIBUTE_SET1_DATA			 138
#define X509_F_X509_CHECK_PRIVATE_KEY			 128
#define X509_F_X509_CRL_PRINT_FP			 147
#define X509_F_X509_EXTENSION_CREATE_BY_NID		 108
#define X509_F_X509_EXTENSION_CREATE_BY_OBJ		 109
#define X509_F_X509_GET_PUBKEY_PARAMETERS		 110
#define X509_F_X509_LOAD_CERT_CRL_FILE			 132
#define X509_F_X509_LOAD_CERT_FILE			 111
#define X509_F_X509_LOAD_CRL_FILE			 112
#define X509_F_X509_NAME_ADD_ENTRY			 113
#define X509_F_X509_NAME_ENTRY_CREATE_BY_NID		 114
#define X509_F_X509_NAME_ENTRY_CREATE_BY_TXT		 131
#define X509_F_X509_NAME_ENTRY_SET_OBJECT		 115
#define X509_F_X509_NAME_ONELINE			 116
#define X509_F_X509_NAME_PRINT				 117
#define X509_F_X509_PRINT_EX_FP				 118
#define X509_F_X509_PUBKEY_GET				 119
#define X509_F_X509_PUBKEY_SET				 120
#define X509_F_X509_REQ_CHECK_PRIVATE_KEY		 144
#define X509_F_X509_REQ_PRINT_EX			 121
#define X509_F_X509_REQ_PRINT_FP			 122
#define X509_F_X509_REQ_TO_X509				 123
#define X509_F_X509_STORE_ADD_CERT			 124
#define X509_F_X509_STORE_ADD_CRL			 125
#define X509_F_X509_STORE_CTX_GET1_ISSUER		 146
#define X509_F_X509_STORE_CTX_INIT			 143
#define X509_F_X509_STORE_CTX_NEW			 142
#define X509_F_X509_STORE_CTX_PURPOSE_INHERIT		 134
#define X509_F_X509_TO_X509_REQ				 126
#define X509_F_X509_TRUST_ADD				 133
#define X509_F_X509_TRUST_SET				 141
#define X509_F_X509_VERIFY_CERT				 127

/* Reason codes. */
#define X509_R_BAD_X509_FILETYPE			 100
#define X509_R_BASE64_DECODE_ERROR			 118
#define X509_R_CANT_CHECK_DH_KEY			 114
#define X509_R_CERT_ALREADY_IN_HASH_TABLE		 101
#define X509_R_ERR_ASN1_LIB				 102
#define X509_R_INVALID_DIRECTORY			 113
#define X509_R_INVALID_FIELD_NAME			 119
#define X509_R_INVALID_TRUST				 123
#define X509_R_KEY_TYPE_MISMATCH			 115
#define X509_R_KEY_VALUES_MISMATCH			 116
#define X509_R_LOADING_CERT_DIR				 103
#define X509_R_LOADING_DEFAULTS				 104
#define X509_R_NO_CERT_SET_FOR_US_TO_VERIFY		 105
#define X509_R_SHOULD_RETRY				 106
#define X509_R_UNABLE_TO_FIND_PARAMETERS_IN_CHAIN	 107
#define X509_R_UNABLE_TO_GET_CERTS_PUBLIC_KEY		 108
#define X509_R_UNKNOWN_KEY_TYPE				 117
#define X509_R_UNKNOWN_NID				 109
#define X509_R_UNKNOWN_PURPOSE_ID			 121
#define X509_R_UNKNOWN_TRUST_ID				 120
#define X509_R_UNSUPPORTED_ALGORITHM			 111
#define X509_R_WRONG_LOOKUP_TYPE			 112
#define X509_R_WRONG_TYPE				 122

#endif
