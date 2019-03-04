
static int ex_data_check(void);

#define EX_IMPL(a) impl->cb_##a
#define IMPL_CHECK if(!impl) impl_check();
#define EX_DATA_CHECK(iffail) if(!ex_data && !ex_data_check()) {iffail}

typedef struct st_ex_class_item {
	int class_index;
	STACK_OF(CRYPTO_EX_DATA_FUNCS) *meth;
	int meth_num;
} EX_CLASS_ITEM;

typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;

static const CRYPTO_EX_DATA_IMPL *impl = NULL;
static LHASH *ex_data = NULL;

struct st_CRYPTO_EX_DATA_IMPL
	{

	int (*cb_new_ex_data)(int class_index, void *obj,
			CRYPTO_EX_DATA *ad);
	void (*cb_free_ex_data)(int class_index, void *obj,
			CRYPTO_EX_DATA *ad);
	};


///////////////////impl_default/////////////

static int int_new_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);

static void int_free_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);

static CRYPTO_EX_DATA_IMPL impl_default =
	{
	int_new_ex_data,
	int_free_ex_data
	};

///////////////ex_hash_cb//////////////////////ok

static unsigned long ex_hash_cb(const void *a_void)
	{

	return ((const EX_CLASS_ITEM *)a_void)->class_index;
	}

///////////////ex_cmp_cb/////////////////////////////ok

static int ex_cmp_cb(const void *a_void, const void *b_void)
	{

	return (((const EX_CLASS_ITEM *)a_void)->class_index -
		((const EX_CLASS_ITEM *)b_void)->class_index);
	}


///////////IMPL_CHECK///////////////////////ok

static void impl_check(void)
	{

	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if(!impl)
		impl = &impl_default;
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	}

////////////////CRYPTO_new_ex_data/////////////////ok

int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{

	IMPL_CHECK
	return EX_IMPL(new_ex_data)(class_index, obj, ad);
	}

/////////////////CRYPTO_free_ex_data///////////////////////////ok

void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{

	IMPL_CHECK
	EX_IMPL(free_ex_data)(class_index, obj, ad);
	}

//////////bio_set////////////////////////ok

int BIO_set(BIO *bio, BIO_METHOD *method)
	{
	bio->method=method;
	bio->callback=NULL;
	bio->cb_arg=NULL;
	bio->init=0;
	bio->shutdown=1;
	bio->flags=0;
	bio->retry_reason=0;
	bio->num=0;
	bio->ptr=NULL;
	bio->prev_bio=NULL;
	bio->next_bio=NULL;
	bio->references=1;
	bio->num_read=0L;
	bio->num_write=0L;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
	if (method->create != NULL)
		if (!method->create(bio))
			{
			CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio,
					&bio->ex_data);
			return(0);
			}
	return(1);
	}


/////////////////BI0_new//////////////ok

BIO *BIO_new(BIO_METHOD *method)
{
	BIO *ret=NULL;

	ret=(BIO *)OPENSSL_malloc(sizeof(BIO));
	if (ret == NULL)
		{

		return(NULL);
		}
	if (!BIO_set(ret,method))
		{
		OPENSSL_free(ret);
		ret=NULL;
		}
	return(ret);
}


///////////////////def_get_class////////////////////////////////////////ok

static EX_CLASS_ITEM *def_get_class(int class_index)
	{
	EX_CLASS_ITEM d, *p, *gen;

	EX_DATA_CHECK(return NULL;)
	d.class_index = class_index;
	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	p = lh_retrieve(ex_data, &d);
	if(!p)
		{
		gen = OPENSSL_malloc(sizeof(EX_CLASS_ITEM));
		if(gen)
			{
			gen->class_index = class_index;
			gen->meth_num = 0;
			gen->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
			if(!gen->meth)
				OPENSSL_free(gen);
			else
				{

				lh_insert(ex_data, gen);
				p = gen;
				}
			}
		}
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	if(!p)
		CRYPTOerr(CRYPTO_F_DEF_GET_CLASS,ERR_R_MALLOC_FAILURE);
	return p;
	}



///////////////////int_new_ex_data/////////////////////////////////////////ok

static int int_new_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad)
	{
	int mx,i;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;

	EX_CLASS_ITEM *item = def_get_class(class_index);

	if(!item)
		/* error is already set */
		return 0;
	ad->sk = NULL;
	//CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if(mx > 0)
		{
		storage = OPENSSL_malloc(mx * sizeof(CRYPTO_EX_DATA_FUNCS*));
		if(!storage)
			goto skip;
		for(i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(item->meth,i);
		}
skip:
	//CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if((mx > 0) && !storage)
		{
		CRYPTOerr(CRYPTO_F_INT_NEW_EX_DATA,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	for(i = 0; i < mx; i++)
		{
		if(storage[i] && storage[i]->new_func)
			{
				;
			}
		}
	if(storage)
		OPENSSL_free(storage);
	return 1;
	}




////////////ex_data_check//////////////////////////////////////////ok

static int ex_data_check(void)
	{
	int toret = 1;

	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if(!ex_data && ((ex_data = lh_new(ex_hash_cb, ex_cmp_cb)) == NULL))
		toret = 0;
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	return toret;
	}

///////////////int_free_ex_data/////////////////////////////////////////ok

static void int_free_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad)
	{
	int mx,i;
	EX_CLASS_ITEM *item;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;

	if((item = def_get_class(class_index)) == NULL)
		return;
	//CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if(mx > 0)
		{
		storage = OPENSSL_malloc(mx * sizeof(CRYPTO_EX_DATA_FUNCS*));
		if(!storage)
			goto skip;
		for(i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(item->meth,i);
		}
skip:
	//CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if((mx > 0) && !storage)
		{
		CRYPTOerr(CRYPTO_F_INT_FREE_EX_DATA,ERR_R_MALLOC_FAILURE);
		return;
		}
	for(i = 0; i < mx; i++)
		{
		if(storage[i] && storage[i]->free_func)
			{
				;
			}
		}
	if(storage)
		OPENSSL_free(storage);
	if(ad->sk)
		{
		sk_free(ad->sk);
		ad->sk=NULL;
		}
	}

void reset_BIO_reset(void)
{
	impl = NULL;
	ex_data = NULL;
}/* crypto/bio/b_print.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* disable assert() unless BIO_DEBUG has been defined */
/*
 * Stolen from tjh's ssl/ssl_trc.c stuff.
 */
/***************************************************************************/

/*
 * Copyright Patrick Powell 1995
 * This code is based on code written by Patrick Powell <papowell@astart.com>
 * It may be used for any purpose as long as this notice remains intact
 * on all source code distributions.
 */

/*
 * This code contains numerious changes and enhancements which were
 * made by lots of contributors over the last years to Patrick Powell's
 * original code:
 *
 * o Patrick Powell <papowell@astart.com>      (1995)
 * o Brandon Long <blong@fiction.net>          (1996, for Mutt)
 * o Thomas Roessler <roessler@guug.de>        (1998, for Mutt)
 * o Michael Elkins <me@cs.hmc.edu>            (1998, for Mutt)
 * o Andrew Tridgell <tridge@samba.org>        (1998, for Samba)
 * o Luke Mewburn <lukem@netbsd.org>           (1999, for LukemFTP)
 * o Ralf S. Engelschall <rse@engelschall.com> (1999, for Pth)
 * o ...                                       (for OpenSSL)
 */


#define LLONG long long

static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args);

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)



static int __isdigit(char c)
{
	if((c>='0') && (c<='9'))
		return 1;
	return 0;
}

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (__isdigit((unsigned char)ch)){
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (__isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
//            case 'f':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                fmtfp(sbuffer, buffer, &currlen, maxlen,
//                      fvalue, min, max, flags);
//                break;
            case 'E':
                flags |= DP_F_UP;
//            case 'e':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                break;
            case 'G':
                flags |= DP_F_UP;
//            case 'g':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}

static void
fmtstr(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    const char *value,
    int flags,
    int min,
    int max)
{
    int padlen, strln;
    int cnt = 0;

    if (value == 0)
        value = "<NULL>";
    for (strln = 0; value[strln]; ++strln)
        ;
    padlen = min - strln;
    if (padlen < 0)
        padlen = 0;
    if (flags & DP_F_MINUS)
        padlen = -padlen;

    while ((padlen > 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --padlen;
        ++cnt;
    }
    while (*value && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, *value++);
        ++cnt;
    }
    while ((padlen < 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++padlen;
        ++cnt;
    }
}

static void
fmtint(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    LLONG value,
    int base,
    int min,
    int max,
    int flags)
{
    int signvalue = 0;
    const char *prefix = "";
    unsigned LLONG uvalue;
    char convert[DECIMAL_SIZE(value)+3];
    int place = 0;
    int spadlen = 0;
    int zpadlen = 0;
    int caps = 0;

    if (max < 0)
        max = 0;
    uvalue = value;
    if (!(flags & DP_F_UNSIGNED)) {
        if (value < 0) {
            signvalue = '-';
            uvalue = -value;
        } else if (flags & DP_F_PLUS)
            signvalue = '+';
        else if (flags & DP_F_SPACE)
            signvalue = ' ';
    }
    if (flags & DP_F_NUM) {
	if (base == 8) prefix = "0";
	if (base == 16) prefix = "0x";
    }
    if (flags & DP_F_UP)
        caps = 1;
    do {
        convert[place++] =
            (caps ? "0123456789ABCDEF" : "0123456789abcdef")
            [uvalue % (unsigned) base];
        uvalue = (uvalue / (unsigned) base);
    } while (uvalue && (place < (int)sizeof(convert)));
    if (place == sizeof(convert))
        place--;
    convert[place] = 0;

    zpadlen = max - place;
    spadlen = min - OSSL_MAX(max, place) - (signvalue ? 1 : 0) - strlen(prefix);
    if (zpadlen < 0)
        zpadlen = 0;
    if (spadlen < 0)
        spadlen = 0;
    if (flags & DP_F_ZERO) {
        zpadlen = OSSL_MAX(zpadlen, spadlen);
        spadlen = 0;
    }
    if (flags & DP_F_MINUS)
        spadlen = -spadlen;

    /* spaces */
    while (spadlen > 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --spadlen;
    }

    /* sign */
    if (signvalue)
        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);

    /* prefix */
    while (*prefix) {
	doapr_outch(sbuffer, buffer, currlen, maxlen, *prefix);
	prefix++;
    }

    /* zeros */
    if (zpadlen > 0) {
        while (zpadlen > 0) {
            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
            --zpadlen;
        }
    }
    /* digits */
    while (place > 0)
        doapr_outch(sbuffer, buffer, currlen, maxlen, convert[--place]);

    /* left justified spaces */
    while (spadlen < 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++spadlen;
    }
    return;
}

//static LDOUBLE
//abs_val(LDOUBLE value)
//{
//    LDOUBLE result = value;
//    if (value < 0)
//        result = -value;
//    return result;
//}

//static LDOUBLE
//pow_10(int in_exp)
//{
//    LDOUBLE result = 1;
//    while (in_exp) {
//        result *= 10;
//        in_exp--;
//    }
//    return result;
//}

//static long
//roundv(LDOUBLE value)
//{
//    long intpart;
//    intpart = (long) value;
//    value = value - intpart;
//    if (value >= 0.5)
//        intpart++;
//    return intpart;
//}

//static void
//fmtfp(
//    char **sbuffer,
//    char **buffer,
//    size_t *currlen,
//    size_t *maxlen,
//    LDOUBLE fvalue,
//    int min,
//    int max,
//    int flags)
//{
//    int signvalue = 0;
//    LDOUBLE ufvalue;
//    char iconvert[20];
//    char fconvert[20];
//    int iplace = 0;
//    int fplace = 0;
//    int padlen = 0;
//    int zpadlen = 0;
//    int caps = 0;
//    long intpart;
//    long fracpart;
//    long max10;
//
//    if (max < 0)
//        max = 6;
//    ufvalue = abs_val(fvalue);
//    if (fvalue < 0)
//        signvalue = '-';
//    else if (flags & DP_F_PLUS)
//        signvalue = '+';
//    else if (flags & DP_F_SPACE)
//        signvalue = ' ';
//
//    intpart = (long)ufvalue;
//
//    /* sorry, we only support 9 digits past the decimal because of our
//       conversion method */
//    if (max > 9)
//        max = 9;
//
//    /* we "cheat" by converting the fractional part to integer by
//       multiplying by a factor of 10 */
//    max10 = roundv(pow_10(max));
//    fracpart = roundv(pow_10(max) * (ufvalue - intpart));
//
//    if (fracpart >= max10) {
//        intpart++;
//        fracpart -= max10;
//    }
//
//    /* convert integer part */
//    do {
//        iconvert[iplace++] =
//            (caps ? "0123456789ABCDEF"
//              : "0123456789abcdef")[intpart % 10];
//        intpart = (intpart / 10);
//    } while (intpart && (iplace < (int)sizeof(iconvert)));
//    if (iplace == sizeof iconvert)
//        iplace--;
//    iconvert[iplace] = 0;
//
//    /* convert fractional part */
//    do {
//        fconvert[fplace++] =
//            (caps ? "0123456789ABCDEF"
//              : "0123456789abcdef")[fracpart % 10];
//        fracpart = (fracpart / 10);
//    } while (fplace < max);
//    if (fplace == sizeof fconvert)
//        fplace--;
//    fconvert[fplace] = 0;
//
//    /* -1 for decimal point, another -1 if we are printing a sign */
//    padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
//    zpadlen = max - fplace;
//    if (zpadlen < 0)
//        zpadlen = 0;
//    if (padlen < 0)
//        padlen = 0;
//    if (flags & DP_F_MINUS)
//        padlen = -padlen;
//
//    if ((flags & DP_F_ZERO) && (padlen > 0)) {
//        if (signvalue) {
//            doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);
//            --padlen;
//            signvalue = 0;
//        }
//        while (padlen > 0) {
//            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
//            --padlen;
//        }
//    }
//    while (padlen > 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
//        --padlen;
//    }
//    if (signvalue)
//        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);
//
//    while (iplace > 0)
//        doapr_outch(sbuffer, buffer, currlen, maxlen, iconvert[--iplace]);
//
//    /*
//     * Decimal point. This should probably use locale to find the correct
//     * char to print out.
//     */
//    if (max > 0 || (flags & DP_F_NUM)) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, '.');
//
//        while (fplace > 0)
//            doapr_outch(sbuffer, buffer, currlen, maxlen, fconvert[--fplace]);
//    }
//    while (zpadlen > 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
//        --zpadlen;
//    }
//
//    while (padlen < 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
//        ++padlen;
//    }
//}

static void
doapr_outch(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    int c)
{
    /* If we haven't at least one buffer, someone has doe a big booboo */
    assert(*sbuffer != NULL || buffer != NULL);

    if (buffer) {
	while (*currlen >= *maxlen) {
	    if (*buffer == NULL) {
		if (*maxlen == 0)
		    *maxlen = 1024;
		*buffer = OPENSSL_malloc(*maxlen);
		if (*currlen > 0) {
		    assert(*sbuffer != NULL);
		    memcpy(*buffer, *sbuffer, *currlen);
		}
		*sbuffer = NULL;
	    } else {
		*maxlen += 1024;
		*buffer = OPENSSL_realloc(*buffer, *maxlen);
	    }
	}
	/* What to do if *buffer is NULL? */
	assert(*sbuffer != NULL || *buffer != NULL);
    }

    if (*currlen < *maxlen) {
	if (*sbuffer)
	    (*sbuffer)[(*currlen)++] = (char)c;
	else
	    (*buffer)[(*currlen)++] = (char)c;
    }

    return;
}

/***************************************************************************/

int BIO_vprintf (BIO *bio, const char *format, va_list args)
	{
	int ret;
	size_t retlen;
	char hugebuf[1024*2];	/* Was previously 10k, which is unreasonable
				   in small-stack environments, like threads
				   or DOS programs. */
	char *hugebufp = hugebuf;
	size_t hugebufsize = sizeof(hugebuf);
	char *dynbuf = NULL;
	int ignored;

	dynbuf = NULL;
	_dopr(&hugebufp, &dynbuf, &hugebufsize,
		&retlen, &ignored, format, args);
	if (dynbuf)
		{
		ret=BIO_write(bio, dynbuf, (int)retlen);
		OPENSSL_free(dynbuf);
		}
	else
		{
		ret=BIO_write(bio, hugebuf, (int)retlen);
		}

	return(ret);
	}

int BIO_printf (BIO *bio, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vprintf(bio, format, args);

	va_end(args);
	return(ret);
	}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	{
	size_t retlen;
	int truncated;

	_dopr(&buf, NULL, &n, &retlen, &truncated, format, args);

	if (truncated)
		/* In case of truncation, return -1 like traditional snprintf.
		 * (Current drafts for ISO/IEC 9899 say snprintf should return
		 * the number of characters that would have been written,
		 * had the buffer been large enough.) */
		return -1;
	else
		return (retlen <= INT_MAX) ? (int)retlen : -1;
	}

/* As snprintf is not available everywhere, we provide our own implementation.
 * This function has nothing to do with BIOs, but it's closely related
 * to BIO_printf, and we need *some* name prefix ...
 * (XXX  the function should be renamed, but to what?) */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vsnprintf(buf, n, format, args);

	va_end(args);
	return(ret);
	}

#define MS_CALLBACK			//samyang  modify

////////////////BIO_read/////////////////////////ok

int BIO_read(BIO *b, void *out, int outl)
	{
	int i;
	long (*cb)(BIO *,int,const char *,int,long,long);
	
	if ((b == NULL) || (b->method == NULL) || (b->method->bread == NULL))
		{
		BIOerr(BIO_F_BIO_READ,BIO_R_UNSUPPORTED_METHOD);
		return(-2);
		}

	cb=b->callback;
	if ((cb != NULL) &&
		((i=(int)cb(b,BIO_CB_READ,out,outl,0L,1L)) <= 0))
			return(i);

	if (!b->init)
		{
		BIOerr(BIO_F_BIO_READ,BIO_R_UNINITIALIZED);
		return(-2);
		}

	i=b->method->bread(b,out,outl);

	if (i > 0) b->num_read+=(unsigned long)i;

	if (cb != NULL)
		i=(int)cb(b,BIO_CB_READ|BIO_CB_RETURN,out,outl,
			0L,(long)i);
	return(i);
	}

/* crypto/bio/bss_bio.c  -*- Mode: C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Special method for a BIO where the other endpoint is also a BIO
 * of this kind, handled by the same thread (i.e. the "peer" is actually
 * ourselves, wearing a different hat).
 * Such "BIO pairs" are mainly for using the SSL library with I/O interfaces
 * for which no specific BIO method is available.
 * See ssl/ssltest.c for some hints on how this can be used. */

/* BIO_DEBUG implies BIO_PAIR_DEBUG */
#ifdef BIO_DEBUG
# ifndef BIO_PAIR_DEBUG
#  define BIO_PAIR_DEBUG
# endif
#endif

/* disable assert() unless BIO_PAIR_DEBUG has been defined */
#ifndef BIO_PAIR_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif




/* VxWorks defines SSIZE_MAX with an empty value causing compile errors */
#if defined(OPENSSL_SYS_VXWORKS)
# undef SSIZE_MAX
#endif
#ifndef SSIZE_MAX
# define SSIZE_MAX INT_MAX
#endif

static int bio_new(BIO *bio);
static int bio_free(BIO *bio);
static int bio_read(BIO *bio, char *buf, int size);
static int bio_write(BIO *bio, const char *buf, int num);
static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr);
static int bio_puts(BIO *bio, const char *str);

static int bio_make_pair(BIO *bio1, BIO *bio2);
static void bio_destroy_pair(BIO *bio);

static BIO_METHOD methods_biop =
{
	BIO_TYPE_BIO,
	"BIO pair",
	bio_write,
	bio_read,
	bio_puts,
	NULL /* no bio_gets */,
	bio_ctrl,
	bio_new,
	bio_free,
	NULL /* no bio_callback_ctrl */
};

BIO_METHOD *BIO_s_bio(void)
	{
	return &methods_biop;
	}

struct bio_bio_st
{
	BIO *peer;     /* NULL if buf == NULL.
	                * If peer != NULL, then peer->ptr is also a bio_bio_st,
	                * and its "peer" member points back to us.
	                * peer != NULL iff init != 0 in the BIO. */

	/* This is for what we write (i.e. reading uses peer's struct): */
	int closed;     /* valid iff peer != NULL */
	size_t len;     /* valid iff buf != NULL; 0 if peer == NULL */
	size_t offset;  /* valid iff buf != NULL; 0 if len == 0 */
	size_t size;
	char *buf;      /* "size" elements (if != NULL) */

	size_t request; /* valid iff peer != NULL; 0 if len != 0,
	                 * otherwise set by peer to number of bytes
	                 * it (unsuccessfully) tried to read,
	                 * never more than buffer space (size-len) warrants. */
};

static int bio_new(BIO *bio)
	{
	struct bio_bio_st *b;

	b = OPENSSL_malloc(sizeof *b);
	if (b == NULL)
		return 0;

	b->peer = NULL;
	b->size = 17*1024; /* enough for one TLS record (just a default) */
	b->buf = NULL;

	bio->ptr = b;
	return 1;
	}


static int bio_free(BIO *bio)
	{
	struct bio_bio_st *b;

	if (bio == NULL)
		return 0;
	b = bio->ptr;

	assert(b != NULL);

	if (b->peer)
		bio_destroy_pair(bio);

	if (b->buf != NULL)
		{
		OPENSSL_free(b->buf);
		}

	OPENSSL_free(b);

	return 1;
	}



static int bio_read(BIO *bio, char *buf, int size_)
	{
	size_t size = size_;
	size_t rest;
	struct bio_bio_st *b, *peer_b;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	peer_b = b->peer->ptr;
	assert(peer_b != NULL);
	assert(peer_b->buf != NULL);

	peer_b->request = 0; /* will be set in "retry_read" situation */

	if (buf == NULL || size == 0)
		return 0;

	if (peer_b->len == 0)
		{
		if (peer_b->closed)
			return 0; /* writer has closed, and no data is left */
		else
			{
			BIO_set_retry_read(bio); /* buffer is empty */
			if (size <= peer_b->size)
				peer_b->request = size;
			else
				/* don't ask for more than the peer can
				 * deliver in one write */
				peer_b->request = peer_b->size;
			return -1;
			}
		}

	/* we can read */
	if (peer_b->len < size)
		size = peer_b->len;

	/* now read "size" bytes */

	rest = size;

	assert(rest > 0);
	do /* one or two iterations */
		{
		size_t chunk;

		assert(rest <= peer_b->len);
		if (peer_b->offset + rest <= peer_b->size)
			chunk = rest;
		else
			/* wrap around ring buffer */
			chunk = peer_b->size - peer_b->offset;
		assert(peer_b->offset + chunk <= peer_b->size);

		memcpy(buf, peer_b->buf + peer_b->offset, chunk);

		peer_b->len -= chunk;
		if (peer_b->len)
			{
			peer_b->offset += chunk;
			assert(peer_b->offset <= peer_b->size);
			if (peer_b->offset == peer_b->size)
				peer_b->offset = 0;
			buf += chunk;
			}
		else
			{
			/* buffer now empty, no need to advance "buf" */
			assert(chunk == rest);
			peer_b->offset = 0;
			}
		rest -= chunk;
		}
	while (rest);

	return size;
	}

/* non-copying interface: provide pointer to available data in buffer
 *    bio_nread0:  return number of available bytes
 *    bio_nread:   also advance index
 * (example usage:  bio_nread0(), read from buffer, bio_nread()
 *  or just         bio_nread(), read from buffer)
 */
/* WARNING: The non-copying interface is largely untested as of yet
 * and may contain bugs. */
static ossl_ssize_t bio_nread0(BIO *bio, char **buf)
	{
	struct bio_bio_st *b, *peer_b;
	ossl_ssize_t num;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	peer_b = b->peer->ptr;
	assert(peer_b != NULL);
	assert(peer_b->buf != NULL);

	peer_b->request = 0;

	if (peer_b->len == 0)
		{
		char dummy;

		/* avoid code duplication -- nothing available for reading */
		return bio_read(bio, &dummy, 1); /* returns 0 or -1 */
		}

	num = peer_b->len;
	if (peer_b->size < peer_b->offset + num)
		/* no ring buffer wrap-around for non-copying interface */
		num = peer_b->size - peer_b->offset;
	assert(num > 0);

	if (buf != NULL)
		*buf = peer_b->buf + peer_b->offset;
	return num;
	}

static ossl_ssize_t bio_nread(BIO *bio, char **buf, size_t num_)
	{
	struct bio_bio_st *b, *peer_b;
	ossl_ssize_t num, available;

	if (num_ > SSIZE_MAX)
		num = SSIZE_MAX;
	else
		num = (ossl_ssize_t)num_;

	available = bio_nread0(bio, buf);
	if (num > available)
		num = available;
	if (num <= 0)
		return num;

	b = bio->ptr;
	peer_b = b->peer->ptr;

	peer_b->len -= num;
	if (peer_b->len)
		{
		peer_b->offset += num;
		assert(peer_b->offset <= peer_b->size);
		if (peer_b->offset == peer_b->size)
			peer_b->offset = 0;
		}
	else
		peer_b->offset = 0;

	return num;
	}


static int bio_write(BIO *bio, const char *buf, int num_)
	{
	size_t num = num_;
	size_t rest;
	struct bio_bio_st *b;

	BIO_clear_retry_flags(bio);

	if (!bio->init || buf == NULL || num == 0)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	assert(b->buf != NULL);

	b->request = 0;
	if (b->closed)
		{
		/* we already closed */
		BIOerr(BIO_F_BIO_WRITE, BIO_R_BROKEN_PIPE);
		return -1;
		}

	assert(b->len <= b->size);

	if (b->len == b->size)
		{
		BIO_set_retry_write(bio); /* buffer is full */
		return -1;
		}

	/* we can write */
	if (num > b->size - b->len)
		num = b->size - b->len;

	/* now write "num" bytes */

	rest = num;

	assert(rest > 0);
	do /* one or two iterations */
		{
		size_t write_offset;
		size_t chunk;

		assert(b->len + rest <= b->size);

		write_offset = b->offset + b->len;
		if (write_offset >= b->size)
			write_offset -= b->size;
		/* b->buf[write_offset] is the first byte we can write to. */

		if (write_offset + rest <= b->size)
			chunk = rest;
		else
			/* wrap around ring buffer */
			chunk = b->size - write_offset;

		memcpy(b->buf + write_offset, buf, chunk);

		b->len += chunk;

		assert(b->len <= b->size);

		rest -= chunk;
		buf += chunk;
		}
	while (rest);

	return num;
	}

/* non-copying interface: provide pointer to region to write to
 *   bio_nwrite0:  check how much space is available
 *   bio_nwrite:   also increase length
 * (example usage:  bio_nwrite0(), write to buffer, bio_nwrite()
 *  or just         bio_nwrite(), write to buffer)
 */
static ossl_ssize_t bio_nwrite0(BIO *bio, char **buf)
	{
	struct bio_bio_st *b;
	size_t num;
	size_t write_offset;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	assert(b->buf != NULL);

	b->request = 0;
	if (b->closed)
		{
		BIOerr(BIO_F_BIO_NWRITE0, BIO_R_BROKEN_PIPE);
		return -1;
		}

	assert(b->len <= b->size);

	if (b->len == b->size)
		{
		BIO_set_retry_write(bio);
		return -1;
		}

	num = b->size - b->len;
	write_offset = b->offset + b->len;
	if (write_offset >= b->size)
		write_offset -= b->size;
	if (write_offset + num > b->size)
		/* no ring buffer wrap-around for non-copying interface
		 * (to fulfil the promise by BIO_ctrl_get_write_guarantee,
		 * BIO_nwrite may have to be called twice) */
		num = b->size - write_offset;

	if (buf != NULL)
		*buf = b->buf + write_offset;
	assert(write_offset + num <= b->size);

	return num;
	}

static ossl_ssize_t bio_nwrite(BIO *bio, char **buf, size_t num_)
	{
	struct bio_bio_st *b;
	ossl_ssize_t num, space;

	if (num_ > SSIZE_MAX)
		num = SSIZE_MAX;
	else
		num = (ossl_ssize_t)num_;

	space = bio_nwrite0(bio, buf);
	if (num > space)
		num = space;
	if (num <= 0)
		return num;
	b = bio->ptr;
	assert(b != NULL);
	b->len += num;
	assert(b->len <= b->size);

	return num;
	}


static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
	{
	long ret;
	struct bio_bio_st *b = bio->ptr;

	assert(b != NULL);

	switch (cmd)
		{
	/* specific CTRL codes */

	case BIO_C_SET_WRITE_BUF_SIZE:
		if (b->peer)
			{
			BIOerr(BIO_F_BIO_CTRL, BIO_R_IN_USE);
			ret = 0;
			}
		else if (num == 0)
			{
			BIOerr(BIO_F_BIO_CTRL, BIO_R_INVALID_ARGUMENT);
			ret = 0;
			}
		else
			{
			size_t new_size = num;

			if (b->size != new_size)
				{
				if (b->buf)
					{
					OPENSSL_free(b->buf);
					b->buf = NULL;
					}
				b->size = new_size;
				}
			ret = 1;
			}
		break;

	case BIO_C_GET_WRITE_BUF_SIZE:
		ret = (long) b->size;
		break;

	case BIO_C_MAKE_BIO_PAIR:
		{
		BIO *other_bio = ptr;

		if (bio_make_pair(bio, other_bio))
			ret = 1;
		else
			ret = 0;
		}
		break;

	case BIO_C_DESTROY_BIO_PAIR:
		/* Affects both BIOs in the pair -- call just once!
		 * Or let BIO_free(bio1); BIO_free(bio2); do the job. */
		bio_destroy_pair(bio);
		ret = 1;
		break;

	case BIO_C_GET_WRITE_GUARANTEE:
		/* How many bytes can the caller feed to the next write
		 * without having to keep any? */
		if (b->peer == NULL || b->closed)
			ret = 0;
		else
			ret = (long) b->size - b->len;
		break;

	case BIO_C_GET_READ_REQUEST:
		/* If the peer unsuccessfully tried to read, how many bytes
		 * were requested?  (As with BIO_CTRL_PENDING, that number
		 * can usually be treated as boolean.) */
		ret = (long) b->request;
		break;

	case BIO_C_RESET_READ_REQUEST:
		/* Reset request.  (Can be useful after read attempts
		 * at the other side that are meant to be non-blocking,
		 * e.g. when probing SSL_read to see if any data is
		 * available.) */
		b->request = 0;
		ret = 1;
		break;

	case BIO_C_SHUTDOWN_WR:
		/* similar to shutdown(..., SHUT_WR) */
		b->closed = 1;
		ret = 1;
		break;

	case BIO_C_NREAD0:
		/* prepare for non-copying read */
		ret = (long) bio_nread0(bio, ptr);
		break;

	case BIO_C_NREAD:
		/* non-copying read */
		ret = (long) bio_nread(bio, ptr, (size_t) num);
		break;

	case BIO_C_NWRITE0:
		/* prepare for non-copying write */
		ret = (long) bio_nwrite0(bio, ptr);
		break;

	case BIO_C_NWRITE:
		/* non-copying write */
		ret = (long) bio_nwrite(bio, ptr, (size_t) num);
		break;


	/* standard CTRL codes follow */

	case BIO_CTRL_RESET:
		if (b->buf != NULL)
			{
			b->len = 0;
			b->offset = 0;
			}
		ret = 0;
		break;

	case BIO_CTRL_GET_CLOSE:
		ret = bio->shutdown;
		break;

	case BIO_CTRL_SET_CLOSE:
		bio->shutdown = (int) num;
		ret = 1;
		break;

	case BIO_CTRL_PENDING:
		if (b->peer != NULL)
			{
			struct bio_bio_st *peer_b = b->peer->ptr;

			ret = (long) peer_b->len;
			}
		else
			ret = 0;
		break;

	case BIO_CTRL_WPENDING:
		if (b->buf != NULL)
			ret = (long) b->len;
		else
			ret = 0;
		break;

	case BIO_CTRL_DUP:
		/* See BIO_dup_chain for circumstances we have to expect. */
		{
		BIO *other_bio = ptr;
		struct bio_bio_st *other_b;

		assert(other_bio != NULL);
		other_b = other_bio->ptr;
		assert(other_b != NULL);

		assert(other_b->buf == NULL); /* other_bio is always fresh */

		other_b->size = b->size;
		}

		ret = 1;
		break;

	case BIO_CTRL_FLUSH:
		ret = 1;
		break;

	case BIO_CTRL_EOF:
		{
		BIO *other_bio = ptr;

		if (other_bio)
			{
			struct bio_bio_st *other_b = other_bio->ptr;

			assert(other_b != NULL);
			ret = other_b->len == 0 && other_b->closed;
			}
		else
			ret = 1;
		}
		break;

	default:
		ret = 0;
		}
	return ret;
	}

static int bio_puts(BIO *bio, const char *str)
	{
	return bio_write(bio, str, strlen(str));
	}


static int bio_make_pair(BIO *bio1, BIO *bio2)
	{
	struct bio_bio_st *b1, *b2;

	assert(bio1 != NULL);
	assert(bio2 != NULL);

	b1 = bio1->ptr;
	b2 = bio2->ptr;

	if (b1->peer != NULL || b2->peer != NULL)
		{
		BIOerr(BIO_F_BIO_MAKE_PAIR, BIO_R_IN_USE);
		return 0;
		}

	if (b1->buf == NULL)
		{
		b1->buf = OPENSSL_malloc(b1->size);
		if (b1->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b1->len = 0;
		b1->offset = 0;
		}

	if (b2->buf == NULL)
		{
		b2->buf = OPENSSL_malloc(b2->size);
		if (b2->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b2->len = 0;
		b2->offset = 0;
		}

	b1->peer = bio2;
	b1->closed = 0;
	b1->request = 0;
	b2->peer = bio1;
	b2->closed = 0;
	b2->request = 0;

	bio1->init = 1;
	bio2->init = 1;

	return 1;
	}

static void bio_destroy_pair(BIO *bio)
	{
	struct bio_bio_st *b = bio->ptr;

	if (b != NULL)
		{
		BIO *peer_bio = b->peer;

		if (peer_bio != NULL)
			{
			struct bio_bio_st *peer_b = peer_bio->ptr;

			assert(peer_b != NULL);
			assert(peer_b->peer == bio);

			peer_b->peer = NULL;
			peer_bio->init = 0;
			assert(peer_b->buf != NULL);
			peer_b->len = 0;
			peer_b->offset = 0;

			b->peer = NULL;
			bio->init = 0;
			assert(b->buf != NULL);
			b->len = 0;
			b->offset = 0;
			}
		}
	}


/* Exported convenience functions */
int BIO_new_bio_pair(BIO **bio1_p, size_t writebuf1,
	BIO **bio2_p, size_t writebuf2)
	 {
	 BIO *bio1 = NULL, *bio2 = NULL;
	 long r;
	 int ret = 0;

	 bio1 = BIO_new(BIO_s_bio());
	 if (bio1 == NULL)
		 goto err;
	 bio2 = BIO_new(BIO_s_bio());
	 if (bio2 == NULL)
		 goto err;

	 if (writebuf1)
		 {
		 r = BIO_set_write_buf_size(bio1, writebuf1);
		 if (!r)
			 goto err;
		 }
	 if (writebuf2)
		 {
		 r = BIO_set_write_buf_size(bio2, writebuf2);
		 if (!r)
			 goto err;
		 }

	 r = BIO_make_bio_pair(bio1, bio2);
	 if (!r)
		 goto err;
	 ret = 1;

 err:
	 if (ret == 0)
		 {
		 if (bio1)
			 {
			 BIO_free(bio1);
			 bio1 = NULL;
			 }
		 if (bio2)
			 {
			 BIO_free(bio2);
			 bio2 = NULL;
			 }
		 }

	 *bio1_p = bio1;
	 *bio2_p = bio2;
	 return ret;
	 }

size_t BIO_ctrl_get_write_guarantee(BIO *bio)
	{
	return BIO_ctrl(bio, BIO_C_GET_WRITE_GUARANTEE, 0, NULL);
	}

size_t BIO_ctrl_get_read_request(BIO *bio)
	{
	return BIO_ctrl(bio, BIO_C_GET_READ_REQUEST, 0, NULL);
	}

int BIO_ctrl_reset_read_request(BIO *bio)
	{
	return (BIO_ctrl(bio, BIO_C_RESET_READ_REQUEST, 0, NULL) != 0);
	}


/* BIO_nread0/nread/nwrite0/nwrite are available only for BIO pairs for now
 * (conceivably some other BIOs could allow non-copying reads and writes too.)
 */
int BIO_nread0(BIO *bio, char **buf)
	{
	long ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NREAD0, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NREAD0, 0, buf);
	if (ret > INT_MAX)
		return INT_MAX;
	else
		return (int) ret;
	}

int BIO_nread(BIO *bio, char **buf, int num)
	{
	int ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NREAD, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = (int) BIO_ctrl(bio, BIO_C_NREAD, num, buf);
	if (ret > 0)
		bio->num_read += ret;
	return ret;
	}

int BIO_nwrite0(BIO *bio, char **buf)
	{
	long ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NWRITE0, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NWRITE0, 0, buf);
	if (ret > INT_MAX)
		return INT_MAX;
	else
		return (int) ret;
	}

int BIO_nwrite(BIO *bio, char **buf, int num)
	{
	int ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NWRITE, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NWRITE, num, buf);
	if (ret > 0)
		bio->num_write += ret;
	return ret;
	}

static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int mem_free(BIO *data);

//static BIO_METHOD mem_method=	//--hgl--20140331--RW mem to const mem
const BIO_METHOD mem_method=
	{
	BIO_TYPE_MEM,
	"memory buffer",
	mem_write,
	mem_read,
	mem_puts,
	mem_gets,
	mem_ctrl,
	mem_new,
	mem_free,
	NULL,
};

//////////////BIO_s_mem/////////////////////ok

BIO_METHOD *BIO_s_mem(void)
{

   return(BIO_METHOD *)(&mem_method);
}
///////////////BUF_MEM_new/////////////////////////ok

BUF_MEM *BUF_MEM_new(void)
	{
	BUF_MEM *ret;
	
	ret=OPENSSL_malloc(sizeof(BUF_MEM));
	if (ret == NULL)
		{
		BUFerr(BUF_F_BUF_MEM_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->max=0;
	ret->data=NULL;
	return(ret);
	}

//////////////// BUF_MEM_free////////////////////////ok

void BUF_MEM_free(BUF_MEM *a)
	{
		
	if(a == NULL)
	    return;
	if (a->data != NULL)
		{
		memset(a->data,0,(unsigned int)a->max);
		OPENSSL_free(a->data);
		}
	OPENSSL_free(a);
	}


/////////////////BUF_MEM_grow_clean/////////////////////////ok

int BUF_MEM_grow_clean(BUF_MEM *str, int len)
	{
	char *ret;
	unsigned int n;
	
	if (str->length >= len)
		{
		memset(&str->data[len],0,str->length-len);
		str->length=len;
		return(len);
		}
	if (str->max >= len)
		{
		memset(&str->data[str->length],0,len-str->length);
		str->length=len;
		return(len);
		}
	n=(len+3)/3*4;
	if (str->data == NULL)
		ret=OPENSSL_malloc(n);
	else
		ret=OPENSSL_realloc_clean(str->data,str->max,n);
	if (ret == NULL)
		{
		BUFerr(BUF_F_BUF_MEM_GROW_CLEAN,ERR_R_MALLOC_FAILURE);
		len=0;
		}
	else
		{
		str->data=ret;//这里是存放数据
		str->max=n;
		memset(&str->data[str->length],0,len-str->length);
		str->length=len;
		}
	return(len);
	}
//////////////////BIO_clear_flags///////////////////////////ok

void BIO_clear_flags(BIO *b, int flags)
	{
	b->flags &= ~flags;
	}
//////////////BIO_set_flags/////////////////////

void BIO_set_flags(BIO *b, int flags)
	{
	b->flags |= flags;
	}

/////////////mem_new///////////////////ok
static int mem_new(BIO *bi)
	{
	BUF_MEM *b;
	if ((b=BUF_MEM_new()) == NULL)
		return(0);
	bi->shutdown=1;
	bi->init=1;
	bi->num= -1;
	bi->ptr=(char *)b;
	return(1);
	}

////////////////mem_free///////////////////////ok

static int mem_free(BIO *a)
	{
	
	if (a == NULL) return(0);
	if (a->shutdown)
		{
		if ((a->init) && (a->ptr != NULL))
			{
			BUF_MEM *b;
			b = (BUF_MEM *)a->ptr;
			if(a->flags & BIO_FLAGS_MEM_RDONLY) b->data = NULL;
			BUF_MEM_free(b);
			a->ptr=NULL;
			}
		}
	return(1);
	}

///////////////// mem_read//////////////////////////ok

static int mem_read(BIO *b, char *out, int outl)
	{
	int ret= -1;
	BUF_MEM *bm;
	int i;
	char *from,*to;
	
	bm=(BUF_MEM *)b->ptr;
	BIO_clear_retry_flags(b);
	ret=(outl > bm->length)?bm->length:outl;
	if ((out != NULL) && (ret > 0)) {
		memcpy(out,bm->data,ret);
		bm->length-=ret;
		/* memmove(&(bm->data[0]),&(bm->data[ret]), bm->length); */
		if(b->flags & BIO_FLAGS_MEM_RDONLY) bm->data += ret;
		else {
			from=(char *)&(bm->data[ret]);
			to=(char *)&(bm->data[0]);
			for (i=0; i<bm->length; i++)
				to[i]=from[i];
		}
	} else if (bm->length == 0)
		{
		ret = b->num;
		if (ret != 0)
			BIO_set_retry_read(b);
		}
	return(ret);
	}

///////////////mem_write////////////////////////////////ok

static int mem_write(BIO *b, const char *in, int inl)
	{
	int ret= -1;
	int blen;
	BUF_MEM *bm;
	
	bm=(BUF_MEM *)b->ptr;
	if (in == NULL)
		{
		BIOerr(BIO_F_MEM_WRITE,BIO_R_NULL_PARAMETER);
		goto end;
		}

	if(b->flags & BIO_FLAGS_MEM_RDONLY) {
		BIOerr(BIO_F_MEM_WRITE,BIO_R_WRITE_TO_READ_ONLY_BIO);
		goto end;
	}

	BIO_clear_retry_flags(b);
	blen=bm->length;
	if (BUF_MEM_grow_clean(bm,blen+inl) != (blen+inl))
		goto end;
	memcpy(&(bm->data[blen]),in,inl);
	ret=inl;
end:
	return(ret);
	}


static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	return 0;
}

static int mem_gets(BIO *bp, char *buf, int size)
{
   return 0;
}

static int mem_puts(BIO *bp, const char *str)
{
	return 0;
}
/* crypto/bio/bss_mem.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int mem_free(BIO *data);
static BIO_METHOD mem_method=
	{
	BIO_TYPE_MEM,
	"memory buffer",
	mem_write,
	mem_read,
	mem_puts,
	mem_gets,
	mem_ctrl,
	mem_new,
	mem_free,
	NULL,
	};

/* bio->num is used to hold the value to return on 'empty', if it is
 * 0, should_retry is not set */

BIO_METHOD *BIO_s_mem(void)
	{
	return(&mem_method);
	}

BIO *BIO_new_mem_buf(void *buf, int len)
{
	BIO *ret;
	BUF_MEM *b;
	size_t sz;

	if (!buf) {
		BIOerr(BIO_F_BIO_NEW_MEM_BUF,BIO_R_NULL_PARAMETER);
		return NULL;
	}
	sz = (len<0) ? strlen(buf) : (size_t)len;
	if(!(ret = BIO_new(BIO_s_mem())) ) return NULL;
	b = (BUF_MEM *)ret->ptr;
	b->data = buf;
	b->length = sz;
	b->max = sz;
	ret->flags |= BIO_FLAGS_MEM_RDONLY;
	/* Since this is static data retrying wont help */
	ret->num = 0;
	return ret;
}

static int mem_new(BIO *bi)
	{
	BUF_MEM *b;

	if ((b=BUF_MEM_new()) == NULL)
		return(0);
	bi->shutdown=1;
	bi->init=1;
	bi->num= -1;
	bi->ptr=(char *)b;
	return(1);
	}

static int mem_free(BIO *a)
	{
	if (a == NULL) return(0);
	if (a->shutdown)
		{
		if ((a->init) && (a->ptr != NULL))
			{
			BUF_MEM *b;
			b = (BUF_MEM *)a->ptr;
			if(a->flags & BIO_FLAGS_MEM_RDONLY) b->data = NULL;
			BUF_MEM_free(b);
			a->ptr=NULL;
			}
		}
	return(1);
	}

static int mem_read(BIO *b, char *out, int outl)
	{
	int ret= -1;
	BUF_MEM *bm;

	bm=(BUF_MEM *)b->ptr;
	BIO_clear_retry_flags(b);
	ret=(outl >=0 && (size_t)outl > bm->length)?(int)bm->length:outl;
	if ((out != NULL) && (ret > 0)) {
		memcpy(out,bm->data,ret);
		bm->length-=ret;
		if(b->flags & BIO_FLAGS_MEM_RDONLY) bm->data += ret;
		else {
			memmove(&(bm->data[0]),&(bm->data[ret]),bm->length);
		}
	} else if (bm->length == 0)
		{
		ret = b->num;
		if (ret != 0)
			BIO_set_retry_read(b);
		}
	return(ret);
	}

static int mem_write(BIO *b, const char *in, int inl)
	{
	int ret= -1;
	int blen;
	BUF_MEM *bm;

	bm=(BUF_MEM *)b->ptr;
	if (in == NULL)
		{
		BIOerr(BIO_F_MEM_WRITE,BIO_R_NULL_PARAMETER);
		goto end;
		}

	if(b->flags & BIO_FLAGS_MEM_RDONLY) {
		BIOerr(BIO_F_MEM_WRITE,BIO_R_WRITE_TO_READ_ONLY_BIO);
		goto end;
	}

	BIO_clear_retry_flags(b);
	blen=bm->length;
	if (BUF_MEM_grow_clean(bm,blen+inl) != (blen+inl))
		goto end;
	memcpy(&(bm->data[blen]),in,inl);
	ret=inl;
end:
	return(ret);
	}

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
	{
	long ret=1;
	char **pptr;

	BUF_MEM *bm=(BUF_MEM *)b->ptr;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		if (bm->data != NULL)
			{
			/* For read only case reset to the start again */
			if(b->flags & BIO_FLAGS_MEM_RDONLY)
				{
				bm->data -= bm->max - bm->length;
				bm->length = bm->max;
				}
			else
				{
				memset(bm->data,0,bm->max);
				bm->length=0;
				}
			}
		break;
	case BIO_CTRL_EOF:
		ret=(long)(bm->length == 0);
		break;
	case BIO_C_SET_BUF_MEM_EOF_RETURN:
		b->num=(int)num;
		break;
	case BIO_CTRL_INFO:
		ret=(long)bm->length;
		if (ptr != NULL)
			{
			pptr=(char **)ptr;
			*pptr=(char *)&(bm->data[0]);
			}
		break;
	case BIO_C_SET_BUF_MEM:
		mem_free(b);
		b->shutdown=(int)num;
		b->ptr=ptr;
		break;
	case BIO_C_GET_BUF_MEM_PTR:
		if (ptr != NULL)
			{
			pptr=(char **)ptr;
			*pptr=(char *)bm;
			}
		break;
	case BIO_CTRL_GET_CLOSE:
		ret=(long)b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown=(int)num;
		break;

	case BIO_CTRL_WPENDING:
		ret=0L;
		break;
	case BIO_CTRL_PENDING:
		ret=(long)bm->length;
		break;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret=1;
		break;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
	default:
		ret=0;
		break;
		}
	return(ret);
	}

static int mem_gets(BIO *bp, char *buf, int size)
	{
	int i,j;
	int ret= -1;
	char *p;
	BUF_MEM *bm=(BUF_MEM *)bp->ptr;

	BIO_clear_retry_flags(bp);
	j=bm->length;
	if ((size-1) < j) j=size-1;
	if (j <= 0)
		{
		*buf='\0';
		return 0;
		}
	p=bm->data;
	for (i=0; i<j; i++)
		{
		if (p[i] == '\n')
			{
			i++;
			break;
			}
		}

	/*
	 * i is now the max num of bytes to copy, either j or up to
	 * and including the first newline
	 */

	i=mem_read(bp,buf,i);
	if (i > 0) buf[i]='\0';
	ret=i;
	return(ret);
	}

static int mem_puts(BIO *bp, const char *str)
	{
	int n,ret;

	n=strlen(str);
	ret=mem_write(bp,str,n);
	/* memory semantics is that it will always work */
	return(ret);
	}

//////////////BIO_free/////////////////////////ok

int BIO_free(BIO *a)
{
	int i;
	
	if (a == NULL) return(0);

	i=CRYPTO_add(&a->references,-1,CRYPTO_LOCK_BIO);////////samyang 	CRYPTO_add_lock
	if (i > 0) return(1);
	if ((a->callback != NULL) &&
		((i=(int)a->callback(a,BIO_CB_FREE,NULL,0,0L,1L)) <= 0))
			return(i);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

	if ((a->method == NULL) || (a->method->destroy == NULL)) return(1);
	a->method->destroy(a);
	OPENSSL_free(a);
	return(1);
}

static int ex_data_check(void);

#define EX_IMPL(a) impl->cb_##a
#define IMPL_CHECK if(!impl) impl_check();
#define EX_DATA_CHECK(iffail) if(!ex_data && !ex_data_check()) {iffail}

typedef struct st_ex_class_item {
	int class_index;
	STACK_OF(CRYPTO_EX_DATA_FUNCS) *meth;
	int meth_num;
} EX_CLASS_ITEM;

typedef struct st_CRYPTO_EX_DATA_IMPL	CRYPTO_EX_DATA_IMPL;

static const CRYPTO_EX_DATA_IMPL *impl = NULL;
static LHASH *ex_data = NULL;

struct st_CRYPTO_EX_DATA_IMPL
	{

	int (*cb_new_ex_data)(int class_index, void *obj,
			CRYPTO_EX_DATA *ad);
	void (*cb_free_ex_data)(int class_index, void *obj,
			CRYPTO_EX_DATA *ad);
	};


///////////////////impl_default/////////////

static int int_new_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);

static void int_free_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad);

static CRYPTO_EX_DATA_IMPL impl_default =
	{
	int_new_ex_data,
	int_free_ex_data
	};

///////////////ex_hash_cb//////////////////////ok

static unsigned long ex_hash_cb(const void *a_void)
	{

	return ((const EX_CLASS_ITEM *)a_void)->class_index;
	}

///////////////ex_cmp_cb/////////////////////////////ok

static int ex_cmp_cb(const void *a_void, const void *b_void)
	{

	return (((const EX_CLASS_ITEM *)a_void)->class_index -
		((const EX_CLASS_ITEM *)b_void)->class_index);
	}


///////////IMPL_CHECK///////////////////////ok

static void impl_check(void)
	{

	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if(!impl)
		impl = &impl_default;
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	}

////////////////CRYPTO_new_ex_data/////////////////ok

int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{

	IMPL_CHECK
	return EX_IMPL(new_ex_data)(class_index, obj, ad);
	}

/////////////////CRYPTO_free_ex_data///////////////////////////ok

void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad)
	{

	IMPL_CHECK
	EX_IMPL(free_ex_data)(class_index, obj, ad);
	}

//////////bio_set////////////////////////ok

int BIO_set(BIO *bio, BIO_METHOD *method)
	{
	bio->method=method;
	bio->callback=NULL;
	bio->cb_arg=NULL;
	bio->init=0;
	bio->shutdown=1;
	bio->flags=0;
	bio->retry_reason=0;
	bio->num=0;
	bio->ptr=NULL;
	bio->prev_bio=NULL;
	bio->next_bio=NULL;
	bio->references=1;
	bio->num_read=0L;
	bio->num_write=0L;

	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_BIO, bio, &bio->ex_data);
	if (method->create != NULL)
		if (!method->create(bio))
			{
			CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, bio,
					&bio->ex_data);
			return(0);
			}
	return(1);
	}


/////////////////BI0_new//////////////ok

BIO *BIO_new(BIO_METHOD *method)
{
	BIO *ret=NULL;

	ret=(BIO *)OPENSSL_malloc(sizeof(BIO));
	if (ret == NULL)
		{

		return(NULL);
		}
	if (!BIO_set(ret,method))
		{
		OPENSSL_free(ret);
		ret=NULL;
		}
	return(ret);
}


///////////////////def_get_class////////////////////////////////////////ok

static EX_CLASS_ITEM *def_get_class(int class_index)
	{
	EX_CLASS_ITEM d, *p, *gen;

	EX_DATA_CHECK(return NULL;)
	d.class_index = class_index;
	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	p = lh_retrieve(ex_data, &d);
	if(!p)
		{
		gen = OPENSSL_malloc(sizeof(EX_CLASS_ITEM));
		if(gen)
			{
			gen->class_index = class_index;
			gen->meth_num = 0;
			gen->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
			if(!gen->meth)
				OPENSSL_free(gen);
			else
				{

				lh_insert(ex_data, gen);
				p = gen;
				}
			}
		}
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	if(!p)
		CRYPTOerr(CRYPTO_F_DEF_GET_CLASS,ERR_R_MALLOC_FAILURE);
	return p;
	}



///////////////////int_new_ex_data/////////////////////////////////////////ok

static int int_new_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad)
	{
	int mx,i;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;

	EX_CLASS_ITEM *item = def_get_class(class_index);

	if(!item)
		/* error is already set */
		return 0;
	ad->sk = NULL;
	//CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if(mx > 0)
		{
		storage = OPENSSL_malloc(mx * sizeof(CRYPTO_EX_DATA_FUNCS*));
		if(!storage)
			goto skip;
		for(i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(item->meth,i);
		}
skip:
	//CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if((mx > 0) && !storage)
		{
		CRYPTOerr(CRYPTO_F_INT_NEW_EX_DATA,ERR_R_MALLOC_FAILURE);
		return 0;
		}
	for(i = 0; i < mx; i++)
		{
		if(storage[i] && storage[i]->new_func)
			{
				;
			}
		}
	if(storage)
		OPENSSL_free(storage);
	return 1;
	}




////////////ex_data_check//////////////////////////////////////////ok

static int ex_data_check(void)
	{
	int toret = 1;

	//CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
	if(!ex_data && ((ex_data = lh_new(ex_hash_cb, ex_cmp_cb)) == NULL))
		toret = 0;
	//CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
	return toret;
	}

///////////////int_free_ex_data/////////////////////////////////////////ok

static void int_free_ex_data(int class_index, void *obj,
		CRYPTO_EX_DATA *ad)
	{
	int mx,i;
	EX_CLASS_ITEM *item;
	CRYPTO_EX_DATA_FUNCS **storage = NULL;

	if((item = def_get_class(class_index)) == NULL)
		return;
	//CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
	mx = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
	if(mx > 0)
		{
		storage = OPENSSL_malloc(mx * sizeof(CRYPTO_EX_DATA_FUNCS*));
		if(!storage)
			goto skip;
		for(i = 0; i < mx; i++)
			storage[i] = sk_CRYPTO_EX_DATA_FUNCS_value(item->meth,i);
		}
skip:
	//CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);
	if((mx > 0) && !storage)
		{
		CRYPTOerr(CRYPTO_F_INT_FREE_EX_DATA,ERR_R_MALLOC_FAILURE);
		return;
		}
	for(i = 0; i < mx; i++)
		{
		if(storage[i] && storage[i]->free_func)
			{
				;
			}
		}
	if(storage)
		OPENSSL_free(storage);
	if(ad->sk)
		{
		sk_free(ad->sk);
		ad->sk=NULL;
		}
	}

void reset_BIO_reset(void)
{
	impl = NULL;
	ex_data = NULL;
}/* crypto/bio/b_print.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* disable assert() unless BIO_DEBUG has been defined */
/*
 * Stolen from tjh's ssl/ssl_trc.c stuff.
 */
/***************************************************************************/

/*
 * Copyright Patrick Powell 1995
 * This code is based on code written by Patrick Powell <papowell@astart.com>
 * It may be used for any purpose as long as this notice remains intact
 * on all source code distributions.
 */

/*
 * This code contains numerious changes and enhancements which were
 * made by lots of contributors over the last years to Patrick Powell's
 * original code:
 *
 * o Patrick Powell <papowell@astart.com>      (1995)
 * o Brandon Long <blong@fiction.net>          (1996, for Mutt)
 * o Thomas Roessler <roessler@guug.de>        (1998, for Mutt)
 * o Michael Elkins <me@cs.hmc.edu>            (1998, for Mutt)
 * o Andrew Tridgell <tridge@samba.org>        (1998, for Samba)
 * o Luke Mewburn <lukem@netbsd.org>           (1999, for LukemFTP)
 * o Ralf S. Engelschall <rse@engelschall.com> (1999, for Pth)
 * o ...                                       (for OpenSSL)
 */


#define LLONG long long

static void fmtstr     (char **, char **, size_t *, size_t *,
			const char *, int, int, int);
static void fmtint     (char **, char **, size_t *, size_t *,
			LLONG, int, int, int, int);
static void doapr_outch (char **, char **, size_t *, size_t *, int);
static void _dopr(char **sbuffer, char **buffer,
		  size_t *maxlen, size_t *retlen, int *truncated,
		  const char *format, va_list args);

/* format read states */
#define DP_S_DEFAULT    0
#define DP_S_FLAGS      1
#define DP_S_MIN        2
#define DP_S_DOT        3
#define DP_S_MAX        4
#define DP_S_MOD        5
#define DP_S_CONV       6
#define DP_S_DONE       7

/* format flags - Bits */
#define DP_F_MINUS      (1 << 0)
#define DP_F_PLUS       (1 << 1)
#define DP_F_SPACE      (1 << 2)
#define DP_F_NUM        (1 << 3)
#define DP_F_ZERO       (1 << 4)
#define DP_F_UP         (1 << 5)
#define DP_F_UNSIGNED   (1 << 6)

/* conversion flags */
#define DP_C_SHORT      1
#define DP_C_LONG       2
#define DP_C_LDOUBLE    3
#define DP_C_LLONG      4

/* some handy macros */
#define char_to_int(p) (p - '0')
#define OSSL_MAX(p,q) ((p >= q) ? p : q)



static int __isdigit(char c)
{
	if((c>='0') && (c<='9'))
		return 1;
	return 0;
}

static void
_dopr(
    char **sbuffer,
    char **buffer,
    size_t *maxlen,
    size_t *retlen,
    int *truncated,
    const char *format,
    va_list args)
{
    char ch;
    LLONG value;
    char *strvalue;
    int min;
    int max;
    int state;
    int flags;
    int cflags;
    size_t currlen;

    state = DP_S_DEFAULT;
    flags = currlen = cflags = min = 0;
    max = -1;
    ch = *format++;

    while (state != DP_S_DONE) {
        if (ch == '\0' || (buffer == NULL && currlen >= *maxlen))
            state = DP_S_DONE;

        switch (state) {
        case DP_S_DEFAULT:
            if (ch == '%')
                state = DP_S_FLAGS;
            else
                doapr_outch(sbuffer,buffer, &currlen, maxlen, ch);
            ch = *format++;
            break;
        case DP_S_FLAGS:
            switch (ch) {
            case '-':
                flags |= DP_F_MINUS;
                ch = *format++;
                break;
            case '+':
                flags |= DP_F_PLUS;
                ch = *format++;
                break;
            case ' ':
                flags |= DP_F_SPACE;
                ch = *format++;
                break;
            case '#':
                flags |= DP_F_NUM;
                ch = *format++;
                break;
            case '0':
                flags |= DP_F_ZERO;
                ch = *format++;
                break;
            default:
                state = DP_S_MIN;
                break;
            }
            break;
        case DP_S_MIN:
            if (__isdigit((unsigned char)ch)){
                min = 10 * min + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                min = va_arg(args, int);
                ch = *format++;
                state = DP_S_DOT;
            } else
                state = DP_S_DOT;
            break;
        case DP_S_DOT:
            if (ch == '.') {
                state = DP_S_MAX;
                ch = *format++;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MAX:
            if (__isdigit((unsigned char)ch)) {
                if (max < 0)
                    max = 0;
                max = 10 * max + char_to_int(ch);
                ch = *format++;
            } else if (ch == '*') {
                max = va_arg(args, int);
                ch = *format++;
                state = DP_S_MOD;
            } else
                state = DP_S_MOD;
            break;
        case DP_S_MOD:
            switch (ch) {
            case 'h':
                cflags = DP_C_SHORT;
                ch = *format++;
                break;
            case 'l':
                if (*format == 'l') {
                    cflags = DP_C_LLONG;
                    format++;
                } else
                    cflags = DP_C_LONG;
                ch = *format++;
                break;
            case 'q':
                cflags = DP_C_LLONG;
                ch = *format++;
                break;
            case 'L':
                cflags = DP_C_LDOUBLE;
                ch = *format++;
                break;
            default:
                break;
            }
            state = DP_S_CONV;
            break;
        case DP_S_CONV:
            switch (ch) {
            case 'd':
            case 'i':
                switch (cflags) {
                case DP_C_SHORT:
                    value = (short int)va_arg(args, int);
                    break;
                case DP_C_LONG:
                    value = va_arg(args, long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, LLONG);
                    break;
                default:
                    value = va_arg(args, int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen,
                       value, 10, min, max, flags);
                break;
            case 'X':
                flags |= DP_F_UP;
                /* FALLTHROUGH */
            case 'x':
            case 'o':
            case 'u':
                flags |= DP_F_UNSIGNED;
                switch (cflags) {
                case DP_C_SHORT:
                    value = (unsigned short int)va_arg(args, unsigned int);
                    break;
                case DP_C_LONG:
                    value = (LLONG) va_arg(args,
                        unsigned long int);
                    break;
                case DP_C_LLONG:
                    value = va_arg(args, unsigned LLONG);
                    break;
                default:
                    value = (LLONG) va_arg(args,
                        unsigned int);
                    break;
                }
                fmtint(sbuffer, buffer, &currlen, maxlen, value,
                       ch == 'o' ? 8 : (ch == 'u' ? 10 : 16),
                       min, max, flags);
                break;
//            case 'f':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                fmtfp(sbuffer, buffer, &currlen, maxlen,
//                      fvalue, min, max, flags);
//                break;
            case 'E':
                flags |= DP_F_UP;
//            case 'e':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                break;
            case 'G':
                flags |= DP_F_UP;
//            case 'g':
//                if (cflags == DP_C_LDOUBLE)
//                    fvalue = va_arg(args, LDOUBLE);
//                else
//                    fvalue = va_arg(args, double);
//                break;
            case 'c':
                doapr_outch(sbuffer, buffer, &currlen, maxlen,
                    va_arg(args, int));
                break;
            case 's':
                strvalue = va_arg(args, char *);
                if (max < 0) {
		    if (buffer)
			max = INT_MAX;
		    else
			max = *maxlen;
		}
                fmtstr(sbuffer, buffer, &currlen, maxlen, strvalue,
                       flags, min, max);
                break;
            case 'p':
                value = (long)va_arg(args, void *);
                fmtint(sbuffer, buffer, &currlen, maxlen,
                    value, 16, min, max, flags|DP_F_NUM);
                break;
            case 'n': /* XXX */
                if (cflags == DP_C_SHORT) {
                    short int *num;
                    num = va_arg(args, short int *);
                    *num = currlen;
                } else if (cflags == DP_C_LONG) { /* XXX */
                    long int *num;
                    num = va_arg(args, long int *);
                    *num = (long int) currlen;
                } else if (cflags == DP_C_LLONG) { /* XXX */
                    LLONG *num;
                    num = va_arg(args, LLONG *);
                    *num = (LLONG) currlen;
                } else {
                    int    *num;
                    num = va_arg(args, int *);
                    *num = currlen;
                }
                break;
            case '%':
                doapr_outch(sbuffer, buffer, &currlen, maxlen, ch);
                break;
            case 'w':
                /* not supported yet, treat as next char */
                ch = *format++;
                break;
            default:
                /* unknown, skip */
                break;
            }
            ch = *format++;
            state = DP_S_DEFAULT;
            flags = cflags = min = 0;
            max = -1;
            break;
        case DP_S_DONE:
            break;
        default:
            break;
        }
    }
    *truncated = (currlen > *maxlen - 1);
    if (*truncated)
        currlen = *maxlen - 1;
    doapr_outch(sbuffer, buffer, &currlen, maxlen, '\0');
    *retlen = currlen - 1;
    return;
}

static void
fmtstr(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    const char *value,
    int flags,
    int min,
    int max)
{
    int padlen, strln;
    int cnt = 0;

    if (value == 0)
        value = "<NULL>";
    for (strln = 0; value[strln]; ++strln)
        ;
    padlen = min - strln;
    if (padlen < 0)
        padlen = 0;
    if (flags & DP_F_MINUS)
        padlen = -padlen;

    while ((padlen > 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --padlen;
        ++cnt;
    }
    while (*value && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, *value++);
        ++cnt;
    }
    while ((padlen < 0) && (cnt < max)) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++padlen;
        ++cnt;
    }
}

static void
fmtint(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    LLONG value,
    int base,
    int min,
    int max,
    int flags)
{
    int signvalue = 0;
    const char *prefix = "";
    unsigned LLONG uvalue;
    char convert[DECIMAL_SIZE(value)+3];
    int place = 0;
    int spadlen = 0;
    int zpadlen = 0;
    int caps = 0;

    if (max < 0)
        max = 0;
    uvalue = value;
    if (!(flags & DP_F_UNSIGNED)) {
        if (value < 0) {
            signvalue = '-';
            uvalue = -value;
        } else if (flags & DP_F_PLUS)
            signvalue = '+';
        else if (flags & DP_F_SPACE)
            signvalue = ' ';
    }
    if (flags & DP_F_NUM) {
	if (base == 8) prefix = "0";
	if (base == 16) prefix = "0x";
    }
    if (flags & DP_F_UP)
        caps = 1;
    do {
        convert[place++] =
            (caps ? "0123456789ABCDEF" : "0123456789abcdef")
            [uvalue % (unsigned) base];
        uvalue = (uvalue / (unsigned) base);
    } while (uvalue && (place < (int)sizeof(convert)));
    if (place == sizeof(convert))
        place--;
    convert[place] = 0;

    zpadlen = max - place;
    spadlen = min - OSSL_MAX(max, place) - (signvalue ? 1 : 0) - strlen(prefix);
    if (zpadlen < 0)
        zpadlen = 0;
    if (spadlen < 0)
        spadlen = 0;
    if (flags & DP_F_ZERO) {
        zpadlen = OSSL_MAX(zpadlen, spadlen);
        spadlen = 0;
    }
    if (flags & DP_F_MINUS)
        spadlen = -spadlen;

    /* spaces */
    while (spadlen > 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        --spadlen;
    }

    /* sign */
    if (signvalue)
        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);

    /* prefix */
    while (*prefix) {
	doapr_outch(sbuffer, buffer, currlen, maxlen, *prefix);
	prefix++;
    }

    /* zeros */
    if (zpadlen > 0) {
        while (zpadlen > 0) {
            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
            --zpadlen;
        }
    }
    /* digits */
    while (place > 0)
        doapr_outch(sbuffer, buffer, currlen, maxlen, convert[--place]);

    /* left justified spaces */
    while (spadlen < 0) {
        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
        ++spadlen;
    }
    return;
}

//static LDOUBLE
//abs_val(LDOUBLE value)
//{
//    LDOUBLE result = value;
//    if (value < 0)
//        result = -value;
//    return result;
//}

//static LDOUBLE
//pow_10(int in_exp)
//{
//    LDOUBLE result = 1;
//    while (in_exp) {
//        result *= 10;
//        in_exp--;
//    }
//    return result;
//}

//static long
//roundv(LDOUBLE value)
//{
//    long intpart;
//    intpart = (long) value;
//    value = value - intpart;
//    if (value >= 0.5)
//        intpart++;
//    return intpart;
//}

//static void
//fmtfp(
//    char **sbuffer,
//    char **buffer,
//    size_t *currlen,
//    size_t *maxlen,
//    LDOUBLE fvalue,
//    int min,
//    int max,
//    int flags)
//{
//    int signvalue = 0;
//    LDOUBLE ufvalue;
//    char iconvert[20];
//    char fconvert[20];
//    int iplace = 0;
//    int fplace = 0;
//    int padlen = 0;
//    int zpadlen = 0;
//    int caps = 0;
//    long intpart;
//    long fracpart;
//    long max10;
//
//    if (max < 0)
//        max = 6;
//    ufvalue = abs_val(fvalue);
//    if (fvalue < 0)
//        signvalue = '-';
//    else if (flags & DP_F_PLUS)
//        signvalue = '+';
//    else if (flags & DP_F_SPACE)
//        signvalue = ' ';
//
//    intpart = (long)ufvalue;
//
//    /* sorry, we only support 9 digits past the decimal because of our
//       conversion method */
//    if (max > 9)
//        max = 9;
//
//    /* we "cheat" by converting the fractional part to integer by
//       multiplying by a factor of 10 */
//    max10 = roundv(pow_10(max));
//    fracpart = roundv(pow_10(max) * (ufvalue - intpart));
//
//    if (fracpart >= max10) {
//        intpart++;
//        fracpart -= max10;
//    }
//
//    /* convert integer part */
//    do {
//        iconvert[iplace++] =
//            (caps ? "0123456789ABCDEF"
//              : "0123456789abcdef")[intpart % 10];
//        intpart = (intpart / 10);
//    } while (intpart && (iplace < (int)sizeof(iconvert)));
//    if (iplace == sizeof iconvert)
//        iplace--;
//    iconvert[iplace] = 0;
//
//    /* convert fractional part */
//    do {
//        fconvert[fplace++] =
//            (caps ? "0123456789ABCDEF"
//              : "0123456789abcdef")[fracpart % 10];
//        fracpart = (fracpart / 10);
//    } while (fplace < max);
//    if (fplace == sizeof fconvert)
//        fplace--;
//    fconvert[fplace] = 0;
//
//    /* -1 for decimal point, another -1 if we are printing a sign */
//    padlen = min - iplace - max - 1 - ((signvalue) ? 1 : 0);
//    zpadlen = max - fplace;
//    if (zpadlen < 0)
//        zpadlen = 0;
//    if (padlen < 0)
//        padlen = 0;
//    if (flags & DP_F_MINUS)
//        padlen = -padlen;
//
//    if ((flags & DP_F_ZERO) && (padlen > 0)) {
//        if (signvalue) {
//            doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);
//            --padlen;
//            signvalue = 0;
//        }
//        while (padlen > 0) {
//            doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
//            --padlen;
//        }
//    }
//    while (padlen > 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
//        --padlen;
//    }
//    if (signvalue)
//        doapr_outch(sbuffer, buffer, currlen, maxlen, signvalue);
//
//    while (iplace > 0)
//        doapr_outch(sbuffer, buffer, currlen, maxlen, iconvert[--iplace]);
//
//    /*
//     * Decimal point. This should probably use locale to find the correct
//     * char to print out.
//     */
//    if (max > 0 || (flags & DP_F_NUM)) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, '.');
//
//        while (fplace > 0)
//            doapr_outch(sbuffer, buffer, currlen, maxlen, fconvert[--fplace]);
//    }
//    while (zpadlen > 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, '0');
//        --zpadlen;
//    }
//
//    while (padlen < 0) {
//        doapr_outch(sbuffer, buffer, currlen, maxlen, ' ');
//        ++padlen;
//    }
//}

static void
doapr_outch(
    char **sbuffer,
    char **buffer,
    size_t *currlen,
    size_t *maxlen,
    int c)
{
    /* If we haven't at least one buffer, someone has doe a big booboo */
    assert(*sbuffer != NULL || buffer != NULL);

    if (buffer) {
	while (*currlen >= *maxlen) {
	    if (*buffer == NULL) {
		if (*maxlen == 0)
		    *maxlen = 1024;
		*buffer = OPENSSL_malloc(*maxlen);
		if (*currlen > 0) {
		    assert(*sbuffer != NULL);
		    memcpy(*buffer, *sbuffer, *currlen);
		}
		*sbuffer = NULL;
	    } else {
		*maxlen += 1024;
		*buffer = OPENSSL_realloc(*buffer, *maxlen);
	    }
	}
	/* What to do if *buffer is NULL? */
	assert(*sbuffer != NULL || *buffer != NULL);
    }

    if (*currlen < *maxlen) {
	if (*sbuffer)
	    (*sbuffer)[(*currlen)++] = (char)c;
	else
	    (*buffer)[(*currlen)++] = (char)c;
    }

    return;
}

/***************************************************************************/

int BIO_vprintf (BIO *bio, const char *format, va_list args)
	{
	int ret;
	size_t retlen;
	char hugebuf[1024*2];	/* Was previously 10k, which is unreasonable
				   in small-stack environments, like threads
				   or DOS programs. */
	char *hugebufp = hugebuf;
	size_t hugebufsize = sizeof(hugebuf);
	char *dynbuf = NULL;
	int ignored;

	dynbuf = NULL;
	_dopr(&hugebufp, &dynbuf, &hugebufsize,
		&retlen, &ignored, format, args);
	if (dynbuf)
		{
		ret=BIO_write(bio, dynbuf, (int)retlen);
		OPENSSL_free(dynbuf);
		}
	else
		{
		ret=BIO_write(bio, hugebuf, (int)retlen);
		}

	return(ret);
	}

int BIO_printf (BIO *bio, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vprintf(bio, format, args);

	va_end(args);
	return(ret);
	}

int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
	{
	size_t retlen;
	int truncated;

	_dopr(&buf, NULL, &n, &retlen, &truncated, format, args);

	if (truncated)
		/* In case of truncation, return -1 like traditional snprintf.
		 * (Current drafts for ISO/IEC 9899 say snprintf should return
		 * the number of characters that would have been written,
		 * had the buffer been large enough.) */
		return -1;
	else
		return (retlen <= INT_MAX) ? (int)retlen : -1;
	}

/* As snprintf is not available everywhere, we provide our own implementation.
 * This function has nothing to do with BIOs, but it's closely related
 * to BIO_printf, and we need *some* name prefix ...
 * (XXX  the function should be renamed, but to what?) */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
	{
	va_list args;
	int ret;

	va_start(args, format);

	ret = BIO_vsnprintf(buf, n, format, args);

	va_end(args);
	return(ret);
	}

#define MS_CALLBACK			//samyang  modify

////////////////BIO_read/////////////////////////ok

int BIO_read(BIO *b, void *out, int outl)
	{
	int i;
	long (*cb)(BIO *,int,const char *,int,long,long);
	
	if ((b == NULL) || (b->method == NULL) || (b->method->bread == NULL))
		{
		BIOerr(BIO_F_BIO_READ,BIO_R_UNSUPPORTED_METHOD);
		return(-2);
		}

	cb=b->callback;
	if ((cb != NULL) &&
		((i=(int)cb(b,BIO_CB_READ,out,outl,0L,1L)) <= 0))
			return(i);

	if (!b->init)
		{
		BIOerr(BIO_F_BIO_READ,BIO_R_UNINITIALIZED);
		return(-2);
		}

	i=b->method->bread(b,out,outl);

	if (i > 0) b->num_read+=(unsigned long)i;

	if (cb != NULL)
		i=(int)cb(b,BIO_CB_READ|BIO_CB_RETURN,out,outl,
			0L,(long)i);
	return(i);
	}

/* crypto/bio/bss_bio.c  -*- Mode: C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1998-2003 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Special method for a BIO where the other endpoint is also a BIO
 * of this kind, handled by the same thread (i.e. the "peer" is actually
 * ourselves, wearing a different hat).
 * Such "BIO pairs" are mainly for using the SSL library with I/O interfaces
 * for which no specific BIO method is available.
 * See ssl/ssltest.c for some hints on how this can be used. */

/* BIO_DEBUG implies BIO_PAIR_DEBUG */
#ifdef BIO_DEBUG
# ifndef BIO_PAIR_DEBUG
#  define BIO_PAIR_DEBUG
# endif
#endif

/* disable assert() unless BIO_PAIR_DEBUG has been defined */
#ifndef BIO_PAIR_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif




/* VxWorks defines SSIZE_MAX with an empty value causing compile errors */
#if defined(OPENSSL_SYS_VXWORKS)
# undef SSIZE_MAX
#endif
#ifndef SSIZE_MAX
# define SSIZE_MAX INT_MAX
#endif

static int bio_new(BIO *bio);
static int bio_free(BIO *bio);
static int bio_read(BIO *bio, char *buf, int size);
static int bio_write(BIO *bio, const char *buf, int num);
static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr);
static int bio_puts(BIO *bio, const char *str);

static int bio_make_pair(BIO *bio1, BIO *bio2);
static void bio_destroy_pair(BIO *bio);

static BIO_METHOD methods_biop =
{
	BIO_TYPE_BIO,
	"BIO pair",
	bio_write,
	bio_read,
	bio_puts,
	NULL /* no bio_gets */,
	bio_ctrl,
	bio_new,
	bio_free,
	NULL /* no bio_callback_ctrl */
};

BIO_METHOD *BIO_s_bio(void)
	{
	return &methods_biop;
	}

struct bio_bio_st
{
	BIO *peer;     /* NULL if buf == NULL.
	                * If peer != NULL, then peer->ptr is also a bio_bio_st,
	                * and its "peer" member points back to us.
	                * peer != NULL iff init != 0 in the BIO. */

	/* This is for what we write (i.e. reading uses peer's struct): */
	int closed;     /* valid iff peer != NULL */
	size_t len;     /* valid iff buf != NULL; 0 if peer == NULL */
	size_t offset;  /* valid iff buf != NULL; 0 if len == 0 */
	size_t size;
	char *buf;      /* "size" elements (if != NULL) */

	size_t request; /* valid iff peer != NULL; 0 if len != 0,
	                 * otherwise set by peer to number of bytes
	                 * it (unsuccessfully) tried to read,
	                 * never more than buffer space (size-len) warrants. */
};

static int bio_new(BIO *bio)
	{
	struct bio_bio_st *b;

	b = OPENSSL_malloc(sizeof *b);
	if (b == NULL)
		return 0;

	b->peer = NULL;
	b->size = 17*1024; /* enough for one TLS record (just a default) */
	b->buf = NULL;

	bio->ptr = b;
	return 1;
	}


static int bio_free(BIO *bio)
	{
	struct bio_bio_st *b;

	if (bio == NULL)
		return 0;
	b = bio->ptr;

	assert(b != NULL);

	if (b->peer)
		bio_destroy_pair(bio);

	if (b->buf != NULL)
		{
		OPENSSL_free(b->buf);
		}

	OPENSSL_free(b);

	return 1;
	}



static int bio_read(BIO *bio, char *buf, int size_)
	{
	size_t size = size_;
	size_t rest;
	struct bio_bio_st *b, *peer_b;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	peer_b = b->peer->ptr;
	assert(peer_b != NULL);
	assert(peer_b->buf != NULL);

	peer_b->request = 0; /* will be set in "retry_read" situation */

	if (buf == NULL || size == 0)
		return 0;

	if (peer_b->len == 0)
		{
		if (peer_b->closed)
			return 0; /* writer has closed, and no data is left */
		else
			{
			BIO_set_retry_read(bio); /* buffer is empty */
			if (size <= peer_b->size)
				peer_b->request = size;
			else
				/* don't ask for more than the peer can
				 * deliver in one write */
				peer_b->request = peer_b->size;
			return -1;
			}
		}

	/* we can read */
	if (peer_b->len < size)
		size = peer_b->len;

	/* now read "size" bytes */

	rest = size;

	assert(rest > 0);
	do /* one or two iterations */
		{
		size_t chunk;

		assert(rest <= peer_b->len);
		if (peer_b->offset + rest <= peer_b->size)
			chunk = rest;
		else
			/* wrap around ring buffer */
			chunk = peer_b->size - peer_b->offset;
		assert(peer_b->offset + chunk <= peer_b->size);

		memcpy(buf, peer_b->buf + peer_b->offset, chunk);

		peer_b->len -= chunk;
		if (peer_b->len)
			{
			peer_b->offset += chunk;
			assert(peer_b->offset <= peer_b->size);
			if (peer_b->offset == peer_b->size)
				peer_b->offset = 0;
			buf += chunk;
			}
		else
			{
			/* buffer now empty, no need to advance "buf" */
			assert(chunk == rest);
			peer_b->offset = 0;
			}
		rest -= chunk;
		}
	while (rest);

	return size;
	}

/* non-copying interface: provide pointer to available data in buffer
 *    bio_nread0:  return number of available bytes
 *    bio_nread:   also advance index
 * (example usage:  bio_nread0(), read from buffer, bio_nread()
 *  or just         bio_nread(), read from buffer)
 */
/* WARNING: The non-copying interface is largely untested as of yet
 * and may contain bugs. */
static ossl_ssize_t bio_nread0(BIO *bio, char **buf)
	{
	struct bio_bio_st *b, *peer_b;
	ossl_ssize_t num;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	peer_b = b->peer->ptr;
	assert(peer_b != NULL);
	assert(peer_b->buf != NULL);

	peer_b->request = 0;

	if (peer_b->len == 0)
		{
		char dummy;

		/* avoid code duplication -- nothing available for reading */
		return bio_read(bio, &dummy, 1); /* returns 0 or -1 */
		}

	num = peer_b->len;
	if (peer_b->size < peer_b->offset + num)
		/* no ring buffer wrap-around for non-copying interface */
		num = peer_b->size - peer_b->offset;
	assert(num > 0);

	if (buf != NULL)
		*buf = peer_b->buf + peer_b->offset;
	return num;
	}

static ossl_ssize_t bio_nread(BIO *bio, char **buf, size_t num_)
	{
	struct bio_bio_st *b, *peer_b;
	ossl_ssize_t num, available;

	if (num_ > SSIZE_MAX)
		num = SSIZE_MAX;
	else
		num = (ossl_ssize_t)num_;

	available = bio_nread0(bio, buf);
	if (num > available)
		num = available;
	if (num <= 0)
		return num;

	b = bio->ptr;
	peer_b = b->peer->ptr;

	peer_b->len -= num;
	if (peer_b->len)
		{
		peer_b->offset += num;
		assert(peer_b->offset <= peer_b->size);
		if (peer_b->offset == peer_b->size)
			peer_b->offset = 0;
		}
	else
		peer_b->offset = 0;

	return num;
	}


static int bio_write(BIO *bio, const char *buf, int num_)
	{
	size_t num = num_;
	size_t rest;
	struct bio_bio_st *b;

	BIO_clear_retry_flags(bio);

	if (!bio->init || buf == NULL || num == 0)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	assert(b->buf != NULL);

	b->request = 0;
	if (b->closed)
		{
		/* we already closed */
		BIOerr(BIO_F_BIO_WRITE, BIO_R_BROKEN_PIPE);
		return -1;
		}

	assert(b->len <= b->size);

	if (b->len == b->size)
		{
		BIO_set_retry_write(bio); /* buffer is full */
		return -1;
		}

	/* we can write */
	if (num > b->size - b->len)
		num = b->size - b->len;

	/* now write "num" bytes */

	rest = num;

	assert(rest > 0);
	do /* one or two iterations */
		{
		size_t write_offset;
		size_t chunk;

		assert(b->len + rest <= b->size);

		write_offset = b->offset + b->len;
		if (write_offset >= b->size)
			write_offset -= b->size;
		/* b->buf[write_offset] is the first byte we can write to. */

		if (write_offset + rest <= b->size)
			chunk = rest;
		else
			/* wrap around ring buffer */
			chunk = b->size - write_offset;

		memcpy(b->buf + write_offset, buf, chunk);

		b->len += chunk;

		assert(b->len <= b->size);

		rest -= chunk;
		buf += chunk;
		}
	while (rest);

	return num;
	}

/* non-copying interface: provide pointer to region to write to
 *   bio_nwrite0:  check how much space is available
 *   bio_nwrite:   also increase length
 * (example usage:  bio_nwrite0(), write to buffer, bio_nwrite()
 *  or just         bio_nwrite(), write to buffer)
 */
static ossl_ssize_t bio_nwrite0(BIO *bio, char **buf)
	{
	struct bio_bio_st *b;
	size_t num;
	size_t write_offset;

	BIO_clear_retry_flags(bio);

	if (!bio->init)
		return 0;

	b = bio->ptr;
	assert(b != NULL);
	assert(b->peer != NULL);
	assert(b->buf != NULL);

	b->request = 0;
	if (b->closed)
		{
		BIOerr(BIO_F_BIO_NWRITE0, BIO_R_BROKEN_PIPE);
		return -1;
		}

	assert(b->len <= b->size);

	if (b->len == b->size)
		{
		BIO_set_retry_write(bio);
		return -1;
		}

	num = b->size - b->len;
	write_offset = b->offset + b->len;
	if (write_offset >= b->size)
		write_offset -= b->size;
	if (write_offset + num > b->size)
		/* no ring buffer wrap-around for non-copying interface
		 * (to fulfil the promise by BIO_ctrl_get_write_guarantee,
		 * BIO_nwrite may have to be called twice) */
		num = b->size - write_offset;

	if (buf != NULL)
		*buf = b->buf + write_offset;
	assert(write_offset + num <= b->size);

	return num;
	}

static ossl_ssize_t bio_nwrite(BIO *bio, char **buf, size_t num_)
	{
	struct bio_bio_st *b;
	ossl_ssize_t num, space;

	if (num_ > SSIZE_MAX)
		num = SSIZE_MAX;
	else
		num = (ossl_ssize_t)num_;

	space = bio_nwrite0(bio, buf);
	if (num > space)
		num = space;
	if (num <= 0)
		return num;
	b = bio->ptr;
	assert(b != NULL);
	b->len += num;
	assert(b->len <= b->size);

	return num;
	}


static long bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
	{
	long ret;
	struct bio_bio_st *b = bio->ptr;

	assert(b != NULL);

	switch (cmd)
		{
	/* specific CTRL codes */

	case BIO_C_SET_WRITE_BUF_SIZE:
		if (b->peer)
			{
			BIOerr(BIO_F_BIO_CTRL, BIO_R_IN_USE);
			ret = 0;
			}
		else if (num == 0)
			{
			BIOerr(BIO_F_BIO_CTRL, BIO_R_INVALID_ARGUMENT);
			ret = 0;
			}
		else
			{
			size_t new_size = num;

			if (b->size != new_size)
				{
				if (b->buf)
					{
					OPENSSL_free(b->buf);
					b->buf = NULL;
					}
				b->size = new_size;
				}
			ret = 1;
			}
		break;

	case BIO_C_GET_WRITE_BUF_SIZE:
		ret = (long) b->size;
		break;

	case BIO_C_MAKE_BIO_PAIR:
		{
		BIO *other_bio = ptr;

		if (bio_make_pair(bio, other_bio))
			ret = 1;
		else
			ret = 0;
		}
		break;

	case BIO_C_DESTROY_BIO_PAIR:
		/* Affects both BIOs in the pair -- call just once!
		 * Or let BIO_free(bio1); BIO_free(bio2); do the job. */
		bio_destroy_pair(bio);
		ret = 1;
		break;

	case BIO_C_GET_WRITE_GUARANTEE:
		/* How many bytes can the caller feed to the next write
		 * without having to keep any? */
		if (b->peer == NULL || b->closed)
			ret = 0;
		else
			ret = (long) b->size - b->len;
		break;

	case BIO_C_GET_READ_REQUEST:
		/* If the peer unsuccessfully tried to read, how many bytes
		 * were requested?  (As with BIO_CTRL_PENDING, that number
		 * can usually be treated as boolean.) */
		ret = (long) b->request;
		break;

	case BIO_C_RESET_READ_REQUEST:
		/* Reset request.  (Can be useful after read attempts
		 * at the other side that are meant to be non-blocking,
		 * e.g. when probing SSL_read to see if any data is
		 * available.) */
		b->request = 0;
		ret = 1;
		break;

	case BIO_C_SHUTDOWN_WR:
		/* similar to shutdown(..., SHUT_WR) */
		b->closed = 1;
		ret = 1;
		break;

	case BIO_C_NREAD0:
		/* prepare for non-copying read */
		ret = (long) bio_nread0(bio, ptr);
		break;

	case BIO_C_NREAD:
		/* non-copying read */
		ret = (long) bio_nread(bio, ptr, (size_t) num);
		break;

	case BIO_C_NWRITE0:
		/* prepare for non-copying write */
		ret = (long) bio_nwrite0(bio, ptr);
		break;

	case BIO_C_NWRITE:
		/* non-copying write */
		ret = (long) bio_nwrite(bio, ptr, (size_t) num);
		break;


	/* standard CTRL codes follow */

	case BIO_CTRL_RESET:
		if (b->buf != NULL)
			{
			b->len = 0;
			b->offset = 0;
			}
		ret = 0;
		break;

	case BIO_CTRL_GET_CLOSE:
		ret = bio->shutdown;
		break;

	case BIO_CTRL_SET_CLOSE:
		bio->shutdown = (int) num;
		ret = 1;
		break;

	case BIO_CTRL_PENDING:
		if (b->peer != NULL)
			{
			struct bio_bio_st *peer_b = b->peer->ptr;

			ret = (long) peer_b->len;
			}
		else
			ret = 0;
		break;

	case BIO_CTRL_WPENDING:
		if (b->buf != NULL)
			ret = (long) b->len;
		else
			ret = 0;
		break;

	case BIO_CTRL_DUP:
		/* See BIO_dup_chain for circumstances we have to expect. */
		{
		BIO *other_bio = ptr;
		struct bio_bio_st *other_b;

		assert(other_bio != NULL);
		other_b = other_bio->ptr;
		assert(other_b != NULL);

		assert(other_b->buf == NULL); /* other_bio is always fresh */

		other_b->size = b->size;
		}

		ret = 1;
		break;

	case BIO_CTRL_FLUSH:
		ret = 1;
		break;

	case BIO_CTRL_EOF:
		{
		BIO *other_bio = ptr;

		if (other_bio)
			{
			struct bio_bio_st *other_b = other_bio->ptr;

			assert(other_b != NULL);
			ret = other_b->len == 0 && other_b->closed;
			}
		else
			ret = 1;
		}
		break;

	default:
		ret = 0;
		}
	return ret;
	}

static int bio_puts(BIO *bio, const char *str)
	{
	return bio_write(bio, str, strlen(str));
	}


static int bio_make_pair(BIO *bio1, BIO *bio2)
	{
	struct bio_bio_st *b1, *b2;

	assert(bio1 != NULL);
	assert(bio2 != NULL);

	b1 = bio1->ptr;
	b2 = bio2->ptr;

	if (b1->peer != NULL || b2->peer != NULL)
		{
		BIOerr(BIO_F_BIO_MAKE_PAIR, BIO_R_IN_USE);
		return 0;
		}

	if (b1->buf == NULL)
		{
		b1->buf = OPENSSL_malloc(b1->size);
		if (b1->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b1->len = 0;
		b1->offset = 0;
		}

	if (b2->buf == NULL)
		{
		b2->buf = OPENSSL_malloc(b2->size);
		if (b2->buf == NULL)
			{
			BIOerr(BIO_F_BIO_MAKE_PAIR, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		b2->len = 0;
		b2->offset = 0;
		}

	b1->peer = bio2;
	b1->closed = 0;
	b1->request = 0;
	b2->peer = bio1;
	b2->closed = 0;
	b2->request = 0;

	bio1->init = 1;
	bio2->init = 1;

	return 1;
	}

static void bio_destroy_pair(BIO *bio)
	{
	struct bio_bio_st *b = bio->ptr;

	if (b != NULL)
		{
		BIO *peer_bio = b->peer;

		if (peer_bio != NULL)
			{
			struct bio_bio_st *peer_b = peer_bio->ptr;

			assert(peer_b != NULL);
			assert(peer_b->peer == bio);

			peer_b->peer = NULL;
			peer_bio->init = 0;
			assert(peer_b->buf != NULL);
			peer_b->len = 0;
			peer_b->offset = 0;

			b->peer = NULL;
			bio->init = 0;
			assert(b->buf != NULL);
			b->len = 0;
			b->offset = 0;
			}
		}
	}


/* Exported convenience functions */
int BIO_new_bio_pair(BIO **bio1_p, size_t writebuf1,
	BIO **bio2_p, size_t writebuf2)
	 {
	 BIO *bio1 = NULL, *bio2 = NULL;
	 long r;
	 int ret = 0;

	 bio1 = BIO_new(BIO_s_bio());
	 if (bio1 == NULL)
		 goto err;
	 bio2 = BIO_new(BIO_s_bio());
	 if (bio2 == NULL)
		 goto err;

	 if (writebuf1)
		 {
		 r = BIO_set_write_buf_size(bio1, writebuf1);
		 if (!r)
			 goto err;
		 }
	 if (writebuf2)
		 {
		 r = BIO_set_write_buf_size(bio2, writebuf2);
		 if (!r)
			 goto err;
		 }

	 r = BIO_make_bio_pair(bio1, bio2);
	 if (!r)
		 goto err;
	 ret = 1;

 err:
	 if (ret == 0)
		 {
		 if (bio1)
			 {
			 BIO_free(bio1);
			 bio1 = NULL;
			 }
		 if (bio2)
			 {
			 BIO_free(bio2);
			 bio2 = NULL;
			 }
		 }

	 *bio1_p = bio1;
	 *bio2_p = bio2;
	 return ret;
	 }

size_t BIO_ctrl_get_write_guarantee(BIO *bio)
	{
	return BIO_ctrl(bio, BIO_C_GET_WRITE_GUARANTEE, 0, NULL);
	}

size_t BIO_ctrl_get_read_request(BIO *bio)
	{
	return BIO_ctrl(bio, BIO_C_GET_READ_REQUEST, 0, NULL);
	}

int BIO_ctrl_reset_read_request(BIO *bio)
	{
	return (BIO_ctrl(bio, BIO_C_RESET_READ_REQUEST, 0, NULL) != 0);
	}


/* BIO_nread0/nread/nwrite0/nwrite are available only for BIO pairs for now
 * (conceivably some other BIOs could allow non-copying reads and writes too.)
 */
int BIO_nread0(BIO *bio, char **buf)
	{
	long ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NREAD0, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NREAD0, 0, buf);
	if (ret > INT_MAX)
		return INT_MAX;
	else
		return (int) ret;
	}

int BIO_nread(BIO *bio, char **buf, int num)
	{
	int ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NREAD, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = (int) BIO_ctrl(bio, BIO_C_NREAD, num, buf);
	if (ret > 0)
		bio->num_read += ret;
	return ret;
	}

int BIO_nwrite0(BIO *bio, char **buf)
	{
	long ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NWRITE0, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NWRITE0, 0, buf);
	if (ret > INT_MAX)
		return INT_MAX;
	else
		return (int) ret;
	}

int BIO_nwrite(BIO *bio, char **buf, int num)
	{
	int ret;

	if (!bio->init)
		{
		BIOerr(BIO_F_BIO_NWRITE, BIO_R_UNINITIALIZED);
		return -2;
		}

	ret = BIO_ctrl(bio, BIO_C_NWRITE, num, buf);
	if (ret > 0)
		bio->num_write += ret;
	return ret;
	}

static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int mem_free(BIO *data);

//static BIO_METHOD mem_method=	//--hgl--20140331--RW mem to const mem
const BIO_METHOD mem_method=
	{
	BIO_TYPE_MEM,
	"memory buffer",
	mem_write,
	mem_read,
	mem_puts,
	mem_gets,
	mem_ctrl,
	mem_new,
	mem_free,
	NULL,
};

//////////////BIO_s_mem/////////////////////ok

BIO_METHOD *BIO_s_mem(void)
{

   return(BIO_METHOD *)(&mem_method);
}
///////////////BUF_MEM_new/////////////////////////ok

BUF_MEM *BUF_MEM_new(void)
	{
	BUF_MEM *ret;
	
	ret=OPENSSL_malloc(sizeof(BUF_MEM));
	if (ret == NULL)
		{
		BUFerr(BUF_F_BUF_MEM_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->max=0;
	ret->data=NULL;
	return(ret);
	}

//////////////// BUF_MEM_free////////////////////////ok

void BUF_MEM_free(BUF_MEM *a)
	{
		
	if(a == NULL)
	    return;
	if (a->data != NULL)
		{
		memset(a->data,0,(unsigned int)a->max);
		OPENSSL_free(a->data);
		}
	OPENSSL_free(a);
	}


/////////////////BUF_MEM_grow_clean/////////////////////////ok

int BUF_MEM_grow_clean(BUF_MEM *str, int len)
	{
	char *ret;
	unsigned int n;
	
	if (str->length >= len)
		{
		memset(&str->data[len],0,str->length-len);
		str->length=len;
		return(len);
		}
	if (str->max >= len)
		{
		memset(&str->data[str->length],0,len-str->length);
		str->length=len;
		return(len);
		}
	n=(len+3)/3*4;
	if (str->data == NULL)
		ret=OPENSSL_malloc(n);
	else
		ret=OPENSSL_realloc_clean(str->data,str->max,n);
	if (ret == NULL)
		{
		BUFerr(BUF_F_BUF_MEM_GROW_CLEAN,ERR_R_MALLOC_FAILURE);
		len=0;
		}
	else
		{
		str->data=ret;//这里是存放数据
		str->max=n;
		memset(&str->data[str->length],0,len-str->length);
		str->length=len;
		}
	return(len);
	}
//////////////////BIO_clear_flags///////////////////////////ok

void BIO_clear_flags(BIO *b, int flags)
	{
	b->flags &= ~flags;
	}
//////////////BIO_set_flags/////////////////////

void BIO_set_flags(BIO *b, int flags)
	{
	b->flags |= flags;
	}

/////////////mem_new///////////////////ok
static int mem_new(BIO *bi)
	{
	BUF_MEM *b;
	if ((b=BUF_MEM_new()) == NULL)
		return(0);
	bi->shutdown=1;
	bi->init=1;
	bi->num= -1;
	bi->ptr=(char *)b;
	return(1);
	}

////////////////mem_free///////////////////////ok

static int mem_free(BIO *a)
	{
	
	if (a == NULL) return(0);
	if (a->shutdown)
		{
		if ((a->init) && (a->ptr != NULL))
			{
			BUF_MEM *b;
			b = (BUF_MEM *)a->ptr;
			if(a->flags & BIO_FLAGS_MEM_RDONLY) b->data = NULL;
			BUF_MEM_free(b);
			a->ptr=NULL;
			}
		}
	return(1);
	}

///////////////// mem_read//////////////////////////ok

static int mem_read(BIO *b, char *out, int outl)
	{
	int ret= -1;
	BUF_MEM *bm;
	int i;
	char *from,*to;
	
	bm=(BUF_MEM *)b->ptr;
	BIO_clear_retry_flags(b);
	ret=(outl > bm->length)?bm->length:outl;
	if ((out != NULL) && (ret > 0)) {
		memcpy(out,bm->data,ret);
		bm->length-=ret;
		/* memmove(&(bm->data[0]),&(bm->data[ret]), bm->length); */
		if(b->flags & BIO_FLAGS_MEM_RDONLY) bm->data += ret;
		else {
			from=(char *)&(bm->data[ret]);
			to=(char *)&(bm->data[0]);
			for (i=0; i<bm->length; i++)
				to[i]=from[i];
		}
	} else if (bm->length == 0)
		{
		ret = b->num;
		if (ret != 0)
			BIO_set_retry_read(b);
		}
	return(ret);
	}

///////////////mem_write////////////////////////////////ok

static int mem_write(BIO *b, const char *in, int inl)
	{
	int ret= -1;
	int blen;
	BUF_MEM *bm;
	
	bm=(BUF_MEM *)b->ptr;
	if (in == NULL)
		{
		BIOerr(BIO_F_MEM_WRITE,BIO_R_NULL_PARAMETER);
		goto end;
		}

	if(b->flags & BIO_FLAGS_MEM_RDONLY) {
		BIOerr(BIO_F_MEM_WRITE,BIO_R_WRITE_TO_READ_ONLY_BIO);
		goto end;
	}

	BIO_clear_retry_flags(b);
	blen=bm->length;
	if (BUF_MEM_grow_clean(bm,blen+inl) != (blen+inl))
		goto end;
	memcpy(&(bm->data[blen]),in,inl);
	ret=inl;
end:
	return(ret);
	}


static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	return 0;
}

static int mem_gets(BIO *bp, char *buf, int size)
{
   return 0;
}

static int mem_puts(BIO *bp, const char *str)
{
	return 0;
}
/* crypto/bio/bss_mem.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


static int mem_write(BIO *h, const char *buf, int num);
static int mem_read(BIO *h, char *buf, int size);
static int mem_puts(BIO *h, const char *str);
static int mem_gets(BIO *h, char *str, int size);
static long mem_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int mem_new(BIO *h);
static int mem_free(BIO *data);
static BIO_METHOD mem_method=
	{
	BIO_TYPE_MEM,
	"memory buffer",
	mem_write,
	mem_read,
	mem_puts,
	mem_gets,
	mem_ctrl,
	mem_new,
	mem_free,
	NULL,
	};

/* bio->num is used to hold the value to return on 'empty', if it is
 * 0, should_retry is not set */

BIO_METHOD *BIO_s_mem(void)
	{
	return(&mem_method);
	}

BIO *BIO_new_mem_buf(void *buf, int len)
{
	BIO *ret;
	BUF_MEM *b;
	size_t sz;

	if (!buf) {
		BIOerr(BIO_F_BIO_NEW_MEM_BUF,BIO_R_NULL_PARAMETER);
		return NULL;
	}
	sz = (len<0) ? strlen(buf) : (size_t)len;
	if(!(ret = BIO_new(BIO_s_mem())) ) return NULL;
	b = (BUF_MEM *)ret->ptr;
	b->data = buf;
	b->length = sz;
	b->max = sz;
	ret->flags |= BIO_FLAGS_MEM_RDONLY;
	/* Since this is static data retrying wont help */
	ret->num = 0;
	return ret;
}

static int mem_new(BIO *bi)
	{
	BUF_MEM *b;

	if ((b=BUF_MEM_new()) == NULL)
		return(0);
	bi->shutdown=1;
	bi->init=1;
	bi->num= -1;
	bi->ptr=(char *)b;
	return(1);
	}

static int mem_free(BIO *a)
	{
	if (a == NULL) return(0);
	if (a->shutdown)
		{
		if ((a->init) && (a->ptr != NULL))
			{
			BUF_MEM *b;
			b = (BUF_MEM *)a->ptr;
			if(a->flags & BIO_FLAGS_MEM_RDONLY) b->data = NULL;
			BUF_MEM_free(b);
			a->ptr=NULL;
			}
		}
	return(1);
	}

static int mem_read(BIO *b, char *out, int outl)
	{
	int ret= -1;
	BUF_MEM *bm;

	bm=(BUF_MEM *)b->ptr;
	BIO_clear_retry_flags(b);
	ret=(outl >=0 && (size_t)outl > bm->length)?(int)bm->length:outl;
	if ((out != NULL) && (ret > 0)) {
		memcpy(out,bm->data,ret);
		bm->length-=ret;
		if(b->flags & BIO_FLAGS_MEM_RDONLY) bm->data += ret;
		else {
			memmove(&(bm->data[0]),&(bm->data[ret]),bm->length);
		}
	} else if (bm->length == 0)
		{
		ret = b->num;
		if (ret != 0)
			BIO_set_retry_read(b);
		}
	return(ret);
	}

static int mem_write(BIO *b, const char *in, int inl)
	{
	int ret= -1;
	int blen;
	BUF_MEM *bm;

	bm=(BUF_MEM *)b->ptr;
	if (in == NULL)
		{
		BIOerr(BIO_F_MEM_WRITE,BIO_R_NULL_PARAMETER);
		goto end;
		}

	if(b->flags & BIO_FLAGS_MEM_RDONLY) {
		BIOerr(BIO_F_MEM_WRITE,BIO_R_WRITE_TO_READ_ONLY_BIO);
		goto end;
	}

	BIO_clear_retry_flags(b);
	blen=bm->length;
	if (BUF_MEM_grow_clean(bm,blen+inl) != (blen+inl))
		goto end;
	memcpy(&(bm->data[blen]),in,inl);
	ret=inl;
end:
	return(ret);
	}

static long mem_ctrl(BIO *b, int cmd, long num, void *ptr)
	{
	long ret=1;
	char **pptr;

	BUF_MEM *bm=(BUF_MEM *)b->ptr;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		if (bm->data != NULL)
			{
			/* For read only case reset to the start again */
			if(b->flags & BIO_FLAGS_MEM_RDONLY)
				{
				bm->data -= bm->max - bm->length;
				bm->length = bm->max;
				}
			else
				{
				memset(bm->data,0,bm->max);
				bm->length=0;
				}
			}
		break;
	case BIO_CTRL_EOF:
		ret=(long)(bm->length == 0);
		break;
	case BIO_C_SET_BUF_MEM_EOF_RETURN:
		b->num=(int)num;
		break;
	case BIO_CTRL_INFO:
		ret=(long)bm->length;
		if (ptr != NULL)
			{
			pptr=(char **)ptr;
			*pptr=(char *)&(bm->data[0]);
			}
		break;
	case BIO_C_SET_BUF_MEM:
		mem_free(b);
		b->shutdown=(int)num;
		b->ptr=ptr;
		break;
	case BIO_C_GET_BUF_MEM_PTR:
		if (ptr != NULL)
			{
			pptr=(char **)ptr;
			*pptr=(char *)bm;
			}
		break;
	case BIO_CTRL_GET_CLOSE:
		ret=(long)b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown=(int)num;
		break;

	case BIO_CTRL_WPENDING:
		ret=0L;
		break;
	case BIO_CTRL_PENDING:
		ret=(long)bm->length;
		break;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret=1;
		break;
	case BIO_CTRL_PUSH:
	case BIO_CTRL_POP:
	default:
		ret=0;
		break;
		}
	return(ret);
	}

static int mem_gets(BIO *bp, char *buf, int size)
	{
	int i,j;
	int ret= -1;
	char *p;
	BUF_MEM *bm=(BUF_MEM *)bp->ptr;

	BIO_clear_retry_flags(bp);
	j=bm->length;
	if ((size-1) < j) j=size-1;
	if (j <= 0)
		{
		*buf='\0';
		return 0;
		}
	p=bm->data;
	for (i=0; i<j; i++)
		{
		if (p[i] == '\n')
			{
			i++;
			break;
			}
		}

	/*
	 * i is now the max num of bytes to copy, either j or up to
	 * and including the first newline
	 */

	i=mem_read(bp,buf,i);
	if (i > 0) buf[i]='\0';
	ret=i;
	return(ret);
	}

static int mem_puts(BIO *bp, const char *str)
	{
	int n,ret;

	n=strlen(str);
	ret=mem_write(bp,str,n);
	/* memory semantics is that it will always work */
	return(ret);
	}

//////////////BIO_free/////////////////////////ok

int BIO_free(BIO *a)
{
	int i;
	
	if (a == NULL) return(0);

	i=CRYPTO_add(&a->references,-1,CRYPTO_LOCK_BIO);////////samyang 	CRYPTO_add_lock
	if (i > 0) return(1);
	if ((a->callback != NULL) &&
		((i=(int)a->callback(a,BIO_CB_FREE,NULL,0,0L,1L)) <= 0))
			return(i);

	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_BIO, a, &a->ex_data);

	if ((a->method == NULL) || (a->method->destroy == NULL)) return(1);
	a->method->destroy(a);
	OPENSSL_free(a);
	return(1);
}
/*
**********************************************************************************************************************
*											        eGon
*						           the Embedded GO-ON Bootloader System
*									       eGON arm boot sub-system
*
*						  Copyright(C), 2006-2014, Allwinner Technology Co., Ltd.
*                                           All Rights Reserved
*
* File    :
*
* By      : Jerry
*
* Version : V2.00
*
* Date	  :
*
* Descript:
**********************************************************************************************************************
*/

int sunxi_bytes_merge(u8 *dst, u32 dst_len, u8 *src, uint src_len);
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static int __asn1_probe_data_head(u8 *buf, sunxi_asn1_t *asn1)
{
	u8 *tmp_buf = buf;
	int index;
	int len, len_bytes;

	asn1->head     = tmp_buf[0];
	asn1->head_len = 2;
	//获取长度
	len = tmp_buf[1];
	if(len & 0x80)		//超过1个字节表示长度
	{
		len_bytes = len & 0x7f;
		if((!len_bytes) || (len_bytes>4))
		{
			printf("len_bytes(%d) is 0 or larger than 4, cant be probe\n", len_bytes);

			return -1;
		}
		asn1->head_len += len_bytes;
		index = 2;
		len = 0;
		while(--len_bytes);
		{
			len += tmp_buf[index++];
			len *= 256;
		}
		len |= tmp_buf[index];

	}
	asn1->data = buf + asn1->head_len;
	asn1->data_len = len;

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static  int __sunxi_publickey_dipatch(sunxi_key_t *pkey, u8 *buf, u32 len)
{
	u8 *tmp_buf = buf;
	int ret;
	sunxi_asn1_t asn1;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("publickey_dipatch err: head is not a sequence\n");

		return -1;
	}
	tmp_buf += asn1.head_len;		//跳过sequnce头部
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if((ret) || (asn1.head != 0x2))	//
	{
		printf("publickey_dipatch err: step 2\n");

		return -2;
	}
	pkey->n = malloc(asn1.data_len);
	memcpy(pkey->n, asn1.data, asn1.data_len);
	pkey->n_len = asn1.data_len;

	tmp_buf = asn1.data + asn1.data_len;
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if((ret) || (asn1.head != 0x2))
	{
		printf("publickey_dipatch err: step 3\n");

		return -3;
	}

	pkey->e = malloc(asn1.data_len);
	memcpy(pkey->e, asn1.data, asn1.data_len);
	pkey->e_len = asn1.data_len;

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static int __certif_probe_signdata(u8 *dst_buf, u32 dst_len_max, u8 *src_buf, u32 src_len)
{
	u8 *tmp_buf = src_buf;
	int ret;
	sunxi_asn1_t asn1;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("certif_decode err: head is not a sequence\n");

		return -1;
	}
	tmp_buf += asn1.head_len;		//跳过sequnce头部
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret)
	{
		printf("certif_decode err: step 1\n");

		return -2;
	}

	if(asn1.data_len > dst_len_max)
	{
		printf("sign data len (0x%x) is longer then buffer size (0x%x)\n", asn1.data_len, dst_len_max);

		return -1;
	}
	memcpy(dst_buf, tmp_buf, asn1.data_len + asn1.head_len);

	return asn1.data_len + asn1.head_len;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static uint __merge_extension_value(u8 **dst_buf, u8 *src_buf, uint src_buf_len)
{
	u8 *tmp_buf = src_buf;
	sunxi_asn1_t asn1;
	int ret;
	uint tmp_len;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("__merge_extension_value err: head is not a sequence\n");

		return 0;
	}

	if(asn1.data_len + asn1.head_len > src_buf_len)
	{
		printf("__merge_extension_value err: the data source len is too short\n");

		return 0;
	}
	*dst_buf = malloc((asn1.data_len + 1)/2);
	memset(*dst_buf, 0, (asn1.data_len + 1)/2);
	tmp_len = asn1.data_len;
	if(tmp_len > 512)		//rsakey
	{
		u8 *src = asn1.data;
		if((src[0] == '0') && (src[1] == '0'))
		{
			src += 2;
		}
		if(sunxi_bytes_merge(*dst_buf, asn1.data_len, src, 512))
		{
			printf("__merge_extension_value err1: in sunxi_bytes_merge\n");

			return 0;
		}
		if(sunxi_bytes_merge(*dst_buf + 512/2, asn1.data_len, src + 512, asn1.data_len - 512 - (src-asn1.data)))
		{
			printf("__merge_extension_value err2: in sunxi_bytes_merge\n");

			return 0;
		}
	}
	else
	{
		if(sunxi_bytes_merge(*dst_buf, asn1.data_len, asn1.data, asn1.data_len))
		{
			printf("__merge_extension_value err1: in sunxi_bytes_merge\n");

			return 0;
		}
	}

	//memcpy(*dst_buf, asn1.data, asn1.data_len);

	return (asn1.data_len + 1)/2;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_create(X509 **certif, u8 *buf, int len)
{
	u8 *p = buf;

	*certif = d2i_X509(NULL, (const unsigned char **)&p, len);
	if(*certif == NULL)
	{
		printf("x509_create: cant get a certif\n");

		return -1;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_free(X509 *certif)
{
	if(certif)
	{
		X509_free(certif);
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_serial_num(X509 *x)
{
	ASN1_INTEGER *bs = NULL;
	long serial_num = 0;

	bs = X509_get_serialNumber(x);
	if(bs->length <= 4)
	{
		serial_num = ASN1_INTEGER_get(bs);
		printf("SERIANL NUMBER: 0x%x\n", (unsigned int)serial_num);
	}
	else
	{
		printf("SERIANL NUMBER: Unknown\n");
	}

	return 0 ;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_version(X509 *x)
{
	long version = 0;

	version = X509_get_version(x);
	printf("Version: 0x%0x\n", (unsigned int)version);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
#define BUFF_NAME_MAX  128
#define BUFF_VALUE_MAX  3072

int sunxi_certif_probe_extension(X509 *x, sunxi_certif_info_t *sunxi_certif)
{
	int extension_count = X509_get_ext_count(x);
	X509_EXTENSION *extension;
	int i, len;
	ASN1_OBJECT *obj;
	u8 buff_name[BUFF_NAME_MAX];
	u8 buff_value[BUFF_VALUE_MAX];

	//printf("extension_count=%d\n", extension_count);
	sunxi_certif->extension.extension_num = extension_count;

	for(i = 0; i < extension_count; i++)
	{
		//printf("************%d***************\n", i);
		//printf("extension name:\n");
		extension=sk_X509_EXTENSION_value(x->cert_info->extensions, i);
		if(!extension)
		{
			printf("get extersion %d fail\n", i);

			return -1;
		}
		obj = X509_EXTENSION_get_object(extension);
		if(!obj)
		{
			printf("get extersion obj %d fail\n", i);

			return -1;
		}
		memset(buff_name, 0, BUFF_NAME_MAX);
		//while((*(volatile int *)0)!=12);
		//len = OBJ_obj2txt(buff_name, BUFF_NAME_MAX, obj, 0);
		len = OBJ_obj2name((char *)buff_name, BUFF_NAME_MAX, obj);
		if(!len)
		{
			printf("extersion %d name length is 0\n", i);
		}
		else
		{
			//printf("name len=%d\n", len);
			sunxi_certif->extension.name[i] = malloc(len + 1);
			memcpy(sunxi_certif->extension.name[i], buff_name, len);
			sunxi_certif->extension.name[i][len] = '\0';
			sunxi_certif->extension.name_len[i] = len;

			//xdump(sunxi_certif->extension.name[i], len);
		}

		memset(buff_value,0,BUFF_NAME_MAX);
		len = ASN1_STRING_mem((char *)buff_value, extension->value);
		if(!len)
		{
			printf("extersion %d value length is 0\n", i);
		}
		else
		{
			//xdump(buff_value, len);
			len = __merge_extension_value(&sunxi_certif->extension.value[i], buff_value, len);
			if(!len)
			{
				printf("get extension value failed\n");

				return -1;
			}
			sunxi_certif->extension.value_len[i] = len;
			//printf("value len=%d\n", len);

			//ndump(sunxi_certif->extension.value[i], len);
		}
		//printf("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>\n");
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_pubkey(X509 *x, sunxi_key_t *pubkey)
{
	EVP_PKEY *pkey = NULL;
	int keylen;
	char *buff_tmp;
//	int  sig_nid;
	u8  keybuff[512];

	pkey = X509_get_pubkey(x);
	if (pkey == NULL)
	{
		printf("cant find the public key %s %d\n", __FILE__, __LINE__);

		return -1;
	}
//	if(pkey->type == 6)
//	{
//		printf("it is rsaEncryption\n");
//	}
//	else
//	{
//		printf("unknown encryption\n");
//
//		//return -1;
//	}
//	sig_nid = OBJ_obj2nid(x->sig_alg->algorithm);
	memset(keybuff, 0, 512);
	buff_tmp = (char *)keybuff;
	keylen = i2d_PublicKey(pkey, (unsigned char **)&buff_tmp);
	if(keylen <= 0)
	{
		printf("The public key is invalid\n");

		return -1;
	}
	if(__sunxi_publickey_dipatch(pubkey, keybuff, keylen))
	{
		printf("get public failed\n");

		return -1;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
void sunxi_certif_mem_reset(void)
{
	reset_OBJ_nid2ln_reset();
	reset_CRYPTO_reset();
	reset_BIO_reset();
	reset_D2I_reset();
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_signature(X509 *x, u8 *sign)
{
	memcpy(sign, x->signature->data, x->signature->length);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_verify_itself(sunxi_certif_info_t *sunxi_certif, u8 *buf, u32 len)
{
	X509 *certif;
	int  ret;
	u8   hash_of_certif[256];
	u8   hash_of_sign[256];

	u8   sign_in_certif[256];
	u8   *p_sign_to_calc;
	u32  sign_src_len;

	//内存初始化
	sunxi_certif_mem_reset();
	//创建证书
	ret = sunxi_certif_create(&certif, buf, len);
	if(ret < 0)
	{
		printf("fail to create a certif\n");

		return -1;
	}
	//获取证书公钥
	ret = sunxi_certif_probe_pubkey(certif, &sunxi_certif->pubkey);
	if(ret)
	{
		printf("fail to probe the public key\n");

		return -1;
	}
	//获取证书签名
	ret = sunxi_certif_probe_signature(certif, sign_in_certif);
	if(ret)
	{
		printf("fail to probe the sign value\n");

		return -1;
	}
	//获取需要签名内容
	//计算sha256时，必须保证内存起始位置16字节对齐，这里采取了32字节对齐
	p_sign_to_calc = malloc(4096);		//证书中待签名内容肯定不超过4k
	//获取待签名内容
	memset(p_sign_to_calc, 0, 4096);
	sign_src_len = __certif_probe_signdata(p_sign_to_calc, 4096, buf, len);
	if(sign_src_len <= 0)
	{
		printf("certif_probe_signdata err\n");

		return -1;
	}
	//计算待签名内容的hash
	memset(hash_of_certif, 0, sizeof(hash_of_certif));
	ret = sunxi_sha_calc(hash_of_certif, sizeof(hash_of_certif), p_sign_to_calc, sign_src_len);
	if(ret)
	{
		printf("sunxi_sha_calc: calc sha256 with hardware err\n");

		return -1;
	}
	//计算证书中签名的rsa
	memset(hash_of_sign, 0, sizeof(hash_of_sign));
	ret = sunxi_rsa_calc(sunxi_certif->pubkey.n+1, sunxi_certif->pubkey.n_len-1,
	                     sunxi_certif->pubkey.e, sunxi_certif->pubkey.e_len,
	                     hash_of_sign,           sizeof(hash_of_sign),
	                     sign_in_certif,         sizeof(sign_in_certif));
	if(ret)
	{
		printf("sunxi_rsa_calc: calc rsa2048 with hardware err\n");

		return -1;
	}
//	printf(">>>>>>>>>>>>>>hash_of_certif\n");
//	ndump(hash_of_certif, 32);
//	printf("<<<<<<<<<<<<<<\n");
//	printf(">>>>>>>>>>>>>>hash_of_sign\n");
//	ndump(hash_of_sign, 32);
//	printf("<<<<<<<<<<<<<<\n");
	if(memcmp(hash_of_certif, hash_of_sign, 32))
	{
		printf("certif verify failed\n");

		return -1;
	}
	ret = sunxi_certif_probe_extension(certif, sunxi_certif);
	if(ret)
	{
		printf("sunxi_rsa_calc: probe extension failed\n");

		return -1;
	}

	sunxi_certif_free(certif);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_ext(sunxi_certif_info_t *sunxi_certif, u8 *buf, u32 len)
{
	X509 *certif;
	int  ret;
	//内存初始化
	sunxi_certif_mem_reset();
	//创建证书
	ret = sunxi_certif_create(&certif, buf, len);
	if(ret < 0)
	{
		printf("fail to create a certif\n");

		return -1;
	}
	ret = sunxi_certif_probe_extension(certif, sunxi_certif);
	if(ret)
	{
		printf("sunxi_rsa_calc: probe extension failed\n");

		return -1;
	}
	sunxi_certif_free(certif);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :  对于一个序列，按照高4+低4,合并成为一个新的字节，比如
*                     0x41(A) 0x31(1)  合并成为0xa1
*
************************************************************************************************************
*/
static int __sample_atoi(u8 ch, u8 *dst)
{
	u8 ret_c;

	if(isdigit(ch))
		ret_c = ch - '0';
	else if(isupper(ch))
		ret_c = ch - 'A' + 10;
	else if(islower(ch))
		ret_c = ch - 'a' + 10;
	else
	{
		printf("sample_atoi err: ch 0x%02x is not a digit or hex ch\n", ch);
		return -1;
	}
	*dst = ret_c;

	return 0;
}

int sunxi_bytes_merge(u8 *dst, u32 dst_len, u8 *src, uint src_len)
{
	int i=0, j;
	u8  c_h, c_l;

	if((src_len>>1) > dst_len)
	{
		printf("bytes merge failed, the dst buffer is too short\n");

		return -1;
	}
	if(src_len & 0x01)		//奇数
	{
		src_len --;
		if(__sample_atoi(src[i], &dst[0]))
		{
			return -1;
		}
		i++;
	}

	for(j=i;i<src_len;i+=2, j++)
	{
		c_h = src[i];
		c_l = src[i+1];

		if(__sample_atoi(src[i], &c_h))
		{
			return -1;
		}

		if(__sample_atoi(src[i+1], &c_l))
		{
			return -1;
		}
		dst[j] = (c_h << 4) | c_l;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_dump(sunxi_certif_info_t *sunxi_certif)
{
	return 0;
}


/////////////////X509_CINF_IT////////////////////////////////

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
//	ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(X509_CINF, serialNumber, ASN1_INTEGER),//
	ASN1_SIMPLE(X509_CINF, signature, X509_ALGOR),//
//	ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
//	ASN1_SIMPLE(X509_CINF, validity, X509_VAL),
//	ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
	ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),//
//	ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
//	ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)//
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

//IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)



static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	X509 *ret = (X509 *)*pval;
		
	switch(operation) {

		case ASN1_OP_NEW_POST:
		ret->valid=0;
		ret->name = NULL;
		ret->ex_flags = 0;
		ret->ex_pathlen = -1;
		ret->skid = NULL;
		ret->akid = NULL;
		ret->aux = NULL;
		CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
		break;

		case ASN1_OP_FREE_POST:
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);

		break;

	}

	return 1;

}

ASN1_SEQUENCE_ref(X509, x509_cb, CRYPTO_LOCK_X509) = {
	ASN1_SIMPLE(X509, cert_info, X509_CINF),
	ASN1_SIMPLE(X509, sig_alg, X509_ALGOR),
	ASN1_SIMPLE(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

IMPLEMENT_ASN1_FUNCTIONS(X509)


static int pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	if (operation == ASN1_OP_FREE_POST)
		{
		X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
		EVP_PKEY_free(pubkey->pkey);
		}
	return 1;
	}

/////////////////X509_PUBKEY_it//////////////////////////////

ASN1_SEQUENCE_cb(X509_PUBKEY, pubkey_cb) = {
	ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
	ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_cb(X509_PUBKEY, X509_PUBKEY)
	
IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY)




//////////EVP_PKEY_type//////////////////////ok

int EVP_PKEY_type(int type)
{

	switch (type)
		{
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA2:
		return(EVP_PKEY_RSA);
	case EVP_PKEY_DSA:
	case EVP_PKEY_DSA1:
	case EVP_PKEY_DSA2:
	case EVP_PKEY_DSA3:
	case EVP_PKEY_DSA4:
		return(EVP_PKEY_DSA);
	case EVP_PKEY_DH:
		return(EVP_PKEY_DH);
	case EVP_PKEY_EC:
		return(EVP_PKEY_EC);
	default:
		return(NID_undef);
		}
}

///////////////EVP_PKEY_new/////////////////////////////ok

EVP_PKEY *EVP_PKEY_new(void)
{
	EVP_PKEY *ret;

	ret=(EVP_PKEY *)OPENSSL_malloc(sizeof(EVP_PKEY));
	if (ret == NULL)
		{
		//EVPerr(EVP_F_EVP_PKEY_NEW,ERR_R_MALLOC_FAILURE);//samyang modify
		return(NULL);
		}
	ret->type=EVP_PKEY_NONE;
	ret->references=1;
	ret->pkey.ptr=NULL;
	ret->attributes=NULL;
	ret->save_parameters=1;
	return(ret);
}
///////////////X509_PUBKEY_get////////////////////////ok

EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key)
{

	EVP_PKEY *ret=NULL;
	long j;
	int type;
	const unsigned char *p;

	if (key == NULL) goto err;

	if (key->pkey != NULL)
		{
		CRYPTO_add(&key->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		return(key->pkey);
		}

	if (key->public_key == NULL) goto err;

	type=OBJ_obj2nid(key->algor->algorithm);
	if ((ret = EVP_PKEY_new()) == NULL)
		{
		//X509err(X509_F_X509_PUBKEY_GET, ERR_R_MALLOC_FAILURE);//samyang modify
		goto err;
		}
	ret->type = EVP_PKEY_type(type);



#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_ECDSA)
	//a=key->algor;
#endif

	p=key->public_key->data;
        j=key->public_key->length;
        if (!d2i_PublicKey(type, &ret, &p, (long)j))
		{
		//X509err(X509_F_X509_PUBKEY_GET, X509_R_ERR_ASN1_LIB);//samyang modify
		goto err;
		}

	key->pkey = ret;
	CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_EVP_PKEY);
	return(ret);
err:
	if (ret != NULL)
		EVP_PKEY_free(ret);
	return(NULL);

}

//////////////////X509_get_pubkey/////////////ok

EVP_PKEY *X509_get_pubkey(X509 *x)
{

	if ((x == NULL) || (x->cert_info == NULL))
		return(NULL);
	return(X509_PUBKEY_get(x->cert_info->key));
}



////////////EVP_PKEY_free/////////////////////ok

void EVP_PKEY_free(EVP_PKEY *x)
{
	int i;
	if (x == NULL) return;
	i=CRYPTO_add(&x->references,-1,CRYPTO_LOCK_EVP_PKEY);
	if (i > 0) return;

	}

/////////////////X509_EXTENSION_it///////////////////////////

ASN1_SEQUENCE(X509_EXTENSION) = {
	ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
	ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
	ASN1_SIMPLE(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION);
	
//////////////X509_ALGOR_it/////////////////////////////////

ASN1_SEQUENCE(X509_ALGOR) = {
	ASN1_SIMPLE(X509_ALGOR, algorithm, ASN1_OBJECT),
	ASN1_OPT(X509_ALGOR, parameter, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ALGOR)

#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)


///////////////////////asn1_get_enc_ptr//////////////////////ok

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	const ASN1_AUX *aux;
	
	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
	}

//////////////////asn1_enc_free//////////////////////////////ok

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		if (enc->enc)
			OPENSSL_free(enc->enc);
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}


///////////////asn1_enc_restore/////////////////////////////////////////ok

int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
							const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;
	
	enc = asn1_get_enc_ptr(pval, it);
	if (!enc || enc->modified)
		return 0;
	if (out)
		{
		memcpy(*out, enc->enc, enc->len);
		*out += enc->len;
		}
	if (len)
		*len = enc->len;
	return 1;
}


#define MSTRING		0
#define COMPAT		0

#define ASN1_MAX_STRING_NEST 5
#define asn1_tlc_clear(c)	if (c) (c)->valid = 0
int k=0;

void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine);

static int asn1_check_eoc(const unsigned char **in, long len);
static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
				char *inf, char *cst,
				const unsigned char **in, long len,
				int exptag, int expclass, char opt,
				ASN1_TLC *ctx);
static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
				const unsigned char **in, long len,
				const ASN1_ITEM *it,
				int tag, int aclass, char opt, ASN1_TLC *ctx);

static int asn1_template_ex_d2i(ASN1_VALUE **pval,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx);
static int asn1_template_noexp_d2i(ASN1_VALUE **val,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx);


///////////////////xx_it//////////////////////////////////////

IMPLEMENT_ASN1_TYPE(ASN1_INTEGER)
IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)
IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING)
IMPLEMENT_ASN1_TYPE(ASN1_ANY)
IMPLEMENT_ASN1_TYPE(ASN1_BIT_STRING)
IMPLEMENT_ASN1_TYPE(ASN1_IA5STRING)
IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)


IMPLEMENT_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)


///////////////////ASN1_item_d2i(i2d_rsapubliy)//////////////////////////////

ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval,
		const unsigned char **in, long len, const ASN1_ITEM *it)
	{
	ASN1_TLC c;
	ASN1_VALUE *ptmpval = NULL;
	if (!pval)
		pval = &ptmpval;
	c.valid = 0;
	if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)
		return *pval;
	return NULL;
	}

////////////////ASN1_item_ex_d2i/////////////////////////////

int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
			const ASN1_ITEM *it,
			int tag, int aclass, char opt, ASN1_TLC *ctx)
	{
	const ASN1_TEMPLATE *tt;
//	const ASN1_TEMPLATE *errtt = NULL;
//	const ASN1_COMPAT_FUNCS *cf;
//	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;//--YXY X509_aux
	ASN1_aux_cb *asn1_cb;
	const unsigned char *p = NULL, *q;
//	unsigned char *wp=NULL;	/* BIG FAT WARNING!  BREAKS CONST WHERE USED */
//	unsigned char imphack = 0;
//	unsigned char oclass;
	char seq_eoc, seq_nolen, cst, isopt;
	long tmplen;
	int i;
//	int otag;
	int ret = 0;
	int j=0,leng=0;//--YXY add
	const unsigned char cinf[][13]={"cert_info","version","serialNumber","signature","algorithm","parameter","isure","vald","suject","key","algor","algorithm","parameter","public_key","extensions"};
	//ASN1_VALUE **pchptr, *ptmpval;
	if (!pval)
		return 0;
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;
	else asn1_cb = 0;

	switch(it->itype)
		{
		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			{

			if ((tag != -1) || opt)
				{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);

				}
			return asn1_template_ex_d2i(pval, in, len,
					it->templates, opt, ctx);
		}
		return asn1_d2i_ex_primitive(pval, in, len, it,	//////////////INTERGER
						tag, aclass, opt, ctx);
		break;
#if	MSTRING
		case ASN1_ITYPE_MSTRING:
		p = *in;

		ret = asn1_check_tlen(NULL, &otag, &oclass, NULL, NULL,
						&p, len, -1, 0, 1, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			}


		if (oclass != V_ASN1_UNIVERSAL)
			{
				if (opt){
					return -1;
				}else{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_MSTRING_NOT_UNIVERSAL);
				}
			}

		return asn1_d2i_ex_primitive(pval, in, len,
						it, otag, 0, 0, ctx);

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		return ef->asn1_ex_d2i(pval, in, len,
						it, tag, aclass, opt, ctx);//??????
#endif
#if COMPAT
		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (opt)
			{
			int exptag;
			p = *in;
			if (tag == -1)
				exptag = it->utype;
			else exptag = tag;


			ret = asn1_check_tlen(NULL, NULL, NULL, NULL, NULL,
					&p, len, exptag, aclass, 1, ctx);
			if (!ret)
				{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				}
			if (ret == -1)
				return -1;
			}

		if (tag != -1)
			{
			wp = *(unsigned char **)in;
			imphack = *wp;
			if (p == NULL)
				{

				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				}
			*wp = (unsigned char)((*p & V_ASN1_CONSTRUCTED)
								| it->utype);
			}

		ptmpval = cf->asn1_d2i(pval, in, len);

		if (tag != -1)
			*wp = imphack;

		if (ptmpval){
			return 1;
		}else{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
		}


		case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it))
				goto auxerr;

		// Allocate structure
		if (!*pval && !ASN1_item_ex_new(pval, it))
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			}

		p = *in;
		for (i = 0, tt=it->templates; i < it->tcount; i++, tt++)
			{
			pchptr = asn1_get_field_ptr(pval, tt);
			ret = asn1_template_ex_d2i(pchptr, &p, len, tt, 1, ctx);

			if (ret == -1)
				continue;

			if (ret > 0)
				break;

			//errtt = tt;
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
						ERR_R_NESTED_ASN1_ERROR);

			}


		if (i == it->tcount)
			{

			if (opt)
				{
				//ASN1_item_ex_free(pval, it);
				return -1;
				}

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_NO_MATCHING_CHOICE_TYPE);

			}

		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it))
				goto auxerr;
		return 1;
#endif
		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		p = *in;
		tmplen = len;

		if (tag == -1)
			{
			tag = V_ASN1_SEQUENCE;//16,sequence
			aclass = V_ASN1_UNIVERSAL;
			}

		ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
					&p, len, tag, aclass, opt, ctx);//1
		if (!ret)
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			}
		else if (ret == -1)
			return -1;
		if (aux && (aux->flags & ASN1_AFLG_BROKEN))
			{
			len = tmplen - (p - *in);
			seq_nolen = 1;
			}

		else seq_nolen = seq_eoc;
		if (!cst)
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ASN1_R_SEQUENCE_NOT_CONSTRUCTED);
			}

		if (!*pval && !ASN1_item_ex_new(pval, it))//--YXY	根据it创建一个新的item
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ERR_R_NESTED_ASN1_ERROR);
			}

		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it))
				goto auxerr;

/**************************************************************************************/

		for (i = 0, tt = it->templates; i < it->tcount; i++, tt++)//x509_CINF_seq_tt
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			pseqval = asn1_get_field_ptr(pval, seqtt);//获得x509_CINF_seq_tt子类型的偏移量
		//	printf("%s\n",seqtt->field_name);
	/*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*/
			q=p;
			leng=len;
			for(j=0+k;j<17;j++){
				if(k>14){
					break;
				}

				if(!strcmp((const char *)cinf[j],seqtt->field_name)){
						k++;
						break;
				}else{
						asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
										&p, len, tag, aclass, opt, ctx);
						p=p+len;
						*in=p;
						len=leng-(p-q);
						k++;

				}

			}

	/*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*/
			if (!len)
				break;
			q = p;//证书的偏移地址###
			if (asn1_check_eoc(&p, len))//检查是否00开头
				{
				if (!seq_eoc)
					{

					ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
							ASN1_R_UNEXPECTED_EOC);
					}
				len -= p - q;
				seq_eoc = 0;
				q = p;
				break;
				}

			if (i == (it->tcount - 1))
				isopt = 0;//=0
			else isopt = (char)(seqtt->flags & ASN1_TFLG_OPTIONAL);//differrn

			ret = asn1_template_ex_d2i(pseqval, &p, len,		//这里开始对子template，进行转化
							seqtt, isopt, ctx);
			if (!ret)
				{
				//errtt = seqtt;
				}
			else if (ret == -1)
				{

				ASN1_template_free(pseqval, seqtt);
				continue;
				}
			/* Update length */
			len -= p - q;//###
			}

		if (seq_eoc && !asn1_check_eoc(&p, len))
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MISSING_EOC);

			}
		/* Check all data read */
		if (!seq_nolen && len)
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_SEQUENCE_LENGTH_MISMATCH);		///	while(1);

			}


		for (; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (seqtt->flags & ASN1_TFLG_OPTIONAL)
				{
				ASN1_VALUE **pseqval;
				pseqval = asn1_get_field_ptr(pval, seqtt);
				ASN1_template_free(pseqval, seqtt);
				}
			else
				{
				//errtt = seqtt;
				 ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
							ASN1_R_FIELD_MISSING);

				}
			}
		/* Save encoding */
		if (!asn1_enc_save(pval, *in, p - *in, it))
			goto auxerr;
		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it))
				goto auxerr;
		return 1;

		default:
		return 0;
		}
	auxerr:
	;ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_AUX_ERROR);
	return 0;
	}

////////////////////asn1_check_eoc//////////////////////////////

static int asn1_check_eoc(const unsigned char **in, long len)
	{
	const unsigned char *p;
	if (len < 2) return 0;
	p = *in;
	if (!p[0] && !p[1])
		{
		*in += 2;
		return 1;
		}
	return 0;
	}
/////////////asn1_check_tlen///////////////////////

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
				char *inf, char *cst,
				const unsigned char **in, long len,
				int exptag, int expclass, char opt,
				ASN1_TLC *ctx)
	{
	int i;
	int ptag, pclass;
	long plen;
	const unsigned char *p, *q;
	p = *in;
	q = p;

	if (ctx && ctx->valid)
		{
		i = ctx->ret;
		plen = ctx->plen;
		pclass = ctx->pclass;
		ptag = ctx->ptag;
		p += ctx->hdrlen;
		}
	else
		{
		i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);//start
		if (ctx)
			{
			ctx->ret = i;//i是指什么结构类型
			ctx->plen = plen;
			ctx->pclass = pclass;
			ctx->ptag = ptag;
			ctx->hdrlen = p - q;//这里用了多少个字节即0x30,0x82,0x04,0x52,4个
			ctx->valid = 1;

			if (!(i & 0x81) && ((plen + ctx->hdrlen) > len))
				{
				ASN1err(ASN1_F_ASN1_CHECK_TLEN,
							ASN1_R_TOO_LONG);
				asn1_tlc_clear(ctx);
				return 0;
				}
			}
		}

	if (i & 0x80)
		{
		ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_BAD_OBJECT_HEADER);
		asn1_tlc_clear(ctx);
		return 0;
		}
	if (exptag >= 0)
		{
		if ((exptag != ptag) || (expclass != pclass))//different,ptag=0,expclass=128
			{

			if (opt) return -1;
			asn1_tlc_clear(ctx);
			ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG);
		//	return 1;
			}

		asn1_tlc_clear(ctx);
		}

	if (i & 1)
		plen = len - (p - q);

	if (inf)
		*inf = i & 1;

	if (cst)
		*cst = i & V_ASN1_CONSTRUCTED;

	if (olen)
		*olen = plen;

	if (oclass)
		*oclass = pclass;

	if (otag)
		*otag = ptag;

	*in = p;//证书的偏移地址

	return 1;
	}

///////////asn1_d2i_ex_primitive///////////////

static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
				const unsigned char **in, long inlen,
				const ASN1_ITEM *it,
				int tag, int aclass, char opt, ASN1_TLC *ctx)
	{
	int ret = 0, utype;
	long plen;
	char cst, inf, free_cont = 0;
	const unsigned char *p;
	BUF_MEM buf;
	const unsigned char *cont = NULL;
	long len;
	if (!pval)
		{
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_ILLEGAL_NULL);
		return 0; /* Should never happen */
		}

	if (it->itype == ASN1_ITYPE_MSTRING)
		{
		utype = tag;
		tag = -1;
		}
	else
		utype = it->utype;

	if (utype == V_ASN1_ANY)
		{
		/* If type is ANY need to figure out type from tag */
		unsigned char oclass;
		if (tag >= 0)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ASN1_R_ILLEGAL_TAGGED_ANY);
			return 0;
			}
		if (opt)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ASN1_R_ILLEGAL_OPTIONAL_ANY);
			return 0;
			}
		p = *in;
		ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
					&p, inlen, -1, 0, 0, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		if (oclass != V_ASN1_UNIVERSAL)
			utype = V_ASN1_OTHER;
		}
	if (tag == -1)
		{
		tag = utype;
		aclass = V_ASN1_UNIVERSAL;
		}
	p = *in;
	/* Check header */
	ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,	//CHECK INTERGER
				&p, inlen, tag, aclass, opt, ctx);
	if (!ret)
		{
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_NESTED_ASN1_ERROR);
		return 0;
		}
	else if (ret == -1)
		return -1;
        ret = 0;

	if ((utype == V_ASN1_SEQUENCE)
		|| (utype == V_ASN1_SET) || (utype == V_ASN1_OTHER))
		{

		if (utype == V_ASN1_OTHER)
			{
			asn1_tlc_clear(ctx);
			}

		else if (!cst)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
				ASN1_R_TYPE_NOT_CONSTRUCTED);
			return 0;
			}

		cont = *in;
		if (inf)
			{
			len = p - cont;
			}
		else
			{
			len = p - cont + plen;
			p += plen;
			buf.data = NULL;
			}
		}
	else if (cst)
		{
		buf.length = 0;
		buf.max = 0;
		buf.data = NULL;
		len = buf.length;
		/* Append a final null to string */
		if (!BUF_MEM_grow_clean(&buf, len + 1))
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
						ERR_R_MALLOC_FAILURE);
			return 0;
			}
		buf.data[len] = 0;
		cont = (const unsigned char *)buf.data;
		free_cont = 1;
		}
	else
		{
		cont = p;		//INTERGER,0X42c5cc to 0x42c5cd
		len = plen;
		p += plen;		//这里是非sequece型，往后增加长度的
		}

	/* We now have content length and type: translate into a structure */
	if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))	//asn1 to interger
		goto err;

	*in = p;//转变之后地址会p=p+plen
	ret = 1;
	err:
	if (free_cont && buf.data) OPENSSL_free(buf.data);
	return ret;
	}

////////////asn1_template_noexp_d2i//////////////////////////

static int asn1_template_noexp_d2i(ASN1_VALUE **val,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx)
	{
	int flags, aclass;
	int ret;
	const unsigned char *p, *q;
	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;
	q = p;

	if (flags & ASN1_TFLG_SK_MASK)
		{

		int sktag, skaclass;
		char sk_eoc;

		if (flags & ASN1_TFLG_IMPTAG)
			{
			sktag = tt->tag;
			skaclass = aclass;
			}
		else
			{
			skaclass = V_ASN1_UNIVERSAL;
			if (flags & ASN1_TFLG_SET_OF)
				sktag = V_ASN1_SET;
			else
				sktag = V_ASN1_SEQUENCE;
			}

		ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
					&p, len, sktag, skaclass, opt, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		else if (ret == -1)
			return -1;
		if (!*val)
			*val = (ASN1_VALUE *)sk_new_null();
		else
			{
				;
			}

		if (!*val)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_MALLOC_FAILURE);
			goto err;
			}


		while(len > 0)
			{
			ASN1_VALUE *skfield;
			q = p;

			if (asn1_check_eoc(&p, len))
				{
				if (!sk_eoc)
					{
					ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
							ASN1_R_UNEXPECTED_EOC);
					goto err;
					}
				len -= p - q;
				sk_eoc = 0;
				break;
				}
			skfield = NULL;
			if (!ASN1_item_ex_d2i(&skfield, &p, len,
						ASN1_ITEM_ptr(tt->item),
						-1, 0, 0, ctx))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				goto err;
				}
			len -= p - q;
			if (!sk_push((STACK *)*val, (char *)skfield))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_MALLOC_FAILURE);
				goto err;
				}
			}
		if (sk_eoc)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ASN1_R_MISSING_EOC);
			goto err;
			}
		}
	else if (flags & ASN1_TFLG_IMPTAG)
		{
		/* IMPLICIT tagging */
		ret = ASN1_item_ex_d2i(val, &p, len,
			ASN1_ITEM_ptr(tt->item), tt->tag, aclass, opt, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			goto err;
			}
		else if (ret == -1)
			return -1;
		}
	else
		{

		ret = ASN1_item_ex_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),//子tempate,INTERGER#####
							-1, 0, opt, ctx);
		if (!ret)
			{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			//goto err;
			}
		else if (ret == -1)
			return -1;
		}

	*in = p;
	return 1;

	err:
	ASN1_template_free(val, tt);
	return 0;
	}

/////////////asn1_template_ex_d2i/////////////////////////

static int asn1_template_ex_d2i(ASN1_VALUE **val,
				const unsigned char **in, long inlen,
				const ASN1_TEMPLATE *tt, char opt,
							ASN1_TLC *ctx)
	{
	int flags, aclass;
	int ret;
	long len;
	const unsigned char *p, *q;
	char exp_eoc;
	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;

	/* Check if EXPLICIT tag expected */
	if (flags & ASN1_TFLG_EXPTAG)
		{
		char cst;

		ret = asn1_check_tlen(&len, NULL, NULL, &exp_eoc, &cst,//interger,
					&p, inlen, tt->tag, aclass, opt, ctx);
		q = p;
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		else if (ret == -1)
			return -1;
		if (!cst)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
			return 0;
			}
		/* We've found the field so it can't be OPTIONAL now */
		ret = asn1_template_noexp_d2i(val, &p, len, tt, 0, ctx);//len=3,p=0x42c5ca
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		/* We read the field in OK so update length */
		len -= p - q;//#####
		if (exp_eoc)
			{
			/* If NDEF we must have an EOC here */
			if (!asn1_check_eoc(&p, len))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
						ASN1_R_MISSING_EOC);
				goto err;
				}
			}
		else
			{

			if (len)
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ASN1_R_EXPLICIT_LENGTH_MISMATCH);
				goto err;
				}
			}
		}
		else
			return asn1_template_noexp_d2i(val, in, inlen,//###
								tt, opt, ctx);

	*in = p;
	return 1;

	err:
	ASN1_template_free(val, tt);
	return 0;
	}

////////////////////////asn1_ex_c2i///////////////////////////////////////

int asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
			int utype, char *free_cont, const ASN1_ITEM *it)
	{
	ASN1_VALUE **opval = NULL;
	ASN1_STRING *stmp;
	ASN1_TYPE *typ = NULL;
	int ret = 0;
	const ASN1_PRIMITIVE_FUNCS *pf;
	ASN1_INTEGER **tint;
	pf = it->funcs;

	if (pf && pf->prim_c2i)
		return pf->prim_c2i(pval, cont, len, utype, free_cont, it);
	/* If ANY type clear type and set pointer to internal value */
	if (it->utype == V_ASN1_ANY)
		{
		if (!*pval)
			{
			typ = ASN1_TYPE_new();
			if (typ == NULL)
				goto err;
			*pval = (ASN1_VALUE *)typ;
			}
		else
			typ = (ASN1_TYPE *)*pval;

		if (utype != typ->type)
			ASN1_TYPE_set(typ, utype, NULL);
		opval = pval;
		pval = &typ->value.asn1_value;
		}
	switch(utype)
		{
		case V_ASN1_OBJECT:
		if (!c2i_ASN1_OBJECT((ASN1_OBJECT **)pval, &cont, len))
			goto err;
		break;

		case V_ASN1_NULL:
		if (len)
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
						ASN1_R_NULL_IS_WRONG_LENGTH);
			goto err;
			}
		*pval = (ASN1_VALUE *)1;
		break;

		case V_ASN1_BOOLEAN:
		if (len != 1)
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
						ASN1_R_BOOLEAN_IS_WRONG_LENGTH);
			goto err;
			}
		else
			{
			ASN1_BOOLEAN *tbool;
			tbool = (ASN1_BOOLEAN *)pval;
			*tbool = *cont;
			}
		break;

		case V_ASN1_BIT_STRING:
		if (!c2i_ASN1_BIT_STRING((ASN1_BIT_STRING **)pval, &cont, len))
			goto err;
		break;

		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
		tint = (ASN1_INTEGER **)pval;
		if (!c2i_ASN1_INTEGER(tint, &cont, len))
			goto err;
		/* Fixup type to match the expected form */
		(*tint)->type = utype | ((*tint)->type & V_ASN1_NEG);
		break;

		case V_ASN1_OCTET_STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_OTHER:
		case V_ASN1_SET:
		case V_ASN1_SEQUENCE:
		default:
		if (utype == V_ASN1_BMPSTRING && (len & 1))
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
					ASN1_R_BMPSTRING_IS_WRONG_LENGTH);
			goto err;
			}
		if (utype == V_ASN1_UNIVERSALSTRING && (len & 3))
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
					ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH);
			goto err;
			}
		/* All based on ASN1_STRING and handled the same */
		if (!*pval)
			{
			stmp = ASN1_STRING_type_new(utype);
			if (!stmp)
				{
				ASN1err(ASN1_F_ASN1_EX_C2I,
							ERR_R_MALLOC_FAILURE);
				goto err;
				}
			*pval = (ASN1_VALUE *)stmp;
			}
		else
			{
			stmp = (ASN1_STRING *)*pval;
			stmp->type = utype;
			}
		/* If we've already allocated a buffer use it */
		if (*free_cont)
			{
			if (stmp->data)
				OPENSSL_free(stmp->data);
			stmp->data = (unsigned char *)cont; /* UGLY CAST! RL */
			stmp->length = len;
			*free_cont = 0;
			}
		else
			{
			if (!ASN1_STRING_set(stmp, cont, len))
				{
				ASN1err(ASN1_F_ASN1_EX_C2I,
							ERR_R_MALLOC_FAILURE);
				ASN1_STRING_free(stmp);
				*pval = NULL;
				goto err;
				}
			}
		break;
		}
	/* If ASN1_ANY and NULL type fix up value */
	if (typ && (utype == V_ASN1_NULL))
		 typ->value.ptr = NULL;

	ret = 1;
	err:
	if (!ret)
		{
		ASN1_TYPE_free(typ);
		if (opval)
			*opval = NULL;
		}
	return ret;
	}

//////////////ASN1_template_free////////////////////////////

void ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	int i;
	if (tt->flags & ASN1_TFLG_SK_MASK)
		{
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++)
			{
			ASN1_VALUE *vtmp;
			vtmp = sk_ASN1_VALUE_value(sk, i);
			asn1_item_combine_free(&vtmp, ASN1_ITEM_ptr(tt->item),
									0);
			}
		sk_ASN1_VALUE_free(sk);
		*pval = NULL;
		}
	else
		asn1_item_combine_free(pval, ASN1_ITEM_ptr(tt->item),
						tt->flags & ASN1_TFLG_COMBINE);
	}


void reset_D2I_reset(void)
{
	k=0;
}/* crypto/asn1/a_int.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



long ASN1_INTEGER_get(ASN1_INTEGER *a)
{
	int neg=0,i;
	long r=0;

	if (a == NULL) return(0L);
	i=a->type;
	if (i == V_ASN1_NEG_INTEGER)
		neg=1;
	else if (i != V_ASN1_INTEGER)
		return -1;

	if (a->length > (int)sizeof(long))
		{
		/* hmm... a bit ugly, return all ones */
		return -1;
		}
	if (a->data == NULL)
		return 0;

	for (i=0; i<a->length; i++)
		{
		r<<=8;
		r|=(unsigned char)a->data[i];
		}
	if (neg) r= -r;
	return(r);
}


int ASN1_STRING_mem(char *bp, const ASN1_STRING *v)
{
	int i,n;
	char *buf = bp;
	const char *p;

	if (v == NULL) return(0);
	n = 0;
	p=(const char *)v->data;
	for (i=0; i<v->length; i++)
		{
//		if ((p[i] > '~') || ((p[i] < ' ') &&
//			(p[i] != '\n') && (p[i] != '\r')))
//			buf[n++]='.';
//		else
			buf[n++]=p[i];
		}
	return(v->length);
}

ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp,
	     long len)
{
	ASN1_INTEGER *ret=NULL;
	const unsigned char *p, *pend;
	unsigned char *to,*s;
	int i;

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=M_ASN1_INTEGER_new()) == NULL) return(NULL);	//interger
		ret->type=V_ASN1_INTEGER;
		}
	else
		ret=(*a);

	p= *pp;	//0x42c5cc?
	pend = p + len;
	s=(unsigned char *)OPENSSL_malloc((int)len+1);
	if (s == NULL)
		{
		i=ERR_R_MALLOC_FAILURE;
		goto err;
		}
	to=s;
	if(!len) {

		ret->type=V_ASN1_INTEGER;
	} else if (*p & 0x80) /* a negative number */
		{
		ret->type=V_ASN1_NEG_INTEGER;
		if ((*p == 0xff) && (len != 1)) {
			p++;
			len--;
		}
		i = len;
		p += i - 1;
		to += i - 1;
		while((!*p) && i) {
			*(to--) = 0;
			i--;
			p--;
		}

		if(!i) {
			*s = 1;
			s[len] = 0;
			len++;
		} else {
			*(to--) = (*(p--) ^ 0xff) + 1;
			i--;
			for(;i > 0; i--) *(to--) = *(p--) ^ 0xff;
		}
	} else {
		ret->type=V_ASN1_INTEGER;
		if ((*p == 0) && (len != 1))
			{
			p++;
			len--;
			}
		memcpy(s,p,(int)len);
	}

	if (ret->data != NULL) OPENSSL_free(ret->data);
	ret->data=s;
	ret->length=(int)len;
	if (a != NULL) (*a)=ret;
	*pp=pend;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_INTEGER,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		M_ASN1_INTEGER_free(ret);
	return(NULL);
	}

///////////////////c2i_ASN1_BIT_STRING////////////////////////////////ok

ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
	const unsigned char **pp, long len)
	{
	ASN1_BIT_STRING *ret=NULL;
	const unsigned char *p;
	unsigned char *s;
	int i;

	if (len < 1)
		{
		i=ASN1_R_STRING_TOO_SHORT;
		goto err;
		}

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=M_ASN1_BIT_STRING_new()) == NULL) return(NULL);
		}
	else
		ret=(*a);

	p= *pp;
	i= *(p++);

	ret->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07); /* clear */
	ret->flags|=(ASN1_STRING_FLAG_BITS_LEFT|(i&0x07)); /* set */

	if (len-- > 1)
		{
		s=(unsigned char *)OPENSSL_malloc((int)len);
		if (s == NULL)
			{
			i=ERR_R_MALLOC_FAILURE;
			goto err;
			}
		memcpy(s,p,(int)len);
		s[len-1]&=(0xff<<i);
		p+=len;
		}
	else
		s=NULL;

	ret->length=(int)len;
	if (ret->data != NULL) OPENSSL_free(ret->data);
	ret->data=s;
	ret->type=V_ASN1_BIT_STRING;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_BIT_STRING,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		M_ASN1_BIT_STRING_free(ret);
	return(NULL);
	}

////////////////c2i_ASN1_OBJECT//////////////////////////ok

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
	     long len)
	{
	ASN1_OBJECT *ret=NULL;
	const unsigned char *p;
	int i;
	for (i = 0, p = *pp + 1; i < len - 1; i++, p++)
		{
		if (*p == 0x80 && (!i || !(p[-1] & 0x80)))
			{
			ASN1err(ASN1_F_C2I_ASN1_OBJECT,ASN1_R_INVALID_OBJECT_ENCODING);
			return NULL;
			}
		}


	if ((a == NULL) || ((*a) == NULL) ||
		!((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC))
		{
		if ((ret=ASN1_OBJECT_new()) == NULL) return(NULL);
		}
	else	ret=(*a);

	p= *pp;
	if ((ret->data == NULL) || (ret->length < len))
		{
		if (ret->data != NULL) OPENSSL_free(ret->data);
		ret->data=(unsigned char *)OPENSSL_malloc(len ? (int)len : 1);
		ret->flags|=ASN1_OBJECT_FLAG_DYNAMIC_DATA;
		if (ret->data == NULL)
			{ i=ERR_R_MALLOC_FAILURE; goto err; }
		}
	memcpy(ret->data,p,(int)len);
	ret->length=(int)len;
	ret->sn=NULL;
	ret->ln=NULL;
	/* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
	p+=len;

	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_OBJECT,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_OBJECT_free(ret);
	return(NULL);
	}

////////////////ASN1_OBJECT_new//////////////////////////ok

ASN1_OBJECT *ASN1_OBJECT_new(void)
	{
	ASN1_OBJECT *ret;
	ret=(ASN1_OBJECT *)OPENSSL_malloc(sizeof(ASN1_OBJECT));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_OBJECT_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->data=NULL;
	ret->nid=0;
	ret->sn=NULL;
	ret->ln=NULL;
	ret->flags=ASN1_OBJECT_FLAG_DYNAMIC;
	return(ret);
	}

//////////ASN1_OBJECT_free/////////////////////ok

void ASN1_OBJECT_free(ASN1_OBJECT *a)
	{

	if (a == NULL) return;
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS)
		{
#ifndef CONST_STRICT /* disable purely for compile-time strict const checking. Doing this on a "real" compile will cause memory leaks */
		if (a->sn != NULL) OPENSSL_free((void *)a->sn);
		if (a->ln != NULL) OPENSSL_free((void *)a->ln);
#endif
		a->sn=a->ln=NULL;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA)
		{
		if (a->data != NULL) OPENSSL_free(a->data);
		a->data=NULL;
		a->length=0;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
		OPENSSL_free(a);
	}



///////////////BIO_write////////////////////ok

int BIO_write(BIO *b, const void *in, int inl)
	{
	int i;
	long (*cb)(BIO *,int,const char *,int,long,long);

	if (b == NULL)
		return(0);

	cb=b->callback;
	if ((b->method == NULL) || (b->method->bwrite == NULL))
		{
		return(-2);
		}

	if ((cb != NULL) &&
		((i=(int)cb(b,BIO_CB_WRITE,in,inl,0L,1L)) <= 0))
			return(i);

	if (!b->init)
		{
		return(-2);
		}

	i=b->method->bwrite(b,in,inl);

	if (i > 0) b->num_write+=(unsigned long)i;

	if (cb != NULL)
		i=(int)cb(b,BIO_CB_WRITE|BIO_CB_RETURN,in,inl,
			0L,(long)i);
	return(i);
	}


///////////i2a_ASN1_INTEGER////////////////////ok

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a)
	{
	int i,n=0;
	static const char *h="0123456789ABCDEF";
	char buf[2];

	if (a == NULL) return(0);

	if (a->type & V_ASN1_NEG)
		{
		if (BIO_write(bp, "-", 1) != 1) goto err;
		n = 1;
		}

	if (a->length == 0)
		{
		if (BIO_write(bp,"00",2) != 2) goto err;
		n += 2;
		}
	else
		{
		for (i=0; i<a->length; i++)
			{
			if ((i != 0) && (i%35 == 0))
				{
				if (BIO_write(bp,"\\\n",2) != 2) goto err;
				n+=2;
				}
			buf[0]=h[((unsigned char)a->data[i]>>4)&0x0f];
			buf[1]=h[((unsigned char)a->data[i]   )&0x0f];
			if (BIO_write(bp,buf,2) != 2) goto err;
			n+=2;
			}
		}
	return(n);
err:
	return(-1);
	}
#ifndef OPENSSL_NO_RSA
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


////////////////////////////////////////////////////ok

ASN1_STRING *ASN1_STRING_type_new(int type)
{
	ASN1_STRING *ret;
	ret=(ASN1_STRING *)OPENSSL_malloc(sizeof(ASN1_STRING));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_STRING_TYPE_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->type=type;
	ret->data=NULL;
	ret->flags=0;
	return(ret);
}
///////////////ASN1_STRING_set/////////////////////////////////ok


int ASN1_STRING_set(ASN1_STRING *str, const void *_data, int len)
	{
	unsigned char *c;
	const char *data=_data;
	if (len < 0)
		{
		if (data == NULL)
			return(0);
		else
			len=strlen(data);
		}
	if ((str->length < len) || (str->data == NULL))
		{
		c=str->data;
		if (c == NULL)
			str->data=OPENSSL_malloc(len+1);
		else
			str->data=OPENSSL_realloc(c,len+1);

		if (str->data == NULL)
			{
			ASN1err(ASN1_F_ASN1_STRING_SET,ERR_R_MALLOC_FAILURE);
			str->data=c;
			return(0);
			}
		}
	str->length=len;
	if (data != NULL)
		{
		memcpy(str->data,data,len);
		/* an allowance for strings :-) */
		str->data[len]='\0';
		}
	return(1);
	}

//////////////ASN1_STRING_free////////////////////////

void ASN1_STRING_free(ASN1_STRING *a)
	{

	if (a == NULL) return;
	if (a->data != NULL) OPENSSL_free(a->data);
	OPENSSL_free(a);
	}


///////////X509_get_serialNumber///////////////////ok

ASN1_INTEGER *X509_get_serialNumber(X509 *a)
	{
	return(a->cert_info->serialNumber);
	}


/////////////////d2i_PublicKey////////////////////////////////////ok

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
	     long length)
	{
	EVP_PKEY *ret;
	
	if ((a == NULL) || (*a == NULL))
		{
		if ((ret=EVP_PKEY_new()) == NULL)
			{
			ASN1err(ASN1_F_D2I_PUBLICKEY,ERR_R_EVP_LIB);
			return(NULL);
			}
		}
	else	ret= *a;

	ret->save_type=type;
	ret->type=EVP_PKEY_type(type);
	switch (ret->type)
		{
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		if ((ret->pkey.rsa=d2i_RSAPublicKey(NULL,
			(const unsigned char **)pp,length)) == NULL) /* TMP UGLY CAST */
			{
			ASN1err(ASN1_F_D2I_PUBLICKEY,ERR_R_ASN1_LIB);
			goto err;
			}
		break;
#endif

	default:
		ASN1err(ASN1_F_D2I_PUBLICKEY,ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
		goto err;
		/* break; */
		}
	if (a != NULL) (*a)=ret;
	return(ret);
err:
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
			EVP_PKEY_free(ret);
	return(NULL);
	}




static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,int combine);
static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);


/////////////////ASN1_item_ex_new/////////////////////////ok

int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	
	return asn1_item_ex_combine_new(pval, it, 0);
}

////////////ASN1_item_new//////////////////////////////////ok

ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)
	{
	ASN1_VALUE *ret = NULL;
	
	if (ASN1_item_ex_new(&ret, it) > 0)
		return ret;
	return NULL;
	}
///////////////asn1_item_ex_combine_new//////////////////////////ok

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,
								int combine)
	{
	const ASN1_TEMPLATE *tt = NULL;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	ASN1_VALUE **pseqval;
	int i;
	
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;//x509_cb
	else
		asn1_cb = 0;

	if (!combine) *pval = NULL;

	switch(it->itype)
		{

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_new)
			{
			if (!ef->asn1_ex_new(pval, it))
				goto memerr;
			}
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (cf && cf->asn1_new) {
			*pval = cf->asn1_new();
			if (!*pval)
				goto memerr;
		}
		break;

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			{
			if (!ASN1_template_new(pval, it->templates))
				goto memerr;
			}
		else if (!ASN1_primitive_new(pval, it))
				goto memerr;
		break;

		case ASN1_ITYPE_MSTRING:
		if (!ASN1_primitive_new(pval, it))
				goto memerr;
		break;

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it);
			if (!i)
				goto auxerr;
			if (i==2)
				{

				return 1;
				}
			}
		if (!combine)
			{
			*pval = OPENSSL_malloc(it->size);
			if (!*pval)
				goto memerr;
			memset(*pval, 0, it->size);
			}
		//asn1_set_choice_selector(pval, -1, it);//samyang delete
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
		break;

		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it);
			if (!i)
				goto auxerr;
			if (i==2)
				{
				return 1;
				}
			}
		if (!combine)
			{
			*pval = OPENSSL_malloc(it->size);//接收结构体的地址
			if (!*pval)
				goto memerr;
			memset(*pval, 0, it->size);
			//asn1_do_lock(pval, 0, it);
			asn1_enc_init(pval, it);//?
			}
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)//x509_seq_tt[]
			{
				pseqval = asn1_get_field_ptr(pval, tt);//返回"接收结构体"中的偏移地址	
			
				if (!ASN1_template_new(pseqval, tt))	//创建子item,根据x509_seq_tt[]中的xx_it
					goto memerr;
			
			}
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
	
		break;
	}

	return 1;

	memerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ERR_R_MALLOC_FAILURE);
	return 0;

	auxerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ASN1_R_AUX_ERROR);
	return 0;

	}

///////////////////ASN1_template_new///////////////////////////////ok

int ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);//
	
	int ret;

	if (tt->flags & ASN1_TFLG_OPTIONAL)
		{
		asn1_template_clear(pval, tt);
		return 1;
		}

	if (tt->flags & ASN1_TFLG_ADB_MASK)
		{
		*pval = NULL;
		return 1;
		}
	
	if (tt->flags & ASN1_TFLG_SK_MASK)
		{
		STACK_OF(ASN1_VALUE) *skval;
		skval = sk_ASN1_VALUE_new_null();
		if (!skval)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
			ret = 0;
			goto done;
			}
		*pval = (ASN1_VALUE *)skval;
		ret = 1;
		goto done;
		}
	
	ret = asn1_item_ex_combine_new(pval, it, tt->flags & ASN1_TFLG_COMBINE);//判断子item结构的类型，长度
	done:
	return ret;
	}

///////////////asn1_template_clear///////////////////////////ok

static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	
	if (tt->flags & (ASN1_TFLG_ADB_MASK|ASN1_TFLG_SK_MASK)) 
		*pval = NULL;
	else
		asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
	}


////////////////ASN1_primitive_new///////////////////////ok

int ASN1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_TYPE *typ;
	int utype;
	
	if (it && it->funcs)
		{
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_new)
			return pf->prim_new(pval, it);
		}

	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = -1;
	else
		utype = it->utype;
	switch(utype)
		{
		case V_ASN1_OBJECT:
		*pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
		return 1;

		case V_ASN1_BOOLEAN:
		if (it)
			*(ASN1_BOOLEAN *)pval = it->size;
		else
			*(ASN1_BOOLEAN *)pval = -1;
		return 1;

		case V_ASN1_NULL:
		*pval = (ASN1_VALUE *)1;
		return 1;

		case V_ASN1_ANY:
		typ = OPENSSL_malloc(sizeof(ASN1_TYPE));
		if (!typ)
			return 0;
		typ->value.ptr = NULL;
		typ->type = -1;
		*pval = (ASN1_VALUE *)typ;
		break;

		default:
		*pval = (ASN1_VALUE *)ASN1_STRING_type_new(utype);
		break;
		}
	if (*pval)
		return 1;
	return 0;
	}


///////////////asn1_item_clear///////////////////////////////ok

static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	const ASN1_EXTERN_FUNCS *ef;
	
	switch(it->itype)
		{

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_clear)
			ef->asn1_ex_clear(pval, it);
		else *pval = NULL;
		break;


		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			asn1_template_clear(pval, it->templates);
		else
			asn1_primitive_clear(pval, it);
		break;

		case ASN1_ITYPE_MSTRING:
		asn1_primitive_clear(pval, it);
		break;

		case ASN1_ITYPE_COMPAT:
		case ASN1_ITYPE_CHOICE:
		case ASN1_ITYPE_SEQUENCE:
		case ASN1_ITYPE_NDEF_SEQUENCE:
		*pval = NULL;
		break;
		}
	}

////////////asn1_primitive_clear///////////////////////ok

void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	int utype;
	
	if (it && it->funcs)
		{
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_clear)
			pf->prim_clear(pval, it);
		else
			*pval = NULL;
		return;
		}
	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = -1;
	else
		utype = it->utype;
	if (utype == V_ASN1_BOOLEAN)
		*(ASN1_BOOLEAN *)pval = it->size;
	else *pval = NULL;
	}





static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
					const ASN1_ITEM *it,
					int tag, int aclass);
static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
					const ASN1_TEMPLATE *tt,
					int tag, int aclass);
static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
					const ASN1_ITEM *it, int flags);


//////////////////ASN1_item_i2d//////////////////////////////////////////ok

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
	{

	return asn1_item_flags_i2d(val, out, it, 0);
	}

/////////////////asn1_item_flags_i2d/////////////////////////////////////////ok

static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
					const ASN1_ITEM *it, int flags)
	{
	/*if (out && !*out)
		{
		unsigned char *p, *buf;
		int len;
		len = ASN1_item_ex_i2d(&val, NULL, it, -1, flags);
		if (len <= 0)
			return len;
		buf = OPENSSL_malloc(len);
		if (!buf)
			return -1;
		p = buf;
		ASN1_item_ex_i2d(&val, &p, it, -1, flags);
		*out = buf;
		return len;
		}
*/
	return ASN1_item_ex_i2d(&val, out, it, -1, flags);
	}

///////////////// ASN1_item_ex_i2d//////////////////////////////////ok

int ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
			const ASN1_ITEM *it, int tag, int aclass)
	{
	const ASN1_TEMPLATE *tt = NULL;
	unsigned char *p = NULL;
	int i, seqcontlen, seqlen, ndef = 1;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb = 0;

	if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
		return 0;

	if (aux && aux->asn1_cb)
		 asn1_cb = aux->asn1_cb;

	switch(it->itype)
		{

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			return asn1_template_ex_i2d(pval, out, it->templates,
								tag, aclass);
		return asn1_i2d_ex_primitive(pval, out, it, tag, aclass);
		break;

		case ASN1_ITYPE_MSTRING:
		return asn1_i2d_ex_primitive(pval, out, it, -1, aclass);

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it))
				return 0;


		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it))
				return 0;
		break;

		case ASN1_ITYPE_EXTERN:
		/* If new style i2d it does all the work */
		ef = it->funcs;
		return ef->asn1_ex_i2d(pval, out, it, tag, aclass);

		case ASN1_ITYPE_COMPAT:
		/* old style hackery... */
		cf = it->funcs;
		if (out)
			p = *out;
		i = cf->asn1_i2d(*pval, out);

		if (out && (tag != -1))
			*p = aclass | tag | (*p & V_ASN1_CONSTRUCTED);
		return i;

		case ASN1_ITYPE_NDEF_SEQUENCE:

		if (aclass & ASN1_TFLG_NDEF) ndef = 2;


		case ASN1_ITYPE_SEQUENCE:
		i = asn1_enc_restore(&seqcontlen, out, pval, it);
		/* An error occurred */
		if (i < 0)
			return 0;
		/* We have a valid cached encoding... */
		if (i > 0)
			return seqcontlen;
		/* Otherwise carry on */
		seqcontlen = 0;
		/* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
		if (tag == -1)
			{
			tag = V_ASN1_SEQUENCE;
			/* Retain any other flags in aclass */
			aclass = (aclass & ~ASN1_TFLG_TAG_CLASS)
					| V_ASN1_UNIVERSAL;
			}
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it))
				return 0;
		/* First work out sequence content length */
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			/* FIXME: check for errors in enhanced version */
			seqcontlen += asn1_template_ex_i2d(pseqval, NULL, seqtt,
								-1, aclass);
			}

		seqlen = ASN1_object_size(ndef, seqcontlen, tag);
		if (!out)
			return seqlen;

		ASN1_put_object(out, ndef, seqcontlen, tag, aclass);
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);

			asn1_template_ex_i2d(pseqval, out, seqtt, -1, aclass);
			}
		//if (ndef == 2)
		//	ASN1_put_eoc(out);//samyang delete
		if (asn1_cb  && !asn1_cb(ASN1_OP_I2D_POST, pval, it))
				return 0;
		return seqlen;

		default:
		return 0;

		}
	return 0;
	}


/////////////////asn1_template_ex_i2d/////////////////////////////////////ok

static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
				const ASN1_TEMPLATE *tt, int tag, int iclass)
	{
	int i, ret, flags, ttag, tclass, ndef;
	flags = tt->flags;

	if (flags & ASN1_TFLG_TAG_MASK)
		{
		if (tag != -1)
			return -1;
		ttag = tt->tag;
		tclass = flags & ASN1_TFLG_TAG_CLASS;
		}
	else if (tag != -1)
		{
		ttag = tag;
		tclass = iclass & ASN1_TFLG_TAG_CLASS;
		}
	else
		{
		ttag = -1;
		tclass = 0;
		}

	iclass &= ~ASN1_TFLG_TAG_CLASS;

	if ((flags & ASN1_TFLG_NDEF) && (iclass & ASN1_TFLG_NDEF))
		ndef = 2;
	else ndef = 1;

	if (flags & ASN1_TFLG_SK_MASK)
		{
		/* SET OF, SEQUENCE OF */
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		int isset, sktag, skaclass;
		int skcontlen, sklen;
		ASN1_VALUE *skitem;

		if (!*pval)
			return 0;

		if (flags & ASN1_TFLG_SET_OF)
			{
			isset = 1;
			/* 2 means we reorder */
			if (flags & ASN1_TFLG_SEQUENCE_OF)
				isset = 2;
			}
		else isset = 0;
		if ((ttag != -1) && !(flags & ASN1_TFLG_EXPTAG))
			{
			sktag = ttag;
			skaclass = tclass;
			}
		else
			{
			skaclass = V_ASN1_UNIVERSAL;
			if (isset)
				sktag = V_ASN1_SET;
			else sktag = V_ASN1_SEQUENCE;
			}

		/* Determine total length of items */
		skcontlen = 0;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++)
			{
			skitem = sk_ASN1_VALUE_value(sk, i);
			skcontlen += ASN1_item_ex_i2d(&skitem, NULL,
						ASN1_ITEM_ptr(tt->item),
							-1, iclass);
			}
		sklen = ASN1_object_size(ndef, skcontlen, sktag);
		/* If EXPLICIT need length of surrounding tag */
		if (flags & ASN1_TFLG_EXPTAG)
			ret = ASN1_object_size(ndef, sklen, ttag);
		else ret = sklen;

		if (!out)
			return ret;


		if (flags & ASN1_TFLG_EXPTAG)
			ASN1_put_object(out, ndef, sklen, ttag, tclass);

		ASN1_put_object(out, ndef, skcontlen, sktag, skaclass);



		return ret;
		}

	if (flags & ASN1_TFLG_EXPTAG)
		{

		i = ASN1_item_ex_i2d(pval, NULL, ASN1_ITEM_ptr(tt->item),
								-1, iclass);
		if (!i)
			return 0;

		ret = ASN1_object_size(ndef, i, ttag);
		if (out)
			{

			ASN1_put_object(out, ndef, i, ttag, tclass);
			ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
								-1, iclass);
			//if (ndef == 2)
				//ASN1_put_eoc(out);//samyang delete
			}
		return ret;
		}

	return ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
						ttag, tclass | iclass);

}


////////////////////asn1_i2d_ex_primitive/////////////////////////////////ok

static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
				const ASN1_ITEM *it, int tag, int aclass)
	{
	int len;
	int utype;
	int usetag;
	int ndef = 0;

	utype = it->utype;

	len = asn1_ex_i2c(pval, NULL, &utype, it);


	if ((utype == V_ASN1_SEQUENCE) || (utype == V_ASN1_SET) ||
	   (utype == V_ASN1_OTHER))
		usetag = 0;
	else usetag = 1;

	if (len == -1)
		return 0;


	if (len == -2)
		{
		ndef = 2;
		len = 0;
		}


	if (tag == -1) tag = utype;


	if (out)
		{
		if (usetag)
			ASN1_put_object(out, ndef, len, tag, aclass);
		asn1_ex_i2c(pval, *out, &utype, it);
		//if (ndef)
			//ASN1_put_eoc(out);//samyang delete
		//else
			*out += len;
		}

	if (usetag)
		return ASN1_object_size(ndef, len, tag);
	return len;
	}

////////////////asn1_ex_i2c//////////////////////////////////ok

int asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cout, int *putype,
				const ASN1_ITEM *it)
	{
	ASN1_BOOLEAN *tbool = NULL;
	ASN1_STRING *strtmp;
	ASN1_OBJECT *otmp;
	int utype;
	unsigned char *cont=NULL, c;
	int len=0;
	const ASN1_PRIMITIVE_FUNCS *pf;
	pf = it->funcs;

	if (pf && pf->prim_i2c)
		return pf->prim_i2c(pval, cout, putype, it);

	if ((it->itype != ASN1_ITYPE_PRIMITIVE)
		|| (it->utype != V_ASN1_BOOLEAN))
		{
		if (!*pval) return -1;
		}

	if (it->itype == ASN1_ITYPE_MSTRING)
		{

		strtmp = (ASN1_STRING *)*pval;
		utype = strtmp->type;
		*putype = utype;
		}
	else if (it->utype == V_ASN1_ANY)
		{
		ASN1_TYPE *typ;
		typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		*putype = utype;
		pval = &typ->value.asn1_value;
		}
	else utype = *putype;

	switch(utype)
		{
		case V_ASN1_OBJECT:
		otmp = (ASN1_OBJECT *)*pval;
		cont = otmp->data;
		len = otmp->length;
		break;

		case V_ASN1_NULL:
		cont = NULL;
		len = 0;
		break;

		case V_ASN1_BOOLEAN:
		tbool = (ASN1_BOOLEAN *)pval;
		if (*tbool == -1)
			return -1;
		if (it->utype != V_ASN1_ANY)
			{
			if (*tbool && (it->size > 0))
				return -1;
			if (!*tbool && !it->size)
				return -1;
			}
		c = (unsigned char)*tbool;
		cont = &c;
		len = 1;
		break;

		case V_ASN1_BIT_STRING:
			;

		break;

		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
					;
		//return i2c_ASN1_INTEGER((ASN1_INTEGER *)*pval,
							//cout ? &cout : NULL);
		break;

		case V_ASN1_OCTET_STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_SEQUENCE:
		case V_ASN1_SET:
		default:
		/* All based on ASN1_STRING and handled the same */
		strtmp = (ASN1_STRING *)*pval;
		/* Special handling for NDEF */
		if ((it->size == ASN1_TFLG_NDEF)
			&& (strtmp->flags & ASN1_STRING_FLAG_NDEF))
			{
			if (cout)
				{
				strtmp->data = cout;
				strtmp->length = 0;
				}
			/* Special return code */
			return -2;
			}
		cont = strtmp->data;
		len = strtmp->length;

		break;

		}
	if (cout && len)
		memcpy(cout, cont, len);
	return len;
	}

#undef MIN_NODES
#define MIN_NODES	4

/////////////////////sk_new_null//////////////////////////////////ok

STACK *sk_new_null(void)
{
	
	return sk_new((int (*)(const char * const *, const char * const *))0);
}
/////////////////sk_new//////////////////////////////////ok

STACK *sk_new(int (*c)(const char * const *, const char * const *))
{
	STACK *ret;
	int i;
	
	if ((ret=(STACK *)OPENSSL_malloc(sizeof(STACK))) == NULL)
		goto err;
	if ((ret->data=(char **)OPENSSL_malloc(sizeof(char *)*MIN_NODES)) == NULL)
		goto err;
	for (i=0; i<MIN_NODES; i++)
		ret->data[i]=NULL;
	ret->comp=c;
	ret->num_alloc=MIN_NODES;
	ret->num=0;
	ret->sorted=0;
	return(ret);
err:
	if(ret)
		OPENSSL_free(ret);
	return(NULL);
}

///////////////sk_insert////////////////////////////ok

int sk_insert(STACK *st, char *data, int loc)
	{
	char **s;

	if(st == NULL) return 0;
	if (st->num_alloc <= st->num+1)
		{
		s=(char **)OPENSSL_realloc((char *)st->data,
			(unsigned int)sizeof(char *)*st->num_alloc*2);
		if (s == NULL)
			return(0);
		st->data=s;
		st->num_alloc*=2;
		}
	if ((loc >= (int)st->num) || (loc < 0))
		st->data[st->num]=data;
	else
		{
		int i;
		char **f,**t;

		f=(char **)st->data;
		t=(char **)&(st->data[1]);
		for (i=st->num; i>=loc; i--)
			t[i]=f[i];

		st->data[loc]=data;
		}
	st->num++;
	st->sorted=0;
	return(st->num);
	}

////////////sk_push//////////////////////////ok

int sk_push(STACK *st, char *data)
	{
		
	return(sk_insert(st,data,st->num));
	}

//////////////sk_free////////////////////////ok

void sk_free(STACK *st)
	{
		
	if (st == NULL) return;
	if (st->data != NULL) OPENSSL_free(st->data);
	OPENSSL_free(st);
	}

/////////////sk_pop_free////////////////////////ok

void sk_pop_free(STACK *st, void (*func)(void *))
	{
	/*int i;
	if (st == NULL) return;
	for (i=0; i<st->num; i++)
		if (st->data[i] != NULL)
			func(st->data[i]);
	sk_free(st);*/
	}


static void asn1_put_length(unsigned char **pp, int length);
static int asn1_get_length(const unsigned char **pp,int *inf,long *rl,int max);

/////////////ASN1_put_object/////////////////////////////////////////ok

void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
	     int xclass)
{
	unsigned char *p= *pp;
	int i, ttag;

	i=(constructed)?V_ASN1_CONSTRUCTED:0;
	i|=(xclass&V_ASN1_PRIVATE);
	if (tag < 31)
		*(p++)=i|(tag&V_ASN1_PRIMITIVE_TAG);
	else
		{
		*(p++)=i|V_ASN1_PRIMITIVE_TAG;
		for(i = 0, ttag = tag; ttag > 0; i++) ttag >>=7;
		ttag = i;
		while(i-- > 0)
			{
			p[i] = tag & 0x7f;
			if(i != (ttag - 1)) p[i] |= 0x80;
			tag >>= 7;
			}
		p += ttag;
		}
	if (constructed == 2)
		*(p++)=0x80;
	else
		asn1_put_length(&p,length);
	*pp=p;
}

//////////////asn1_put_length///////////////////////////////////////ok

static void asn1_put_length(unsigned char **pp, int length)
	{
	unsigned char *p= *pp;
	int i,l;

	if (length <= 127)
		*(p++)=(unsigned char)length;
	else
		{
		l=length;
		for (i=0; l > 0; i++)
			l>>=8;
		*(p++)=i|0x80;
		l=i;
		while (i-- > 0)
			{
			p[i]=length&0xff;
			length>>=8;
			}
		p+=l;
		}
	*pp=p;
	}


////////////////ASN1_object_size//////////////////////////////////ok

int ASN1_object_size(int constructed, int length, int tag)
	{
	int ret;

	ret=length;
	ret++;
	if (tag >= 31)
		{
		while (tag > 0)
			{
			tag>>=7;
			ret++;
			}
		}
	if (constructed == 2)
		return ret + 3;
	ret++;
	if (length > 127)
		{
		while (length > 0)
			{
			length>>=8;
			ret++;
			}
		}
	return(ret);
	}

/////////ASN1_get_object//////////////////////////////////////////////ok
//	--YXY	获得证书是什么结构类型，例如sequence
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax)
	{
	int i,ret;
	long l;
	const unsigned char *p= *pp;
	int tag,xclass,inf;
	long max=omax;

	if (!max) goto err;
	ret=(*p&V_ASN1_CONSTRUCTED);//0x20
	xclass=(*p&V_ASN1_PRIVATE);//0xc0
	i= *p&V_ASN1_PRIMITIVE_TAG;//0x1f
	if (i == V_ASN1_PRIMITIVE_TAG)
		{		/* high-tag */
		p++;
		if (--max == 0) goto err;
		l=0;
		while (*p&0x80)
			{
			l<<=7L;
			l|= *(p++)&0x7f;
			if (--max == 0) goto err;
			if (l > (INT_MAX >> 7L)) goto err;
			}
		l<<=7L;
		l|= *(p++)&0x7f;
		tag=(int)l;
		if (--max == 0) goto err;
		}
	else
		{
		tag=i;//确定是什么类型,即universal的值
		p++;
		if (--max == 0) goto err;
		}
	*ptag=tag;
	*pclass=xclass;
	if (!asn1_get_length(&p,&inf,plength,(int)max)) goto err;//intenger

	if (*plength > (omax - (p - *pp)))//判断证书剩余的大小
		{
		ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_TOO_LONG);
		ret|=0x80;
		}
	*pp=p;//证书的偏移地址
	return(ret|inf);
err:
	ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_HEADER_TOO_LONG);
	return(0x80);
	}

/////////////////asn1_get_length//////////////////////////////////////////ok
//--YXY	获取证书的结构中的长度
static int asn1_get_length(const unsigned char **pp, int *inf, long *rl, int max)
	{
	const unsigned char *p= *pp;
	unsigned long ret=0;
	unsigned int i;

	if (max-- < 1) return(0);
	if (*p == 0x80)
		{
		*inf=1;
		ret=0;
		p++;
		}
	else
		{
		*inf=0;
		i= *p&0x7f;//获得多少个字节0x82，即2个字节
		if (*(p++) & 0x80)//获得长度0x04,0x51,即1105
			{
			if (i > sizeof(long))
				return 0;
			if (max-- == 0) return(0);
			while (i-- > 0)
				{
				ret<<=8L;
				ret|= *(p++);
				if (max-- == 0) return(0);
				}
			}
		else
			ret=i;
		}
	if (ret > LONG_MAX)
		return 0;
	*pp=p;//返回证书的偏移地址
	*rl=(long)ret;//返回长度值



	return(1);
	}



#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

////////////////asn1_get_field_ptr///////////////////////////////////ok由tt中的offset计算要读取数据在"接收结构体"里面的偏移

ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	ASN1_VALUE **pvaltmp;

	if (tt->flags & ASN1_TFLG_COMBINE)
		return pval;
	pvaltmp = offset2ptr(*pval, tt->offset);

	return pvaltmp;
}


////////////////asn1_get_enc_ptr/////////////////////////ok

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	const ASN1_AUX *aux;

	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
}
////////////////asn1_enc_save//////////////////////////////ok

int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
							 const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (!enc)
		return 1;

	if (enc->enc)
		OPENSSL_free(enc->enc);
	enc->enc = OPENSSL_malloc(inlen);
	if (!enc->enc)
		return 0;
	memcpy(enc->enc, in, inlen);
	enc->len = inlen;
	enc->modified = 0;

	return 1;
	}

////////////////asn1_do_adb//////////////////////////////////////ok

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,int nullerr)
	{
	const ASN1_ADB *adb;
	const ASN1_ADB_TABLE *atbl;
	long selector = 0;
	ASN1_VALUE **sfld;
	int i;

	if (!(tt->flags & ASN1_TFLG_ADB_MASK))
		return tt;//??

	adb = ASN1_ADB_ptr(tt->item);

	sfld = offset2ptr(*pval, adb->offset);

	if (!sfld)
		{
		if (!adb->null_tt)
			goto err;
		return adb->null_tt;
		}

	if (tt->flags & ASN1_TFLG_ADB_OID)
		selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
	else
		//selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);
		;


	for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
		if (atbl->value == selector)
			return &atbl->tt;


	if (!adb->default_tt)
		goto err;
	return adb->default_tt;

	err:
	if (nullerr)
		ASN1err(ASN1_F_ASN1_DO_ADB,
			ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
	return NULL;
	}



///////////////asn1_enc_init////////////////////////////////////ok

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}


int ASN1_STRING_print(BIO *bp, ASN1_STRING *v)
	{
	int i,n;
	char buf[80],*p;

	if (v == NULL) return(0);
	n=0;
	p=(char *)v->data;
	for (i=0; i<v->length; i++)
		{
//		if ((p[i] > '~') || ((p[i] < ' ') &&
//			(p[i] != '\n') && (p[i] != '\r')))
//			buf[n]='.';
//		else
			buf[n]=p[i];
		n++;
		if (n >= 80)
			{
			if (BIO_write(bp,buf,n) <= 0)
				return(0);
			n=0;
			}
		}
	if (n > 0)
		if (BIO_write(bp,buf,n) <= 0)
			return(0);
	return(1);
	}


/////////////////////rsa_cb/////////////////////////////////

static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	if(operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)RSA_new();
		if(*pval) return 2;
		return 0;
	} else if(operation == ASN1_OP_FREE_PRE) {
		//RSA_free((RSA *)*pval);//samyang delete
		*pval = NULL;
		return 2;
	}
	return 1;
}


////////////////RSAPublicKey_it//////////////////////////////////////

ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
	ASN1_SIMPLE(RSA, n, BIGNUM),
	ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPublicKey, RSAPublicKey)


void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine);

///////////////ASN1_item_free//////////////////////////ok

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)
	{

	asn1_item_combine_free(&val, it, 0);
	}

//////////////ASN1_TYPE_set//////////////////////ok
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
{

	if (a->value.ptr != NULL)
		{
		ASN1_TYPE **tmp_a = &a;
		ASN1_primitive_free((ASN1_VALUE **)tmp_a, NULL);
		}
	a->type=type;
	a->value.ptr=value;
}

/////////////////ASN1_primitive_free//////////////////////////ok

void ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	int utype;

	if (it)
		{
		const ASN1_PRIMITIVE_FUNCS *pf;
		pf = it->funcs;
		if (pf && pf->prim_free)
			{
			pf->prim_free(pval, it);
			return;
			}
		}

	if (!it)
		{
		ASN1_TYPE *typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		pval = &typ->value.asn1_value;
		if (!*pval)
			return;
		}
	else if (it->itype == ASN1_ITYPE_MSTRING)
		{
		utype = -1;
		if (!*pval)
			return;
		}
	else
		{
		utype = it->utype;
		if ((utype != V_ASN1_BOOLEAN) && !*pval)
			return;
		}

	switch(utype)
		{
		case V_ASN1_OBJECT:
		ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
		break;

		case V_ASN1_BOOLEAN:
		if (it)
			*(ASN1_BOOLEAN *)pval = it->size;
		else
			*(ASN1_BOOLEAN *)pval = -1;
		return;

		case V_ASN1_NULL:
		break;

		case V_ASN1_ANY:
		ASN1_primitive_free(pval, NULL);
		OPENSSL_free(*pval);
		break;

		default:
		ASN1_STRING_free((ASN1_STRING *)*pval);
		*pval = NULL;
		break;
		}
	*pval = NULL;
	}


////////////////asn1_item_combine_free///////////////////////////ok

 void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
	{
	const ASN1_TEMPLATE *tt = NULL, *seqtt;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	int i=0;

	if (!pval)
		return;
	if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
		return;
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;
	else
		asn1_cb = 0;

	switch(it->itype)
		{

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			ASN1_template_free(pval, it->templates);
		else
			ASN1_primitive_free(pval, it);
		break;

		case ASN1_ITYPE_MSTRING:
		ASN1_primitive_free(pval, it);
		break;

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it);
			if (i == 2)
				return;
			}
		//i = asn1_get_choice_selector(pval, it);//samyang delete
		if ((i >= 0) && (i < it->tcount))
			{
			ASN1_VALUE **pchval;
			tt = it->templates + i;
			pchval = asn1_get_field_ptr(pval, tt);
			ASN1_template_free(pchval, tt);
			}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it);
		if (!combine)
			{
			OPENSSL_free(*pval);
			*pval = NULL;
			}
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (cf && cf->asn1_free)
			cf->asn1_free(*pval);
		break;

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_free)
			ef->asn1_ex_free(pval, it);
		break;

		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		//if (asn1_do_lock(pval, -1, it) > 0)//samyang delete
		//	return;
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it);
			if (i == 2)
				return;
			}
		asn1_enc_free(pval, it);

		tt = it->templates + it->tcount - 1;
		for (i = 0; i < it->tcount; tt--, i++)
			{
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 0);
			if (!seqtt)
				continue;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			ASN1_template_free(pseqval, seqtt);
			}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it);
		if (!combine)
			{
			OPENSSL_free(*pval);
			*pval = NULL;
			}
		break;
		}
	}



#define BN_SENSITIVE	1

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it);
static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype, char *free_cont, const ASN1_ITEM *it);

static ASN1_PRIMITIVE_FUNCS bignum_pf = {
	NULL, 0,
	bn_new,
	bn_free,
	0,
	bn_c2i,
	bn_i2c
};

////////////////////////BIGNUM_it//////////////////////////////////////////////

ASN1_ITEM_start(BIGNUM)
	ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM"
ASN1_ITEM_end(BIGNUM)

//////////////////bn_new//////////////////////////////////ok

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
		
	*pval = (ASN1_VALUE *)BN_new();
	if(*pval) return 1;
	else return 0;
}

////////////////bn_free//////////////////////////////////

static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
		;
}

//////////////////bn_i2c/////////////////////////////////////////////////////////////ok

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it)
{
	BIGNUM *bn;
	int pad;
		
	if(!*pval) return -1;
	bn = (BIGNUM *)*pval;
	/* If MSB set in an octet we need a padding byte */
	if(BN_num_bits(bn) & 0x7) pad = 0;
	else pad = 1;
	if(cont) {
		if(pad) *cont++ = 0;
		BN_bn2bin(bn, cont);
	}
	return pad + BN_num_bytes(bn);
}

////////////////////bn_c2i/////////////////////////////////////////////ok

static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
		  int utype, char *free_cont, const ASN1_ITEM *it)
{
	BIGNUM *bn;
		
	if(!*pval) bn_new(pval, it);
	bn  = (BIGNUM *)*pval;
	if(!BN_bin2bn(cont, len, bn)) {
		bn_free(pval, it);
		return 0;
	}
	return 1;
}


/* crypto/x509/x509_ext.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



int X509_get_ext_count(X509 *x)
	{
	return(X509v3_get_ext_count(x->cert_info->extensions));
	}


#define sk_X509_EXTENSION_value(st, i) SKM_sk_value(X509_EXTENSION, (st), (i))
#define sk_X509_EXTENSION_num(st) SKM_sk_num(X509_EXTENSION, (st))

////////////sk_num//////////////////////////////////ok

int sk_num(const STACK *st)
{

	if(st == NULL) return -1;
	return st->num;
}
//////////sk_value//////////////////////////////ok

char *sk_value(const STACK *st, int i)
{

	if(!st || (i < 0) || (i >= st->num)) return NULL;
	return st->data[i];
}
/////////X509v3_get_ext_count//////////////////////////////ok


/* crypto/x509/x509_v3.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)
	{
	if (x == NULL) return(0);
	return(sk_X509_EXTENSION_num(x));
	}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
	{
	if (ex == NULL) return(NULL);
	return(ex->object);
	}






#undef MIN_NODES
#define MIN_NODES	16
#define UP_LOAD		(2*LH_LOAD_MULT)
#define DOWN_LOAD	(LH_LOAD_MULT)

static LHASH_NODE **getrn(LHASH *lh, const void *data, unsigned long *rhash);


////////////////getrn//////////////////////////ok

static LHASH_NODE **getrn(LHASH *lh, const void *data, unsigned long *rhash)
	{
	LHASH_NODE **ret,*n1;
	unsigned long hash,nn;
	LHASH_COMP_FN_TYPE cf;

	//DMSG_DEBUG("============getrn=================--1--\n");

	hash=(*(lh->hash))(data);
	lh->num_hash_calls++;
	*rhash=hash;

	//DMSG_DEBUG("============getrn=================--2--\n");

	nn=hash%lh->pmax;

	if (nn < lh->p)
		nn=hash%lh->num_alloc_nodes;

	cf=lh->comp;
	ret= &(lh->b[(int)nn]);

	//DMSG_DEBUG("============getrn=================--3--\n");

	for (n1= *ret; n1 != NULL; n1=n1->next)
		{
#ifndef OPENSSL_NO_HASH_COMP
		lh->num_hash_comps++;
		if (n1->hash != hash)
			{
			ret= &(n1->next);
			continue;
			}
#endif
		lh->num_comp_calls++;
		if(cf(n1->data,data) == 0)
			break;
		ret= &(n1->next);
		}

	//DMSG_DEBUG("============getrn=================--end--\n");

	return(ret);
	}

///////////lh_retrieve//////////////////////////ok

void *lh_retrieve(LHASH *lh, const void *data)
{
	unsigned long hash;
	LHASH_NODE **rn;
	void *ret;

	lh->error=0;
	rn=getrn(lh,data,&hash);

	if (*rn == NULL)
		{
		lh->num_retrieve_miss++;
		return(NULL);
		}
	else
		{
		ret= (*rn)->data;
		lh->num_retrieve++;
		}
	return(ret);
}


///////////////lh_insert//////////////////////////ok

void *lh_insert(LHASH *lh, void *data)
	{
	unsigned long hash;
	LHASH_NODE *nn,**rn;
	void *ret;

	lh->error=0;

	rn=getrn(lh,data,&hash);

	if (*rn == NULL)
		{
		if ((nn=(LHASH_NODE *)OPENSSL_malloc(sizeof(LHASH_NODE))) == NULL)
			{
			lh->error++;
			return(NULL);
			}
		nn->data=data;
		nn->next=NULL;
#ifndef OPENSSL_NO_HASH_COMP
		nn->hash=hash;
#endif
		*rn=nn;
		ret=NULL;
		lh->num_insert++;
		lh->num_items++;
		}
	else /* replace same key */
		{
		ret= (*rn)->data;
		(*rn)->data=data;
		lh->num_replace++;
		}
	return(ret);
	}


///////////lh_new/////////////////////////////ok

LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c)
	{
	LHASH *ret;
	int i;

	if ((ret=(LHASH *)OPENSSL_malloc(sizeof(LHASH))) == NULL)
		goto err0;
	if ((ret->b=(LHASH_NODE **)OPENSSL_malloc(sizeof(LHASH_NODE *)*MIN_NODES)) == NULL)
		goto err1;
	for (i=0; i<MIN_NODES; i++)
		ret->b[i]=NULL;
	ret->comp=((c == NULL)?(LHASH_COMP_FN_TYPE)strcmp:c);
	ret->hash=h;//((h == NULL)?(LHASH_HASH_FN_TYPE)lh_strhash:h);//samyang delete
	ret->num_nodes=MIN_NODES/2;
	ret->num_alloc_nodes=MIN_NODES;
	ret->p=0;
	ret->pmax=MIN_NODES/2;
	ret->up_load=UP_LOAD;
	ret->down_load=DOWN_LOAD;
	ret->num_items=0;

	ret->num_expands=0;
	ret->num_expand_reallocs=0;
	ret->num_contracts=0;
	ret->num_contract_reallocs=0;
	ret->num_hash_calls=0;
	ret->num_comp_calls=0;
	ret->num_insert=0;
	ret->num_replace=0;
	ret->num_delete=0;
	ret->num_no_delete=0;
	ret->num_retrieve=0;
	ret->num_retrieve_miss=0;
	ret->num_hash_comps=0;

	ret->error=0;
	return(ret);
err1:
	OPENSSL_free(ret);
err0:
	return(NULL);
	}

/* crypto/x509/x509_ext.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



int X509_get_ext_count(X509 *x)
{
	return(X509v3_get_ext_count(x->cert_info->extensions));
}

/* crypto/x509/x509_v3.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)
	{
	if (x == NULL) return(0);
	return(sk_X509_EXTENSION_num(x));
	}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
	{
	if (ex == NULL) return(NULL);
	return(ex->object);
	}



unsigned char cleanse_ctr = 0;

void OPENSSL_cleanse(void *ptr, size_t len)
{
	unsigned char *p = ptr;
	size_t loop = len, ctr = cleanse_ctr;
	while(loop--)
		{
		*(p++) = (unsigned char)ctr;
		ctr += (17 + ((size_t)p & 0xF));
		}
	p=memchr(ptr, (unsigned char)ctr, len);
	if(p)
		ctr += (63 + (size_t)p);
	cleanse_ctr = (unsigned char)ctr;
}


void *CRYPTO_malloc(int num, const char *file, int line)
	{
	if (num <= 0) return NULL;

	return malloc(num);
	}

void *CRYPTO_realloc(void *str, int num, const char *file, int line)
	{
	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	return realloc(str, num);
	}

void *CRYPTO_realloc_clean(void *str, int old_len, int num, const char *file,
			   int line)
	{
	void *ret = NULL;

	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	/* We don't support shrinking the buffer. Note the memcpy that copies
	 * |old_len| bytes to the new buffer, below. */
	if (num < old_len) return NULL;

	ret =  malloc(num);
	if(ret)
		{
		memcpy(ret,str,old_len);
		OPENSSL_cleanse(str,old_len);
		free(str);
		}

	return ret;
	}

void CRYPTO_free(void *str)
	{
	free(str);
	}

void *CRYPTO_remalloc(void *a, int num, const char *file, int line)
	{
	if (a != NULL) free(a);
	a=(char *)malloc(num);
	return(a);
	}


void reset_CRYPTO_reset(void)
{
	cleanse_ctr = 0;
}

//static RSA_METHOD rsa_pkcs1_eay_meth={		//--hgl--20140331--RW mem to const mem
const RSA_METHOD rsa_pkcs1_eay_meth={
	"Eric Young's PKCS#1 RSA",
	0, /* flags */
	NULL,
	0, /* rsa_sign */
	0, /* rsa_verify */
	NULL /* rsa_keygen */
	};
/////////////////////RSA_new////////////////////////////////////////ok

RSA *RSA_new(void)
	{
		
	RSA *r=RSA_new_method(NULL);
	
	return r;
	}

///////////////////RSA_new_method///////////////////////////////////////ok

RSA *RSA_new_method(ENGINE *engine)
	{
	RSA *ret;
	
	ret=(RSA *)OPENSSL_malloc(sizeof(RSA));
	if (ret == NULL)
		{
		RSAerr(RSA_F_RSA_NEW_METHOD,ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = &rsa_pkcs1_eay_meth;

	ret->pad=0;
	ret->version=0;
	ret->n=NULL;
	ret->e=NULL;
	ret->d=NULL;
	ret->p=NULL;
	ret->q=NULL;
	ret->dmp1=NULL;
	ret->dmq1=NULL;
	ret->iqmp=NULL;
	ret->references=1;
	ret->_method_mod_n=NULL;
	ret->_method_mod_p=NULL;
	ret->_method_mod_q=NULL;
	ret->blinding=NULL;
	ret->mt_blinding=NULL;
	ret->bignum_data=NULL;
	ret->flags=ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data))
		{
		OPENSSL_free(ret);
		return(NULL);
		}

	if ((ret->meth->init != NULL) && !ret->meth->init(ret))
		{
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
		}
	return(ret);
	}




////////////ERR_put_error/////////////////////////////////////

void ERR_put_error(int lib, int func, int reason, const char *file,
	     int line)
{

	;
}


#define ADDED_NID	3
#define ADDED_DATA	0

//#define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),__FILE__,__LINE__)

typedef struct added_obj_st
{
	int type;
	ASN1_OBJECT *obj;
} ADDED_OBJ;

static LHASH *added=NULL;

void reset_OBJ_nid2ln_reset(void)
{
	added=NULL;
}
/////////////OBJ_nid2ln/////////////////////////ok

const char *OBJ_nid2ln(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			return(NULL);
			}
		return(nid_objs[n].ln);
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj->ln);
		else
		{
			return(NULL);
		}
	}
}
///////////////OBJ_bsearch/////////////////ok

const char *OBJ_bsearch(const char *key, const char *base, int num, int size,
	int (*cmp)(const void *, const void *))
{

	return OBJ_bsearch_ex(key, base, num, size, cmp, 0);
}

//////////////////////////////////////////////////////////////////ok

const char *OBJ_bsearch_ex(const char *key, const char *base, int num,
	int size, int (*cmp)(const void *, const void *), int flags)
{
	int l,h,i=0,c=0;
	const char *p = NULL;

	if (num == 0) return(NULL);
	l=0;
	h=num;
	while (l < h)
		{
		i=(l+h)/2;
		p= &(base[i*size]);
		c=(*cmp)(key,p);
		if (c < 0)
			h=i;
		else if (c > 0)
			l=i+1;
		else
			break;
}
//#ifdef CHARSET_EBCDIC			//###samyang  modity
/* THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and
 * I don't have perl (yet), we revert to a *LINEAR* search
 * when the object wasn't found in the binary search.
 */
	if (c != 0)
		{
		for (i=0; i<num; ++i)
			{
			p= &(base[i*size]);
			c = (*cmp)(key,p);
			if (c == 0 || (c < 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH)))
				return p;
			}
		}
//#endif		////###samyang  modity
	if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
		p =NULL;//&(base[78*size]);
	else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH))
		{
		while(i > 0 && (*cmp)(key,&(base[(i-1)*size])) == 0)
			i--;
		p = &(base[i*size]);
		}
	return(p);
	}

//////////////////obj_cmp//////////////////ok

static int obj_cmp(const void *ap, const void *bp)
{
	int j;
	const ASN1_OBJECT *a= *(ASN1_OBJECT * const *)ap;
	const ASN1_OBJECT *b= *(ASN1_OBJECT * const *)bp;

	j=(a->length - b->length);
        if (j) return(j);
	return(memcmp(a->data,b->data,a->length));
  }
///////////////////OBJ_obj2nid//////////////////////ok

int OBJ_obj2nid(const ASN1_OBJECT *a)
	{
	ASN1_OBJECT **op;
	ADDED_OBJ ad,*adp;

	if (a == NULL)
		return(NID_undef);
	if (a->nid != 0)
		return(a->nid);

	if (added != NULL)
		{
		ad.type=ADDED_DATA;
		ad.obj=(ASN1_OBJECT *)a; /* XXX: ugly but harmless */
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=(ASN1_OBJECT **)OBJ_bsearch((const char *)&a,(const char *)obj_objs,
		NUM_OBJ, sizeof(ASN1_OBJECT *),obj_cmp);
	if (op == NULL)
		return(NID_undef);
	return((*op)->nid);
	}


///////////////OBJ_nid2obj////////////////////////////////ok

ASN1_OBJECT *OBJ_nid2obj(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
		{

			return(NULL);
		}
		return((ASN1_OBJECT *)&(nid_objs[n]));
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj);
		else
		{
			return(NULL);
		}
	}
}

const char *OBJ_nid2sn(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			OBJerr(OBJ_F_OBJ_NID2SN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		return(nid_objs[n].sn);
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj->sn);
		else
			{
				return(NULL);
			}
	}
}


int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
//	int i,n=0,len,nid, first, use_bn;
//	BIGNUM *bl;
//	unsigned long l;
//	const unsigned char *p;
//	char tbuf[DECIMAL_SIZE(i)+DECIMAL_SIZE(l)+2];
//
//	if ((a == NULL) || (a->data == NULL)) {
//		buf[0]='\0';
//		return(0);
//	}
//
//	if (!no_name && (nid=OBJ_obj2nid(a)) != NID_undef)
//		{
//		const char *s;
//		s=OBJ_nid2ln(nid);
//		if (s == NULL)
//			s=OBJ_nid2sn(nid);
//		if (s)
//			{
//			if (buf)
//				strncpy(buf,s,buf_len);
//			n=strlen(s);
//			return n;
//			}
//		}
//
//	len=a->length;
//	p=a->data;
//
//	first = 1;
//	bl = NULL;
//
//	while (len > 0)
//		{
//		l=0;
//		use_bn = 0;
//		for (;;)
//			{
//			unsigned char c = *p++;
//			len--;
//			if ((len == 0) && (c & 0x80))
//				goto err;
//			if (use_bn)
//				{
//				if (!BN_add_word(bl, c & 0x7f))
//					goto err;
//				}
//			else
//				l |= c  & 0x7f;
//			if (!(c & 0x80))
//				break;
//			if (!use_bn && (l > (ULONG_MAX >> 7L)))
//				{
//				if (!bl && !(bl = BN_new()))
//					goto err;
//				if (!BN_set_word(bl, l))
//					goto err;
//				use_bn = 1;
//				}
//			if (use_bn)
//				{
//				if (!BN_lshift(bl, bl, 7))
//					goto err;
//				}
//			else
//				l<<=7L;
//			}
//
//		if (first)
//			{
//			first = 0;
//			if (l >= 80)
//				{
//				i = 2;
//				if (use_bn)
//					{
//					if (!BN_sub_word(bl, 80))
//						goto err;
//					}
//				else
//					l -= 80;
//				}
//			else
//				{
//				i=(int)(l/40);
//				l-=(long)(i*40);
//				}
//			if (buf && (buf_len > 0))
//				{
//				*buf++ = i + '0';
//				buf_len--;
//				}
//			n++;
//			}
//
//		if (use_bn)
//			{
//			char *bndec;
//			bndec = BN_bn2dec(bl);
//			if (!bndec)
//				goto err;
//			i = strlen(bndec);
//			if (buf)
//				{
//				if (buf_len > 0)
//					{
//					*buf++ = '.';
//					buf_len--;
//					}
//				strncpy(buf,bndec,buf_len);
//				if (i > buf_len)
//					{
//					buf += buf_len;
//					buf_len = 0;
//					}
//				else
//					{
//					buf+=i;
//					buf_len-=i;
//					}
//				}
//			n++;
//			n += i;
//			OPENSSL_free(bndec);
//			}
//		else
//			{
//			BIO_snprintf(tbuf,sizeof tbuf,".%lu",l);
//			i=strlen(tbuf);
//			if (buf && (buf_len > 0))
//				{
//				strncpy(buf,tbuf,buf_len);
//				if (i > buf_len)
//					{
//					buf += buf_len;
//					buf_len = 0;
//					}
//				else
//					{
//					buf+=i;
//					buf_len-=i;
//					}
//				}
//			n+=i;
//			l=0;
//			}
//		}
//
//	if (bl)
//		BN_free(bl);
//	return n;
//
//	err:
//	if (bl)
//		BN_free(bl);
	return -1;
}

int OBJ_obj2name(char *dst_buf, int buf_len, const ASN1_OBJECT *a)
{
	if(buf_len < a->length)
	{
		printf("OBJ_obj2name err: not enough buffer to store name\n");

		return -1;
	}
	memcpy(dst_buf, a->data, a->length);

	return a->length;
}
//#define BN_ULONG	unsigned long	//samyang add  depend on bn.h
//#define BN_BITS2	32

struct bn_blinding_st
	{
	BIGNUM *A;
	BIGNUM *Ai;
	BIGNUM *e;
	BIGNUM *mod; /* just a reference */
	unsigned long thread_id; /* added in OpenSSL 0.9.6j and 0.9.7b;
				  * used only by crypto/rsa/rsa_eay.c, rsa_lib.c */
	unsigned int  counter;
	unsigned long flags;
	BN_MONT_CTX *m_ctx;
	int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx,
			  BN_MONT_CTX *m_ctx);
	};

typedef struct bn_blinding_st BN_BLINDING;


///////////////BN_new/////////////////////////////////ok

BIGNUM *BN_new(void)
	{
	BIGNUM *ret;
	if ((ret=(BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL)
		{
		BNerr(BN_F_BN_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->flags=BN_FLG_MALLOCED;
	ret->top=0;
	ret->neg=0;
	ret->dmax=0;
	ret->d=NULL;
	bn_check_top(ret);
	return(ret);
	}

////////////////bn_expand_internal//////////////////////////////ok

static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
	{
	BN_ULONG *A,*a = NULL;
	const BN_ULONG *B;
	int i;
	bn_check_top(b);

	if (words > (INT_MAX/(4*BN_BITS2)))
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_BIGNUM_TOO_LONG);
		return NULL;
		}
	if (BN_get_flags(b,BN_FLG_STATIC_DATA))
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return(NULL);
		}
	a=A=(BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG)*words);
	if (A == NULL)
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
#if 1
	B=b->d;

	if (B != NULL)
		{
		for (i=b->top>>2; i>0; i--,A+=4,B+=4)
			{

			BN_ULONG a0,a1,a2,a3;
			a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
			A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
			}
		switch (b->top&3)
			{
		case 3:	A[2]=B[2];
		case 2:	A[1]=B[1];
		case 1:	A[0]=B[0];
		case 0:
			;
			}
		}

#else
	memset(A,0,sizeof(BN_ULONG)*words);
	memcpy(A,b->d,sizeof(b->d[0])*b->top);
#endif

	return(a);
	}

//////////////bn_expand2///////////////////////////////ok

BIGNUM *bn_expand2(BIGNUM *b, int words)
	{
	bn_check_top(b);

	if (words > b->dmax)
		{
		BN_ULONG *a = bn_expand_internal(b, words);
		if(!a) return NULL;
		if(b->d) OPENSSL_free(b->d);
		b->d=a;
		b->dmax=words;
		}
	bn_check_top(b);
	return b;
	}

////////////BN_num_bits_word//////////////////////////ok

int BN_num_bits_word(BN_ULONG l)
	{
	static const char bits[256]={
		0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
		5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		};


#ifdef SIXTY_FOUR_BIT
	if (l & 0xffffffff00000000LL)
		{
		if (l & 0xffff000000000000LL)
			{
			if (l & 0xff00000000000000LL)
				{
				return(bits[(int)(l>>56)]+56);
				}
			else	return(bits[(int)(l>>48)]+48);
			}
		else
			{
			if (l & 0x0000ff0000000000LL)
				{
				return(bits[(int)(l>>40)]+40);
				}
			else	return(bits[(int)(l>>32)]+32);
			}
		}
	else
#endif

		{
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
		if (l & 0xffff0000L)
			{
			if (l & 0xff000000L)
				return(bits[(int)(l>>24L)]+24);
			else	return(bits[(int)(l>>16L)]+16);
			}
		else
#endif
			{
#if defined(SIXTEEN_BIT) || defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
			if (l & 0xff00L)
				return(bits[(int)(l>>8)]+8);
			else
#endif
				return(bits[(int)(l   )]  );
			}
		}
	}

////////////BN_num_bits///////////////////////////ok

int BN_num_bits(const BIGNUM *a)
{
	int i = a->top - 1;
	bn_check_top(a);

	if (BN_is_zero(a)) return 0;
	return ((i*BN_BITS2) + BN_num_bits_word(a->d[i]));
}

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG ret = 0;
	int i, j;

	bn_check_top(a);
	w &= BN_MASK2;

	if (!w)
		/* actually this an error (division by zero) */
		return (BN_ULONG)-1;
	if (a->top == 0)
		return 0;

	/* normalize input (so bn_div_words doesn't complain) */
	j = BN_BITS2 - BN_num_bits_word(w);
	w <<= j;
	if (!BN_lshift(a, a, j))
		return (BN_ULONG)-1;

	for (i=a->top-1; i>=0; i--)
		{
		BN_ULONG l,d;

		l=a->d[i];
		d=bn_div_words(ret,l,w);
		ret=(l-((d*w)&BN_MASK2))&BN_MASK2;
		a->d[i]=d;
		}
	if ((a->top > 0) && (a->d[a->top-1] == 0))
		a->top--;
	ret >>= j;
	bn_check_top(a);
	return(ret);
	}


int BN_add_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG l;
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a)) return BN_set_word(a, w);
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_sub_word(a,w);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return(i);
		}
	for (i=0;w!=0 && i<a->top;i++)
		{
		a->d[i] = l = (a->d[i]+w)&BN_MASK2;
		w = (w>l)?1:0;
		}
	if (w && i==a->top)
		{
		if (bn_wexpand(a,a->top+1) == NULL) return 0;
		a->top++;
		a->d[i]=w;
		}
	bn_check_top(a);
	return(1);
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
	{
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a))
		{
		i = BN_set_word(a,w);
		if (i != 0)
			BN_set_negative(a, 1);
		return i;
		}
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_add_word(a,w);
		a->neg=1;
		return(i);
		}

	if ((a->top == 1) && (a->d[0] < w))
		{
		a->d[0]=w-a->d[0];
		a->neg=1;
		return(1);
		}
	i=0;
	for (;;)
		{
		if (a->d[i] >= w)
			{
			a->d[i]-=w;
			break;
			}
		else
			{
			a->d[i]=(a->d[i]-w)&BN_MASK2;
			i++;
			w=1;
			}
		}
	if ((a->d[i] == 0) && (i == (a->top-1)))
		a->top--;
	bn_check_top(a);
	return(1);
	}
/* crypto/bn/bn_shift.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


//int BN_lshift1(BIGNUM *r, const BIGNUM *a)
//	{
//	register BN_ULONG *ap,*rp,t,c;
//	int i;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	if (r != a)
//		{
//		r->neg=a->neg;
//		if (bn_wexpand(r,a->top+1) == NULL) return(0);
//		r->top=a->top;
//		}
//	else
//		{
//		if (bn_wexpand(r,a->top+1) == NULL) return(0);
//		}
//	ap=a->d;
//	rp=r->d;
//	c=0;
//	for (i=0; i<a->top; i++)
//		{
//		t= *(ap++);
//		*(rp++)=((t<<1)|c)&BN_MASK2;
//		c=(t & BN_TBIT)?1:0;
//		}
//	if (c)
//		{
//		*rp=1;
//		r->top++;
//		}
//	bn_check_top(r);
//	return(1);
//	}

//int BN_rshift1(BIGNUM *r, const BIGNUM *a)
//	{
//	BN_ULONG *ap,*rp,t,c;
//	int i,j;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	if (BN_is_zero(a))
//		{
//		BN_zero(r);
//		return(1);
//		}
//	i = a->top;
//	ap= a->d;
//	j = i-(ap[i-1]==1);
//	if (a != r)
//		{
//		if (bn_wexpand(r,j) == NULL) return(0);
//		r->neg=a->neg;
//		}
//	rp=r->d;
//	t=ap[--i];
//	c=(t&1)?BN_TBIT:0;
//	if (t>>=1) rp[i]=t;
//	while (i>0)
//		{
//		t=ap[--i];
//		rp[i]=((t>>1)&BN_MASK2)|c;
//		c=(t&1)?BN_TBIT:0;
//		}
//	r->top=j;
//	bn_check_top(r);
//	return(1);
//	}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int i,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l;

	bn_check_top(r);
	bn_check_top(a);

	r->neg=a->neg;
	nw=n/BN_BITS2;
	if (bn_wexpand(r,a->top+nw+1) == NULL) return(0);
	lb=n%BN_BITS2;
	rb=BN_BITS2-lb;
	f=a->d;
	t=r->d;
	t[a->top+nw]=0;
	if (lb == 0)
		for (i=a->top-1; i>=0; i--)
			t[nw+i]=f[i];
	else
		for (i=a->top-1; i>=0; i--)
			{
			l=f[i];
			t[nw+i+1]|=(l>>rb)&BN_MASK2;
			t[nw+i]=(l<<lb)&BN_MASK2;
			}
	memset(t,0,nw*sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top=a->top+nw+1;
	bn_correct_top(r);
	bn_check_top(r);
	return(1);
	}

//int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
//	{
//	int i,j,nw,lb,rb;
//	BN_ULONG *t,*f;
//	BN_ULONG l,tmp;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	nw=n/BN_BITS2;
//	rb=n%BN_BITS2;
//	lb=BN_BITS2-rb;
//	if (nw >= a->top || a->top == 0)
//		{
//		BN_zero(r);
//		return(1);
//		}
//	i = (BN_num_bits(a)-n+(BN_BITS2-1))/BN_BITS2;
//	if (r != a)
//		{
//		r->neg=a->neg;
//		if (bn_wexpand(r,i) == NULL) return(0);
//		}
//	else
//		{
//		if (n == 0)
//			return 1; /* or the copying loop will go berserk */
//		}
//
//	f= &(a->d[nw]);
//	t=r->d;
//	j=a->top-nw;
//	r->top=i;
//
//	if (rb == 0)
//		{
//		for (i=j; i != 0; i--)
//			*(t++)= *(f++);
//		}
//	else
//		{
//		l= *(f++);
//		for (i=j-1; i != 0; i--)
//			{
//			tmp =(l>>rb)&BN_MASK2;
//			l= *(f++);
//			*(t++) =(tmp|(l<<lb))&BN_MASK2;
//			}
//		if ((l = (l>>rb)&BN_MASK2)) *(t) = l;
//		}
//	bn_check_top(r);
//	return(1);
//	}

/////////////////// BN_bn2bin////////////////////////////////////////ok

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
	{
	int n,i;
	BN_ULONG l;
	
	bn_check_top(a);
	n=i=BN_num_bytes(a);
	while (i--)
		{
		l=a->d[i/BN_BYTES];
		*(to++)=(unsigned char)(l>>(8*(i%BN_BYTES)))&0xff;
		}
	return(n);
	}

////////////////BN_bin2bn/////////////////////////////////////////////////ok

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
	{
	unsigned int i,m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM  *bn = NULL;
	
	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL) return(NULL);
	bn_check_top(ret);
	l=0;
	n=len;
	if (n == 0)
		{
		ret->top=0;
		return(ret);
		}
	i=((n-1)/BN_BYTES)+1;
	m=((n-1)%(BN_BYTES));
	if (bn_wexpand(ret, (int)i) == NULL)
		{
		//if (bn) BN_free(bn);
		return NULL;
		}
	ret->top=i;
	ret->neg=0;
	while (n--)
		{
		l=(l<<8L)| *(s++);
		if (m-- == 0)
			{
			ret->d[--i]=l;
			l=0;
			m=BN_BYTES-1;
			}
		}

	bn_correct_top(ret);
	return(ret);
	}

/* crypto/bn/bn_print.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


extern int BIO_snprintf(char *buf, size_t n, const char *format, ...);

static const char Hex[]="0123456789ABCDEF";

/* Must 'OPENSSL_free' the returned data */
//char *BN_bn2hex(const BIGNUM *a)
//	{
//	int i,j,v,z=0;
//	char *buf;
//	char *p;
//
//	buf=(char *)OPENSSL_malloc(a->top*BN_BYTES*2+2);
//	if (buf == NULL)
//		{
//		BNerr(BN_F_BN_BN2HEX,ERR_R_MALLOC_FAILURE);
//		goto err;
//		}
//	p=buf;
//	if (a->neg) *(p++)='-';
//	if (BN_is_zero(a)) *(p++)='0';
//	for (i=a->top-1; i >=0; i--)
//		{
//		for (j=BN_BITS2-8; j >= 0; j-=8)
//			{
//			/* strip leading zeros */
//			v=((int)(a->d[i]>>(long)j))&0xff;
//			if (z || (v != 0))
//				{
//				*(p++)=Hex[v>>4];
//				*(p++)=Hex[v&0x0f];
//				z=1;
//				}
//			}
//		}
//	*p='\0';
//err:
//	return(buf);
//	}

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2dec(const BIGNUM *a)
	{
	int i=0,num, ok = 0;
	char *buf=NULL;
	char *p;
	BIGNUM *t=NULL;
	BN_ULONG *bn_data=NULL,*lp;

	/* get an upper bound for the length of the decimal integer
	 * num <= (BN_num_bits(a) + 1) * log(2)
	 *     <= 3 * BN_num_bits(a) * 0.1001 + log(2) + 1     (rounding error)
	 *     <= BN_num_bits(a)/10 + BN_num_bits/1000 + 1 + 1
	 */
	i=BN_num_bits(a)*3;
	num=(i/10+i/1000+1)+1;
	bn_data=(BN_ULONG *)OPENSSL_malloc((num/BN_DEC_NUM+1)*sizeof(BN_ULONG));
	buf=(char *)OPENSSL_malloc(num+3);
	if ((buf == NULL) || (bn_data == NULL))
		{
		goto err;
		}
	if ((t=BN_dup(a)) == NULL) goto err;

#define BUF_REMAIN (num+3 - (size_t)(p - buf))
	p=buf;
	lp=bn_data;
	if (BN_is_zero(t))
		{
		*(p++)='0';
		*(p++)='\0';
		}
	else
		{
		if (BN_is_negative(t))
			*p++ = '-';

		i=0;
		while (!BN_is_zero(t))
			{
			*lp=BN_div_word(t,BN_DEC_CONV);
			lp++;
			}
		lp--;
		/* We now have a series of blocks, BN_DEC_NUM chars
		 * in length, where the last one needs truncation.
		 * The blocks need to be reversed in order. */
		BIO_snprintf(p,BUF_REMAIN,BN_DEC_FMT1,*lp);
		while (*p) p++;
		while (lp != bn_data)
			{
			lp--;
			BIO_snprintf(p,BUF_REMAIN,BN_DEC_FMT2,*lp);
			while (*p) p++;
			}
		}
	ok = 1;
err:
	if (bn_data != NULL) OPENSSL_free(bn_data);
	if (t != NULL) BN_free(t);
	if (!ok && buf)
		{
		OPENSSL_free(buf);
		buf = NULL;
		}

	return(buf);
	}

//int BN_hex2bn(BIGNUM **bn, const char *a)
//	{
//		printf("%s %d %s\n", __FILE__, __LINE__, __func__);
//	BIGNUM *ret=NULL;
//	BN_ULONG l=0;
//	int neg=0,h,m,i,j,k,c;
//	int num;
//
//	if ((a == NULL) || (*a == '\0')) return(0);
//
//	if (*a == '-') { neg=1; a++; }
//
//	for (i=0; isxdigit((unsigned char) a[i]); i++)
//		;
//
//	num=i+neg;
//	if (bn == NULL) return(num);
//
//	/* a is the start of the hex digits, and it is 'i' long */
//	if (*bn == NULL)
//		{
//		if ((ret=BN_new()) == NULL) return(0);
//		}
//	else
//		{
//		ret= *bn;
//		BN_zero(ret);
//		}
//
//	/* i is the number of hex digests; */
//	if (bn_expand(ret,i*4) == NULL) goto err;
//
//	j=i; /* least significant 'hex' */
//	m=0;
//	h=0;
//	while (j > 0)
//		{
//		m=((BN_BYTES*2) <= j)?(BN_BYTES*2):j;
//		l=0;
//		for (;;)
//			{
//			c=a[j-m];
//			if ((c >= '0') && (c <= '9')) k=c-'0';
//			else if ((c >= 'a') && (c <= 'f')) k=c-'a'+10;
//			else if ((c >= 'A') && (c <= 'F')) k=c-'A'+10;
//			else k=0; /* paranoia */
//			l=(l<<4)|k;
//
//			if (--m <= 0)
//				{
//				ret->d[h++]=l;
//				break;
//				}
//			}
//		j-=(BN_BYTES*2);
//		}
//	ret->top=h;
//	bn_correct_top(ret);
//	ret->neg=neg;
//
//	*bn=ret;
//	bn_check_top(ret);
//	return(num);
//err:
//	if (*bn == NULL) BN_free(ret);
//	return(0);
//	}

//int BN_dec2bn(BIGNUM **bn, const char *a)
//	{
//		printf("%s %d %s\n", __FILE__, __LINE__, __func__);
//	BIGNUM *ret=NULL;
//	BN_ULONG l=0;
//	int neg=0,i,j;
//	int num;
//
//	if ((a == NULL) || (*a == '\0')) return(0);
//	if (*a == '-') { neg=1; a++; }
//
//	for (i=0; isdigit((unsigned char) a[i]); i++)
//		;
//
//	num=i+neg;
//	if (bn == NULL) return(num);
//
//	/* a is the start of the digits, and it is 'i' long.
//	 * We chop it into BN_DEC_NUM digits at a time */
//	if (*bn == NULL)
//		{
//		if ((ret=BN_new()) == NULL) return(0);
//		}
//	else
//		{
//		ret= *bn;
//		BN_zero(ret);
//		}
//
//	/* i is the number of digests, a bit of an over expand; */
//	if (bn_expand(ret,i*4) == NULL) goto err;
//
//	j=BN_DEC_NUM-(i%BN_DEC_NUM);
//	if (j == BN_DEC_NUM) j=0;
//	l=0;
//	while (*a)
//		{
//		l*=10;
//		l+= *a-'0';
//		a++;
//		if (++j == BN_DEC_NUM)
//			{
//			BN_mul_word(ret,BN_DEC_CONV);
//			BN_add_word(ret,l);
//			l=0;
//			j=0;
//			}
//		}
//	ret->neg=neg;
//
//	bn_correct_top(ret);
//	*bn=ret;
//	bn_check_top(ret);
//	return(num);
//err:
//	if (*bn == NULL) BN_free(ret);
//	return(0);
//	}

//int BN_asc2bn(BIGNUM **bn, const char *a)
//	{
//	const char *p = a;
//	if (*p == '-')
//		p++;
//
//	if (p[0] == '0' && (p[1] == 'X' || p[1] == 'x'))
//		{
//		if (!BN_hex2bn(bn, p + 2))
//			return 0;
//		}
//	else
//		{
//		if (!BN_dec2bn(bn, p))
//			return 0;
//		}
//	if (*a == '-')
//		(*bn)->neg = 1;
//	return 1;
//	}

//#ifndef OPENSSL_NO_BIO
//
//
//int BN_print(BIO *bp, const BIGNUM *a)
//	{
//	int i,j,v,z=0;
//	int ret=0;
//
//	if ((a->neg) && (BIO_write(bp,"-",1) != 1)) goto end;
//	if (BN_is_zero(a) && (BIO_write(bp,"0",1) != 1)) goto end;
//	for (i=a->top-1; i >=0; i--)
//		{
//		for (j=BN_BITS2-4; j >= 0; j-=4)
//			{
//			/* strip leading zeros */
//			v=((int)(a->d[i]>>(long)j))&0x0f;
//			if (z || (v != 0))
//				{
//				if (BIO_write(bp,&(Hex[v]),1) != 1)
//					goto end;
//				z=1;
//				}
//			}
//		}
//	ret=1;
//end:
//	return(ret);
//	}
//#endif

//char *BN_options(void)
//	{
//	static int init=0;
//	static char data[16];
//
//	if (!init)
//		{
//		init++;
//#ifdef BN_LLONG
//		BIO_snprintf(data,sizeof data,"bn(%d,%d)",
//			     (int)sizeof(BN_ULLONG)*8,(int)sizeof(BN_ULONG)*8);
//#else
//		BIO_snprintf(data,sizeof data,"bn(%d,%d)",
//			     (int)sizeof(BN_ULONG)*8,(int)sizeof(BN_ULONG)*8);
//#endif
//		}
//	return(data);
//	}
/* crypto/bn/bn_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


void BN_free(BIGNUM *a)
	{
	if (a == NULL) return;
	bn_check_top(a);
	if ((a->d != NULL) && !(BN_get_flags(a,BN_FLG_STATIC_DATA)))
		OPENSSL_free(a->d);
	if (a->flags & BN_FLG_MALLOCED)
		OPENSSL_free(a);
	else
		{
		a->d = NULL;
		}
	}

BIGNUM *BN_dup(const BIGNUM *a)
	{
	BIGNUM *t;

	if (a == NULL) return NULL;
	bn_check_top(a);

	t = BN_new();
	if (t == NULL) return NULL;
	if(!BN_copy(t, a))
		{
		BN_free(t);
		return NULL;
		}
	bn_check_top(t);
	return t;
	}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
	{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;

	bn_check_top(b);

	if (a == b) return(a);
	if (bn_wexpand(a,b->top) == NULL) return(NULL);

#if 1
	A=a->d;
	B=b->d;
	for (i=b->top>>2; i>0; i--,A+=4,B+=4)
		{
		BN_ULONG a0,a1,a2,a3;
		a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
		A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
		}
	switch (b->top&3)
		{
		case 3: A[2]=B[2];
		case 2: A[1]=B[1];
		case 1: A[0]=B[0];
		case 0: ; /* ultrix cc workaround, see comments in bn_expand_internal */
		}
#else
	memcpy(a->d,b->d,sizeof(b->d[0])*b->top);
#endif

	a->top=b->top;
	a->neg=b->neg;
	bn_check_top(a);
	return(a);
	}

int BN_set_word(BIGNUM *a, BN_ULONG w)
	{
	bn_check_top(a);
	if (bn_expand(a,(int)sizeof(BN_ULONG)*8) == NULL) return(0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	bn_check_top(a);
	return(1);
	}

void BN_set_negative(BIGNUM *a, int b)
	{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
	}
/* crypto/bn/bn_asm.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



//#if defined(BN_LLONG) || defined(BN_UMULT_HIGH)
//
//BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c1=0;
//
//	assert(num >= 0);
//	if (num <= 0) return(c1);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul_add(rp[0],ap[0],w,c1);
//		mul_add(rp[1],ap[1],w,c1);
//		mul_add(rp[2],ap[2],w,c1);
//		mul_add(rp[3],ap[3],w,c1);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul_add(rp[0],ap[0],w,c1);
//		ap++; rp++; num--;
//		}
//
//	return(c1);
//	}
//
//BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c1=0;
//
//	assert(num >= 0);
//	if (num <= 0) return(c1);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul(rp[0],ap[0],w,c1);
//		mul(rp[1],ap[1],w,c1);
//		mul(rp[2],ap[2],w,c1);
//		mul(rp[3],ap[3],w,c1);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul(rp[0],ap[0],w,c1);
//		ap++; rp++; num--;
//		}
//	return(c1);
//	}
//
//void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
//        {
//	assert(n >= 0);
//	if (n <= 0) return;
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (n&~3)
//		{
//		sqr(r[0],r[1],a[0]);
//		sqr(r[2],r[3],a[1]);
//		sqr(r[4],r[5],a[2]);
//		sqr(r[6],r[7],a[3]);
//		a+=4; r+=8; n-=4;
//		}
//#endif
//	while (n)
//		{
//		sqr(r[0],r[1],a[0]);
//		a++; r+=2; n--;
//		}
//	}
//
//#else /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
//
//BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c=0;
//	BN_ULONG bl,bh;
//
//	assert(num >= 0);
//	if (num <= 0) return((BN_ULONG)0);
//
//	bl=LBITS(w);
//	bh=HBITS(w);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul_add(rp[0],ap[0],bl,bh,c);
//		mul_add(rp[1],ap[1],bl,bh,c);
//		mul_add(rp[2],ap[2],bl,bh,c);
//		mul_add(rp[3],ap[3],bl,bh,c);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul_add(rp[0],ap[0],bl,bh,c);
//		ap++; rp++; num--;
//		}
//	return(c);
//	}
//
//BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG carry=0;
//	BN_ULONG bl,bh;
//
//	assert(num >= 0);
//	if (num <= 0) return((BN_ULONG)0);
//
//	bl=LBITS(w);
//	bh=HBITS(w);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul(rp[0],ap[0],bl,bh,carry);
//		mul(rp[1],ap[1],bl,bh,carry);
//		mul(rp[2],ap[2],bl,bh,carry);
//		mul(rp[3],ap[3],bl,bh,carry);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul(rp[0],ap[0],bl,bh,carry);
//		ap++; rp++; num--;
//		}
//	return(carry);
//	}
//
//void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
//        {
//	assert(n >= 0);
//	if (n <= 0) return;
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (n&~3)
//		{
//		sqr64(r[0],r[1],a[0]);
//		sqr64(r[2],r[3],a[1]);
//		sqr64(r[4],r[5],a[2]);
//		sqr64(r[6],r[7],a[3]);
//		a+=4; r+=8; n-=4;
//		}
//#endif
//	while (n)
//		{
//		sqr64(r[0],r[1],a[0]);
//		a++; r+=2; n--;
//		}
//	}
//
//#endif /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
//
//
///* Divide h,l by d and return the result. */
///* I need to test this some more :-( */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
	{
	BN_ULONG dh,dl,q,ret=0,th,tl,t;
	int i,count=2;

	if (d == 0) return(BN_MASK2);

	i=BN_num_bits_word(d);
	assert((i == BN_BITS2) || (h <= (BN_ULONG)1<<i));

	i=BN_BITS2-i;
	if (h >= d) h-=d;

	if (i)
		{
		d<<=i;
		h=(h<<i)|(l>>(BN_BITS2-i));
		l<<=i;
		}
	dh=(d&BN_MASK2h)>>BN_BITS4;
	dl=(d&BN_MASK2l);
	for (;;)
		{
		if ((h>>BN_BITS4) == dh)
			q=BN_MASK2l;
		else
			q=h/dh;

		th=q*dh;
		tl=dl*q;
		for (;;)
			{
			t=h-th;
			if ((t&BN_MASK2h) ||
				((tl) <= (
					(t<<BN_BITS4)|
					((l&BN_MASK2h)>>BN_BITS4))))
				break;
			q--;
			th-=dh;
			tl-=dl;
			}
		t=(tl>>BN_BITS4);
		tl=(tl<<BN_BITS4)&BN_MASK2h;
		th+=t;

		if (l < tl) th++;
		l-=tl;
		if (h < th)
			{
			h+=d;
			q--;
			}
		h-=th;

		if (--count == 0) break;

		ret=q<<BN_BITS4;
		h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
		l=(l&BN_MASK2l)<<BN_BITS4;
		}
	ret|=q;
	return(ret);
	}


/*
**********************************************************************************************************************
*											        eGon
*						           the Embedded GO-ON Bootloader System
*									       eGON arm boot sub-system
*
*						  Copyright(C), 2006-2014, Allwinner Technology Co., Ltd.
*                                           All Rights Reserved
*
* File    :
*
* By      : Jerry
*
* Version : V2.00
*
* Date	  :
*
* Descript:
**********************************************************************************************************************
*/

int sunxi_bytes_merge(u8 *dst, u32 dst_len, u8 *src, uint src_len);
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static int __asn1_probe_data_head(u8 *buf, sunxi_asn1_t *asn1)
{
	u8 *tmp_buf = buf;
	int index;
	int len, len_bytes;

	asn1->head     = tmp_buf[0];
	asn1->head_len = 2;
	//获取长度
	len = tmp_buf[1];
	if(len & 0x80)		//超过1个字节表示长度
	{
		len_bytes = len & 0x7f;
		if((!len_bytes) || (len_bytes>4))
		{
			printf("len_bytes(%d) is 0 or larger than 4, cant be probe\n", len_bytes);

			return -1;
		}
		asn1->head_len += len_bytes;
		index = 2;
		len = 0;
		while(--len_bytes);
		{
			len += tmp_buf[index++];
			len *= 256;
		}
		len |= tmp_buf[index];

	}
	asn1->data = buf + asn1->head_len;
	asn1->data_len = len;

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static  int __sunxi_publickey_dipatch(sunxi_key_t *pkey, u8 *buf, u32 len)
{
	u8 *tmp_buf = buf;
	int ret;
	sunxi_asn1_t asn1;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("publickey_dipatch err: head is not a sequence\n");

		return -1;
	}
	tmp_buf += asn1.head_len;		//跳过sequnce头部
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if((ret) || (asn1.head != 0x2))	//
	{
		printf("publickey_dipatch err: step 2\n");

		return -2;
	}
	pkey->n = malloc(asn1.data_len);
	memcpy(pkey->n, asn1.data, asn1.data_len);
	pkey->n_len = asn1.data_len;

	tmp_buf = asn1.data + asn1.data_len;
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if((ret) || (asn1.head != 0x2))
	{
		printf("publickey_dipatch err: step 3\n");

		return -3;
	}

	pkey->e = malloc(asn1.data_len);
	memcpy(pkey->e, asn1.data, asn1.data_len);
	pkey->e_len = asn1.data_len;

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static int __certif_probe_signdata(u8 *dst_buf, u32 dst_len_max, u8 *src_buf, u32 src_len)
{
	u8 *tmp_buf = src_buf;
	int ret;
	sunxi_asn1_t asn1;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("certif_decode err: head is not a sequence\n");

		return -1;
	}
	tmp_buf += asn1.head_len;		//跳过sequnce头部
	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret)
	{
		printf("certif_decode err: step 1\n");

		return -2;
	}

	if(asn1.data_len > dst_len_max)
	{
		printf("sign data len (0x%x) is longer then buffer size (0x%x)\n", asn1.data_len, dst_len_max);

		return -1;
	}
	memcpy(dst_buf, tmp_buf, asn1.data_len + asn1.head_len);

	return asn1.data_len + asn1.head_len;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
static uint __merge_extension_value(u8 **dst_buf, u8 *src_buf, uint src_buf_len)
{
	u8 *tmp_buf = src_buf;
	sunxi_asn1_t asn1;
	int ret;
	uint tmp_len;

	ret = __asn1_probe_data_head(tmp_buf, &asn1);
	if(ret < 0)	//
	{
		printf("__merge_extension_value err: head is not a sequence\n");

		return 0;
	}

	if(asn1.data_len + asn1.head_len > src_buf_len)
	{
		printf("__merge_extension_value err: the data source len is too short\n");

		return 0;
	}
	*dst_buf = malloc((asn1.data_len + 1)/2);
	memset(*dst_buf, 0, (asn1.data_len + 1)/2);
	tmp_len = asn1.data_len;
	if(tmp_len > 512)		//rsakey
	{
		u8 *src = asn1.data;
		if((src[0] == '0') && (src[1] == '0'))
		{
			src += 2;
		}
		if(sunxi_bytes_merge(*dst_buf, asn1.data_len, src, 512))
		{
			printf("__merge_extension_value err1: in sunxi_bytes_merge\n");

			return 0;
		}
		if(sunxi_bytes_merge(*dst_buf + 512/2, asn1.data_len, src + 512, asn1.data_len - 512 - (src-asn1.data)))
		{
			printf("__merge_extension_value err2: in sunxi_bytes_merge\n");

			return 0;
		}
	}
	else
	{
		if(sunxi_bytes_merge(*dst_buf, asn1.data_len, asn1.data, asn1.data_len))
		{
			printf("__merge_extension_value err1: in sunxi_bytes_merge\n");

			return 0;
		}
	}

	//memcpy(*dst_buf, asn1.data, asn1.data_len);

	return (asn1.data_len + 1)/2;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_create(X509 **certif, u8 *buf, int len)
{
	u8 *p = buf;

	*certif = d2i_X509(NULL, (const unsigned char **)&p, len);
	if(*certif == NULL)
	{
		printf("x509_create: cant get a certif\n");

		return -1;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_free(X509 *certif)
{
	if(certif)
	{
		X509_free(certif);
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_serial_num(X509 *x)
{
	ASN1_INTEGER *bs = NULL;
	long serial_num = 0;

	bs = X509_get_serialNumber(x);
	if(bs->length <= 4)
	{
		serial_num = ASN1_INTEGER_get(bs);
		printf("SERIANL NUMBER: 0x%x\n", (unsigned int)serial_num);
	}
	else
	{
		printf("SERIANL NUMBER: Unknown\n");
	}

	return 0 ;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_version(X509 *x)
{
	long version = 0;

	version = X509_get_version(x);
	printf("Version: 0x%0x\n", (unsigned int)version);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
#define BUFF_NAME_MAX  128
#define BUFF_VALUE_MAX  3072

int sunxi_certif_probe_extension(X509 *x, sunxi_certif_info_t *sunxi_certif)
{
	int extension_count = X509_get_ext_count(x);
	X509_EXTENSION *extension;
	int i, len;
	ASN1_OBJECT *obj;
	u8 buff_name[BUFF_NAME_MAX];
	u8 buff_value[BUFF_VALUE_MAX];

	//printf("extension_count=%d\n", extension_count);
	sunxi_certif->extension.extension_num = extension_count;

	for(i = 0; i < extension_count; i++)
	{
		//printf("************%d***************\n", i);
		//printf("extension name:\n");
		extension=sk_X509_EXTENSION_value(x->cert_info->extensions, i);
		if(!extension)
		{
			printf("get extersion %d fail\n", i);

			return -1;
		}
		obj = X509_EXTENSION_get_object(extension);
		if(!obj)
		{
			printf("get extersion obj %d fail\n", i);

			return -1;
		}
		memset(buff_name, 0, BUFF_NAME_MAX);
		//while((*(volatile int *)0)!=12);
		//len = OBJ_obj2txt(buff_name, BUFF_NAME_MAX, obj, 0);
		len = OBJ_obj2name((char *)buff_name, BUFF_NAME_MAX, obj);
		if(!len)
		{
			printf("extersion %d name length is 0\n", i);
		}
		else
		{
			//printf("name len=%d\n", len);
			sunxi_certif->extension.name[i] = malloc(len + 1);
			memcpy(sunxi_certif->extension.name[i], buff_name, len);
			sunxi_certif->extension.name[i][len] = '\0';
			sunxi_certif->extension.name_len[i] = len;

			//xdump(sunxi_certif->extension.name[i], len);
		}

		memset(buff_value,0,BUFF_NAME_MAX);
		len = ASN1_STRING_mem((char *)buff_value, extension->value);
		if(!len)
		{
			printf("extersion %d value length is 0\n", i);
		}
		else
		{
			//xdump(buff_value, len);
			len = __merge_extension_value(&sunxi_certif->extension.value[i], buff_value, len);
			if(!len)
			{
				printf("get extension value failed\n");

				return -1;
			}
			sunxi_certif->extension.value_len[i] = len;
			//printf("value len=%d\n", len);

			//ndump(sunxi_certif->extension.value[i], len);
		}
		//printf("<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>\n");
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_pubkey(X509 *x, sunxi_key_t *pubkey)
{
	EVP_PKEY *pkey = NULL;
	int keylen;
	char *buff_tmp;
//	int  sig_nid;
	u8  keybuff[512];

	pkey = X509_get_pubkey(x);
	if (pkey == NULL)
	{
		printf("cant find the public key %s %d\n", __FILE__, __LINE__);

		return -1;
	}
//	if(pkey->type == 6)
//	{
//		printf("it is rsaEncryption\n");
//	}
//	else
//	{
//		printf("unknown encryption\n");
//
//		//return -1;
//	}
//	sig_nid = OBJ_obj2nid(x->sig_alg->algorithm);
	memset(keybuff, 0, 512);
	buff_tmp = (char *)keybuff;
	keylen = i2d_PublicKey(pkey, (unsigned char **)&buff_tmp);
	if(keylen <= 0)
	{
		printf("The public key is invalid\n");

		return -1;
	}
	if(__sunxi_publickey_dipatch(pubkey, keybuff, keylen))
	{
		printf("get public failed\n");

		return -1;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
void sunxi_certif_mem_reset(void)
{
	reset_OBJ_nid2ln_reset();
	reset_CRYPTO_reset();
	reset_BIO_reset();
	reset_D2I_reset();
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_signature(X509 *x, u8 *sign)
{
	memcpy(sign, x->signature->data, x->signature->length);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_verify_itself(sunxi_certif_info_t *sunxi_certif, u8 *buf, u32 len)
{
	X509 *certif;
	int  ret;
	u8   hash_of_certif[256];
	u8   hash_of_sign[256];

	u8   sign_in_certif[256];
	u8   *p_sign_to_calc;
	u32  sign_src_len;

	//内存初始化
	sunxi_certif_mem_reset();
	//创建证书
	ret = sunxi_certif_create(&certif, buf, len);
	if(ret < 0)
	{
		printf("fail to create a certif\n");

		return -1;
	}
	//获取证书公钥
	ret = sunxi_certif_probe_pubkey(certif, &sunxi_certif->pubkey);
	if(ret)
	{
		printf("fail to probe the public key\n");

		return -1;
	}
	//获取证书签名
	ret = sunxi_certif_probe_signature(certif, sign_in_certif);
	if(ret)
	{
		printf("fail to probe the sign value\n");

		return -1;
	}
	//获取需要签名内容
	//计算sha256时，必须保证内存起始位置16字节对齐，这里采取了32字节对齐
	p_sign_to_calc = malloc(4096);		//证书中待签名内容肯定不超过4k
	//获取待签名内容
	memset(p_sign_to_calc, 0, 4096);
	sign_src_len = __certif_probe_signdata(p_sign_to_calc, 4096, buf, len);
	if(sign_src_len <= 0)
	{
		printf("certif_probe_signdata err\n");

		return -1;
	}
	//计算待签名内容的hash
	memset(hash_of_certif, 0, sizeof(hash_of_certif));
	ret = sunxi_sha_calc(hash_of_certif, sizeof(hash_of_certif), p_sign_to_calc, sign_src_len);
	if(ret)
	{
		printf("sunxi_sha_calc: calc sha256 with hardware err\n");

		return -1;
	}
	//计算证书中签名的rsa
	memset(hash_of_sign, 0, sizeof(hash_of_sign));
	ret = sunxi_rsa_calc(sunxi_certif->pubkey.n+1, sunxi_certif->pubkey.n_len-1,
	                     sunxi_certif->pubkey.e, sunxi_certif->pubkey.e_len,
	                     hash_of_sign,           sizeof(hash_of_sign),
	                     sign_in_certif,         sizeof(sign_in_certif));
	if(ret)
	{
		printf("sunxi_rsa_calc: calc rsa2048 with hardware err\n");

		return -1;
	}
//	printf(">>>>>>>>>>>>>>hash_of_certif\n");
//	ndump(hash_of_certif, 32);
//	printf("<<<<<<<<<<<<<<\n");
//	printf(">>>>>>>>>>>>>>hash_of_sign\n");
//	ndump(hash_of_sign, 32);
//	printf("<<<<<<<<<<<<<<\n");
	if(memcmp(hash_of_certif, hash_of_sign, 32))
	{
		printf("certif verify failed\n");

		return -1;
	}
	ret = sunxi_certif_probe_extension(certif, sunxi_certif);
	if(ret)
	{
		printf("sunxi_rsa_calc: probe extension failed\n");

		return -1;
	}

	sunxi_certif_free(certif);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_probe_ext(sunxi_certif_info_t *sunxi_certif, u8 *buf, u32 len)
{
	X509 *certif;
	int  ret;
	//内存初始化
	sunxi_certif_mem_reset();
	//创建证书
	ret = sunxi_certif_create(&certif, buf, len);
	if(ret < 0)
	{
		printf("fail to create a certif\n");

		return -1;
	}
	ret = sunxi_certif_probe_extension(certif, sunxi_certif);
	if(ret)
	{
		printf("sunxi_rsa_calc: probe extension failed\n");

		return -1;
	}
	sunxi_certif_free(certif);

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :
*
*    return        :
*
*    note          :  对于一个序列，按照高4+低4,合并成为一个新的字节，比如
*                     0x41(A) 0x31(1)  合并成为0xa1
*
************************************************************************************************************
*/
static int __sample_atoi(u8 ch, u8 *dst)
{
	u8 ret_c;

	if(isdigit(ch))
		ret_c = ch - '0';
	else if(isupper(ch))
		ret_c = ch - 'A' + 10;
	else if(islower(ch))
		ret_c = ch - 'a' + 10;
	else
	{
		printf("sample_atoi err: ch 0x%02x is not a digit or hex ch\n", ch);
		return -1;
	}
	*dst = ret_c;

	return 0;
}

int sunxi_bytes_merge(u8 *dst, u32 dst_len, u8 *src, uint src_len)
{
	int i=0, j;
	u8  c_h, c_l;

	if((src_len>>1) > dst_len)
	{
		printf("bytes merge failed, the dst buffer is too short\n");

		return -1;
	}
	if(src_len & 0x01)		//奇数
	{
		src_len --;
		if(__sample_atoi(src[i], &dst[0]))
		{
			return -1;
		}
		i++;
	}

	for(j=i;i<src_len;i+=2, j++)
	{
		c_h = src[i];
		c_l = src[i+1];

		if(__sample_atoi(src[i], &c_h))
		{
			return -1;
		}

		if(__sample_atoi(src[i+1], &c_l))
		{
			return -1;
		}
		dst[j] = (c_h << 4) | c_l;
	}

	return 0;
}
/*
************************************************************************************************************
*
*                                             function
*
*    name          :
*
*    parmeters     :  buf: 证书存放起始   len：数据长度
*
*    return        :
*
*    note          :  证书自校验
*
*
************************************************************************************************************
*/
int sunxi_certif_dump(sunxi_certif_info_t *sunxi_certif)
{
	return 0;
}


/////////////////X509_CINF_IT////////////////////////////////

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
//	ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
	ASN1_SIMPLE(X509_CINF, serialNumber, ASN1_INTEGER),//
	ASN1_SIMPLE(X509_CINF, signature, X509_ALGOR),//
//	ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
//	ASN1_SIMPLE(X509_CINF, validity, X509_VAL),
//	ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
	ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),//
//	ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
//	ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)//
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

//IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)



static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	X509 *ret = (X509 *)*pval;
		
	switch(operation) {

		case ASN1_OP_NEW_POST:
		ret->valid=0;
		ret->name = NULL;
		ret->ex_flags = 0;
		ret->ex_pathlen = -1;
		ret->skid = NULL;
		ret->akid = NULL;
		ret->aux = NULL;
		CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
		break;

		case ASN1_OP_FREE_POST:
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);

		break;

	}

	return 1;

}

ASN1_SEQUENCE_ref(X509, x509_cb, CRYPTO_LOCK_X509) = {
	ASN1_SIMPLE(X509, cert_info, X509_CINF),
	ASN1_SIMPLE(X509, sig_alg, X509_ALGOR),
	ASN1_SIMPLE(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)

IMPLEMENT_ASN1_FUNCTIONS(X509)


static int pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	if (operation == ASN1_OP_FREE_POST)
		{
		X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
		EVP_PKEY_free(pubkey->pkey);
		}
	return 1;
	}

/////////////////X509_PUBKEY_it//////////////////////////////

ASN1_SEQUENCE_cb(X509_PUBKEY, pubkey_cb) = {
	ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
	ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_cb(X509_PUBKEY, X509_PUBKEY)
	
IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY)




//////////EVP_PKEY_type//////////////////////ok

int EVP_PKEY_type(int type)
{

	switch (type)
		{
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA2:
		return(EVP_PKEY_RSA);
	case EVP_PKEY_DSA:
	case EVP_PKEY_DSA1:
	case EVP_PKEY_DSA2:
	case EVP_PKEY_DSA3:
	case EVP_PKEY_DSA4:
		return(EVP_PKEY_DSA);
	case EVP_PKEY_DH:
		return(EVP_PKEY_DH);
	case EVP_PKEY_EC:
		return(EVP_PKEY_EC);
	default:
		return(NID_undef);
		}
}

///////////////EVP_PKEY_new/////////////////////////////ok

EVP_PKEY *EVP_PKEY_new(void)
{
	EVP_PKEY *ret;

	ret=(EVP_PKEY *)OPENSSL_malloc(sizeof(EVP_PKEY));
	if (ret == NULL)
		{
		//EVPerr(EVP_F_EVP_PKEY_NEW,ERR_R_MALLOC_FAILURE);//samyang modify
		return(NULL);
		}
	ret->type=EVP_PKEY_NONE;
	ret->references=1;
	ret->pkey.ptr=NULL;
	ret->attributes=NULL;
	ret->save_parameters=1;
	return(ret);
}
///////////////X509_PUBKEY_get////////////////////////ok

EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key)
{

	EVP_PKEY *ret=NULL;
	long j;
	int type;
	const unsigned char *p;

	if (key == NULL) goto err;

	if (key->pkey != NULL)
		{
		CRYPTO_add(&key->pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		return(key->pkey);
		}

	if (key->public_key == NULL) goto err;

	type=OBJ_obj2nid(key->algor->algorithm);
	if ((ret = EVP_PKEY_new()) == NULL)
		{
		//X509err(X509_F_X509_PUBKEY_GET, ERR_R_MALLOC_FAILURE);//samyang modify
		goto err;
		}
	ret->type = EVP_PKEY_type(type);



#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_ECDSA)
	//a=key->algor;
#endif

	p=key->public_key->data;
        j=key->public_key->length;
        if (!d2i_PublicKey(type, &ret, &p, (long)j))
		{
		//X509err(X509_F_X509_PUBKEY_GET, X509_R_ERR_ASN1_LIB);//samyang modify
		goto err;
		}

	key->pkey = ret;
	CRYPTO_add(&ret->references, 1, CRYPTO_LOCK_EVP_PKEY);
	return(ret);
err:
	if (ret != NULL)
		EVP_PKEY_free(ret);
	return(NULL);

}

//////////////////X509_get_pubkey/////////////ok

EVP_PKEY *X509_get_pubkey(X509 *x)
{

	if ((x == NULL) || (x->cert_info == NULL))
		return(NULL);
	return(X509_PUBKEY_get(x->cert_info->key));
}



////////////EVP_PKEY_free/////////////////////ok

void EVP_PKEY_free(EVP_PKEY *x)
{
	int i;
	if (x == NULL) return;
	i=CRYPTO_add(&x->references,-1,CRYPTO_LOCK_EVP_PKEY);
	if (i > 0) return;

	}

/////////////////X509_EXTENSION_it///////////////////////////

ASN1_SEQUENCE(X509_EXTENSION) = {
	ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
	ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
	ASN1_SIMPLE(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION);
	
//////////////X509_ALGOR_it/////////////////////////////////

ASN1_SEQUENCE(X509_ALGOR) = {
	ASN1_SIMPLE(X509_ALGOR, algorithm, ASN1_OBJECT),
	ASN1_OPT(X509_ALGOR, parameter, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ALGOR)

#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)


///////////////////////asn1_get_enc_ptr//////////////////////ok

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	const ASN1_AUX *aux;
	
	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
	}

//////////////////asn1_enc_free//////////////////////////////ok

void asn1_enc_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		if (enc->enc)
			OPENSSL_free(enc->enc);
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}


///////////////asn1_enc_restore/////////////////////////////////////////ok

int asn1_enc_restore(int *len, unsigned char **out, ASN1_VALUE **pval,
							const ASN1_ITEM *it)
{
	ASN1_ENCODING *enc;
	
	enc = asn1_get_enc_ptr(pval, it);
	if (!enc || enc->modified)
		return 0;
	if (out)
		{
		memcpy(*out, enc->enc, enc->len);
		*out += enc->len;
		}
	if (len)
		*len = enc->len;
	return 1;
}


#define MSTRING		0
#define COMPAT		0

#define ASN1_MAX_STRING_NEST 5
#define asn1_tlc_clear(c)	if (c) (c)->valid = 0
int k=0;

void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine);

static int asn1_check_eoc(const unsigned char **in, long len);
static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
				char *inf, char *cst,
				const unsigned char **in, long len,
				int exptag, int expclass, char opt,
				ASN1_TLC *ctx);
static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
				const unsigned char **in, long len,
				const ASN1_ITEM *it,
				int tag, int aclass, char opt, ASN1_TLC *ctx);

static int asn1_template_ex_d2i(ASN1_VALUE **pval,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx);
static int asn1_template_noexp_d2i(ASN1_VALUE **val,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx);


///////////////////xx_it//////////////////////////////////////

IMPLEMENT_ASN1_TYPE(ASN1_INTEGER)
IMPLEMENT_ASN1_TYPE(ASN1_OBJECT)
IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING)
IMPLEMENT_ASN1_TYPE(ASN1_ANY)
IMPLEMENT_ASN1_TYPE(ASN1_BIT_STRING)
IMPLEMENT_ASN1_TYPE(ASN1_IA5STRING)
IMPLEMENT_ASN1_TYPE_ex(ASN1_BOOLEAN, ASN1_BOOLEAN, -1)


IMPLEMENT_ASN1_FUNCTIONS_fname(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)


///////////////////ASN1_item_d2i(i2d_rsapubliy)//////////////////////////////

ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **pval,
		const unsigned char **in, long len, const ASN1_ITEM *it)
	{
	ASN1_TLC c;
	ASN1_VALUE *ptmpval = NULL;
	if (!pval)
		pval = &ptmpval;
	c.valid = 0;
	if (ASN1_item_ex_d2i(pval, in, len, it, -1, 0, 0, &c) > 0)
		return *pval;
	return NULL;
	}

////////////////ASN1_item_ex_d2i/////////////////////////////

int ASN1_item_ex_d2i(ASN1_VALUE **pval, const unsigned char **in, long len,
			const ASN1_ITEM *it,
			int tag, int aclass, char opt, ASN1_TLC *ctx)
	{
	const ASN1_TEMPLATE *tt;
//	const ASN1_TEMPLATE *errtt = NULL;
//	const ASN1_COMPAT_FUNCS *cf;
//	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;//--YXY X509_aux
	ASN1_aux_cb *asn1_cb;
	const unsigned char *p = NULL, *q;
//	unsigned char *wp=NULL;	/* BIG FAT WARNING!  BREAKS CONST WHERE USED */
//	unsigned char imphack = 0;
//	unsigned char oclass;
	char seq_eoc, seq_nolen, cst, isopt;
	long tmplen;
	int i;
//	int otag;
	int ret = 0;
	int j=0,leng=0;//--YXY add
	const unsigned char cinf[][13]={"cert_info","version","serialNumber","signature","algorithm","parameter","isure","vald","suject","key","algor","algorithm","parameter","public_key","extensions"};
	//ASN1_VALUE **pchptr, *ptmpval;
	if (!pval)
		return 0;
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;
	else asn1_cb = 0;

	switch(it->itype)
		{
		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			{

			if ((tag != -1) || opt)
				{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);

				}
			return asn1_template_ex_d2i(pval, in, len,
					it->templates, opt, ctx);
		}
		return asn1_d2i_ex_primitive(pval, in, len, it,	//////////////INTERGER
						tag, aclass, opt, ctx);
		break;
#if	MSTRING
		case ASN1_ITYPE_MSTRING:
		p = *in;

		ret = asn1_check_tlen(NULL, &otag, &oclass, NULL, NULL,
						&p, len, -1, 0, 1, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			}


		if (oclass != V_ASN1_UNIVERSAL)
			{
				if (opt){
					return -1;
				}else{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_MSTRING_NOT_UNIVERSAL);
				}
			}

		return asn1_d2i_ex_primitive(pval, in, len,
						it, otag, 0, 0, ctx);

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		return ef->asn1_ex_d2i(pval, in, len,
						it, tag, aclass, opt, ctx);//??????
#endif
#if COMPAT
		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (opt)
			{
			int exptag;
			p = *in;
			if (tag == -1)
				exptag = it->utype;
			else exptag = tag;


			ret = asn1_check_tlen(NULL, NULL, NULL, NULL, NULL,
					&p, len, exptag, aclass, 1, ctx);
			if (!ret)
				{
				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				}
			if (ret == -1)
				return -1;
			}

		if (tag != -1)
			{
			wp = *(unsigned char **)in;
			imphack = *wp;
			if (p == NULL)
				{

				ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				}
			*wp = (unsigned char)((*p & V_ASN1_CONSTRUCTED)
								| it->utype);
			}

		ptmpval = cf->asn1_d2i(pval, in, len);

		if (tag != -1)
			*wp = imphack;

		if (ptmpval){
			return 1;
		}else{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ERR_R_NESTED_ASN1_ERROR);
		}


		case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it))
				goto auxerr;

		// Allocate structure
		if (!*pval && !ASN1_item_ex_new(pval, it))
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			}

		p = *in;
		for (i = 0, tt=it->templates; i < it->tcount; i++, tt++)
			{
			pchptr = asn1_get_field_ptr(pval, tt);
			ret = asn1_template_ex_d2i(pchptr, &p, len, tt, 1, ctx);

			if (ret == -1)
				continue;

			if (ret > 0)
				break;

			//errtt = tt;
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
						ERR_R_NESTED_ASN1_ERROR);

			}


		if (i == it->tcount)
			{

			if (opt)
				{
				//ASN1_item_ex_free(pval, it);
				return -1;
				}

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_NO_MATCHING_CHOICE_TYPE);

			}

		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it))
				goto auxerr;
		return 1;
#endif
		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		p = *in;
		tmplen = len;

		if (tag == -1)
			{
			tag = V_ASN1_SEQUENCE;//16,sequence
			aclass = V_ASN1_UNIVERSAL;
			}

		ret = asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
					&p, len, tag, aclass, opt, ctx);//1
		if (!ret)
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			}
		else if (ret == -1)
			return -1;
		if (aux && (aux->flags & ASN1_AFLG_BROKEN))
			{
			len = tmplen - (p - *in);
			seq_nolen = 1;
			}

		else seq_nolen = seq_eoc;
		if (!cst)
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ASN1_R_SEQUENCE_NOT_CONSTRUCTED);
			}

		if (!*pval && !ASN1_item_ex_new(pval, it))//--YXY	根据it创建一个新的item
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
				ERR_R_NESTED_ASN1_ERROR);
			}

		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_PRE, pval, it))
				goto auxerr;

/**************************************************************************************/

		for (i = 0, tt = it->templates; i < it->tcount; i++, tt++)//x509_CINF_seq_tt
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			pseqval = asn1_get_field_ptr(pval, seqtt);//获得x509_CINF_seq_tt子类型的偏移量
		//	printf("%s\n",seqtt->field_name);
	/*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*/
			q=p;
			leng=len;
			for(j=0+k;j<17;j++){
				if(k>14){
					break;
				}

				if(!strcmp((const char *)cinf[j],seqtt->field_name)){
						k++;
						break;
				}else{
						asn1_check_tlen(&len, NULL, NULL, &seq_eoc, &cst,
										&p, len, tag, aclass, opt, ctx);
						p=p+len;
						*in=p;
						len=leng-(p-q);
						k++;

				}

			}

	/*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*/
			if (!len)
				break;
			q = p;//证书的偏移地址###
			if (asn1_check_eoc(&p, len))//检查是否00开头
				{
				if (!seq_eoc)
					{

					ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
							ASN1_R_UNEXPECTED_EOC);
					}
				len -= p - q;
				seq_eoc = 0;
				q = p;
				break;
				}

			if (i == (it->tcount - 1))
				isopt = 0;//=0
			else isopt = (char)(seqtt->flags & ASN1_TFLG_OPTIONAL);//differrn

			ret = asn1_template_ex_d2i(pseqval, &p, len,		//这里开始对子template，进行转化
							seqtt, isopt, ctx);
			if (!ret)
				{
				//errtt = seqtt;
				}
			else if (ret == -1)
				{

				ASN1_template_free(pseqval, seqtt);
				continue;
				}
			/* Update length */
			len -= p - q;//###
			}

		if (seq_eoc && !asn1_check_eoc(&p, len))
			{
			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_MISSING_EOC);

			}
		/* Check all data read */
		if (!seq_nolen && len)
			{

			ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
					ASN1_R_SEQUENCE_LENGTH_MISMATCH);		///	while(1);

			}


		for (; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (seqtt->flags & ASN1_TFLG_OPTIONAL)
				{
				ASN1_VALUE **pseqval;
				pseqval = asn1_get_field_ptr(pval, seqtt);
				ASN1_template_free(pseqval, seqtt);
				}
			else
				{
				//errtt = seqtt;
				 ASN1err(ASN1_F_ASN1_ITEM_EX_D2I,
							ASN1_R_FIELD_MISSING);

				}
			}
		/* Save encoding */
		if (!asn1_enc_save(pval, *in, p - *in, it))
			goto auxerr;
		*in = p;
		if (asn1_cb && !asn1_cb(ASN1_OP_D2I_POST, pval, it))
				goto auxerr;
		return 1;

		default:
		return 0;
		}
	auxerr:
	;ASN1err(ASN1_F_ASN1_ITEM_EX_D2I, ASN1_R_AUX_ERROR);
	return 0;
	}

////////////////////asn1_check_eoc//////////////////////////////

static int asn1_check_eoc(const unsigned char **in, long len)
	{
	const unsigned char *p;
	if (len < 2) return 0;
	p = *in;
	if (!p[0] && !p[1])
		{
		*in += 2;
		return 1;
		}
	return 0;
	}
/////////////asn1_check_tlen///////////////////////

static int asn1_check_tlen(long *olen, int *otag, unsigned char *oclass,
				char *inf, char *cst,
				const unsigned char **in, long len,
				int exptag, int expclass, char opt,
				ASN1_TLC *ctx)
	{
	int i;
	int ptag, pclass;
	long plen;
	const unsigned char *p, *q;
	p = *in;
	q = p;

	if (ctx && ctx->valid)
		{
		i = ctx->ret;
		plen = ctx->plen;
		pclass = ctx->pclass;
		ptag = ctx->ptag;
		p += ctx->hdrlen;
		}
	else
		{
		i = ASN1_get_object(&p, &plen, &ptag, &pclass, len);//start
		if (ctx)
			{
			ctx->ret = i;//i是指什么结构类型
			ctx->plen = plen;
			ctx->pclass = pclass;
			ctx->ptag = ptag;
			ctx->hdrlen = p - q;//这里用了多少个字节即0x30,0x82,0x04,0x52,4个
			ctx->valid = 1;

			if (!(i & 0x81) && ((plen + ctx->hdrlen) > len))
				{
				ASN1err(ASN1_F_ASN1_CHECK_TLEN,
							ASN1_R_TOO_LONG);
				asn1_tlc_clear(ctx);
				return 0;
				}
			}
		}

	if (i & 0x80)
		{
		ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_BAD_OBJECT_HEADER);
		asn1_tlc_clear(ctx);
		return 0;
		}
	if (exptag >= 0)
		{
		if ((exptag != ptag) || (expclass != pclass))//different,ptag=0,expclass=128
			{

			if (opt) return -1;
			asn1_tlc_clear(ctx);
			ASN1err(ASN1_F_ASN1_CHECK_TLEN, ASN1_R_WRONG_TAG);
		//	return 1;
			}

		asn1_tlc_clear(ctx);
		}

	if (i & 1)
		plen = len - (p - q);

	if (inf)
		*inf = i & 1;

	if (cst)
		*cst = i & V_ASN1_CONSTRUCTED;

	if (olen)
		*olen = plen;

	if (oclass)
		*oclass = pclass;

	if (otag)
		*otag = ptag;

	*in = p;//证书的偏移地址

	return 1;
	}

///////////asn1_d2i_ex_primitive///////////////

static int asn1_d2i_ex_primitive(ASN1_VALUE **pval,
				const unsigned char **in, long inlen,
				const ASN1_ITEM *it,
				int tag, int aclass, char opt, ASN1_TLC *ctx)
	{
	int ret = 0, utype;
	long plen;
	char cst, inf, free_cont = 0;
	const unsigned char *p;
	BUF_MEM buf;
	const unsigned char *cont = NULL;
	long len;
	if (!pval)
		{
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_ILLEGAL_NULL);
		return 0; /* Should never happen */
		}

	if (it->itype == ASN1_ITYPE_MSTRING)
		{
		utype = tag;
		tag = -1;
		}
	else
		utype = it->utype;

	if (utype == V_ASN1_ANY)
		{
		/* If type is ANY need to figure out type from tag */
		unsigned char oclass;
		if (tag >= 0)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ASN1_R_ILLEGAL_TAGGED_ANY);
			return 0;
			}
		if (opt)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ASN1_R_ILLEGAL_OPTIONAL_ANY);
			return 0;
			}
		p = *in;
		ret = asn1_check_tlen(NULL, &utype, &oclass, NULL, NULL,
					&p, inlen, -1, 0, 0, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		if (oclass != V_ASN1_UNIVERSAL)
			utype = V_ASN1_OTHER;
		}
	if (tag == -1)
		{
		tag = utype;
		aclass = V_ASN1_UNIVERSAL;
		}
	p = *in;
	/* Check header */
	ret = asn1_check_tlen(&plen, NULL, NULL, &inf, &cst,	//CHECK INTERGER
				&p, inlen, tag, aclass, opt, ctx);
	if (!ret)
		{
		ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ERR_R_NESTED_ASN1_ERROR);
		return 0;
		}
	else if (ret == -1)
		return -1;
        ret = 0;

	if ((utype == V_ASN1_SEQUENCE)
		|| (utype == V_ASN1_SET) || (utype == V_ASN1_OTHER))
		{

		if (utype == V_ASN1_OTHER)
			{
			asn1_tlc_clear(ctx);
			}

		else if (!cst)
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
				ASN1_R_TYPE_NOT_CONSTRUCTED);
			return 0;
			}

		cont = *in;
		if (inf)
			{
			len = p - cont;
			}
		else
			{
			len = p - cont + plen;
			p += plen;
			buf.data = NULL;
			}
		}
	else if (cst)
		{
		buf.length = 0;
		buf.max = 0;
		buf.data = NULL;
		len = buf.length;
		/* Append a final null to string */
		if (!BUF_MEM_grow_clean(&buf, len + 1))
			{
			ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE,
						ERR_R_MALLOC_FAILURE);
			return 0;
			}
		buf.data[len] = 0;
		cont = (const unsigned char *)buf.data;
		free_cont = 1;
		}
	else
		{
		cont = p;		//INTERGER,0X42c5cc to 0x42c5cd
		len = plen;
		p += plen;		//这里是非sequece型，往后增加长度的
		}

	/* We now have content length and type: translate into a structure */
	if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))	//asn1 to interger
		goto err;

	*in = p;//转变之后地址会p=p+plen
	ret = 1;
	err:
	if (free_cont && buf.data) OPENSSL_free(buf.data);
	return ret;
	}

////////////asn1_template_noexp_d2i//////////////////////////

static int asn1_template_noexp_d2i(ASN1_VALUE **val,
				const unsigned char **in, long len,
				const ASN1_TEMPLATE *tt, char opt,
				ASN1_TLC *ctx)
	{
	int flags, aclass;
	int ret;
	const unsigned char *p, *q;
	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;
	q = p;

	if (flags & ASN1_TFLG_SK_MASK)
		{

		int sktag, skaclass;
		char sk_eoc;

		if (flags & ASN1_TFLG_IMPTAG)
			{
			sktag = tt->tag;
			skaclass = aclass;
			}
		else
			{
			skaclass = V_ASN1_UNIVERSAL;
			if (flags & ASN1_TFLG_SET_OF)
				sktag = V_ASN1_SET;
			else
				sktag = V_ASN1_SEQUENCE;
			}

		ret = asn1_check_tlen(&len, NULL, NULL, &sk_eoc, NULL,
					&p, len, sktag, skaclass, opt, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		else if (ret == -1)
			return -1;
		if (!*val)
			*val = (ASN1_VALUE *)sk_new_null();
		else
			{
				;
			}

		if (!*val)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_MALLOC_FAILURE);
			goto err;
			}


		while(len > 0)
			{
			ASN1_VALUE *skfield;
			q = p;

			if (asn1_check_eoc(&p, len))
				{
				if (!sk_eoc)
					{
					ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
							ASN1_R_UNEXPECTED_EOC);
					goto err;
					}
				len -= p - q;
				sk_eoc = 0;
				break;
				}
			skfield = NULL;
			if (!ASN1_item_ex_d2i(&skfield, &p, len,
						ASN1_ITEM_ptr(tt->item),
						-1, 0, 0, ctx))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
					ERR_R_NESTED_ASN1_ERROR);
				goto err;
				}
			len -= p - q;
			if (!sk_push((STACK *)*val, (char *)skfield))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_MALLOC_FAILURE);
				goto err;
				}
			}
		if (sk_eoc)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I, ASN1_R_MISSING_EOC);
			goto err;
			}
		}
	else if (flags & ASN1_TFLG_IMPTAG)
		{
		/* IMPLICIT tagging */
		ret = ASN1_item_ex_d2i(val, &p, len,
			ASN1_ITEM_ptr(tt->item), tt->tag, aclass, opt, ctx);
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
						ERR_R_NESTED_ASN1_ERROR);
			goto err;
			}
		else if (ret == -1)
			return -1;
		}
	else
		{

		ret = ASN1_item_ex_d2i(val, &p, len, ASN1_ITEM_ptr(tt->item),//子tempate,INTERGER#####
							-1, 0, opt, ctx);
		if (!ret)
			{
				ASN1err(ASN1_F_ASN1_TEMPLATE_NOEXP_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			//goto err;
			}
		else if (ret == -1)
			return -1;
		}

	*in = p;
	return 1;

	err:
	ASN1_template_free(val, tt);
	return 0;
	}

/////////////asn1_template_ex_d2i/////////////////////////

static int asn1_template_ex_d2i(ASN1_VALUE **val,
				const unsigned char **in, long inlen,
				const ASN1_TEMPLATE *tt, char opt,
							ASN1_TLC *ctx)
	{
	int flags, aclass;
	int ret;
	long len;
	const unsigned char *p, *q;
	char exp_eoc;
	if (!val)
		return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;

	p = *in;

	/* Check if EXPLICIT tag expected */
	if (flags & ASN1_TFLG_EXPTAG)
		{
		char cst;

		ret = asn1_check_tlen(&len, NULL, NULL, &exp_eoc, &cst,//interger,
					&p, inlen, tt->tag, aclass, opt, ctx);
		q = p;
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		else if (ret == -1)
			return -1;
		if (!cst)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
			return 0;
			}
		/* We've found the field so it can't be OPTIONAL now */
		ret = asn1_template_noexp_d2i(val, &p, len, tt, 0, ctx);//len=3,p=0x42c5ca
		if (!ret)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ERR_R_NESTED_ASN1_ERROR);
			return 0;
			}
		/* We read the field in OK so update length */
		len -= p - q;//#####
		if (exp_eoc)
			{
			/* If NDEF we must have an EOC here */
			if (!asn1_check_eoc(&p, len))
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
						ASN1_R_MISSING_EOC);
				goto err;
				}
			}
		else
			{

			if (len)
				{
				ASN1err(ASN1_F_ASN1_TEMPLATE_EX_D2I,
					ASN1_R_EXPLICIT_LENGTH_MISMATCH);
				goto err;
				}
			}
		}
		else
			return asn1_template_noexp_d2i(val, in, inlen,//###
								tt, opt, ctx);

	*in = p;
	return 1;

	err:
	ASN1_template_free(val, tt);
	return 0;
	}

////////////////////////asn1_ex_c2i///////////////////////////////////////

int asn1_ex_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
			int utype, char *free_cont, const ASN1_ITEM *it)
	{
	ASN1_VALUE **opval = NULL;
	ASN1_STRING *stmp;
	ASN1_TYPE *typ = NULL;
	int ret = 0;
	const ASN1_PRIMITIVE_FUNCS *pf;
	ASN1_INTEGER **tint;
	pf = it->funcs;

	if (pf && pf->prim_c2i)
		return pf->prim_c2i(pval, cont, len, utype, free_cont, it);
	/* If ANY type clear type and set pointer to internal value */
	if (it->utype == V_ASN1_ANY)
		{
		if (!*pval)
			{
			typ = ASN1_TYPE_new();
			if (typ == NULL)
				goto err;
			*pval = (ASN1_VALUE *)typ;
			}
		else
			typ = (ASN1_TYPE *)*pval;

		if (utype != typ->type)
			ASN1_TYPE_set(typ, utype, NULL);
		opval = pval;
		pval = &typ->value.asn1_value;
		}
	switch(utype)
		{
		case V_ASN1_OBJECT:
		if (!c2i_ASN1_OBJECT((ASN1_OBJECT **)pval, &cont, len))
			goto err;
		break;

		case V_ASN1_NULL:
		if (len)
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
						ASN1_R_NULL_IS_WRONG_LENGTH);
			goto err;
			}
		*pval = (ASN1_VALUE *)1;
		break;

		case V_ASN1_BOOLEAN:
		if (len != 1)
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
						ASN1_R_BOOLEAN_IS_WRONG_LENGTH);
			goto err;
			}
		else
			{
			ASN1_BOOLEAN *tbool;
			tbool = (ASN1_BOOLEAN *)pval;
			*tbool = *cont;
			}
		break;

		case V_ASN1_BIT_STRING:
		if (!c2i_ASN1_BIT_STRING((ASN1_BIT_STRING **)pval, &cont, len))
			goto err;
		break;

		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
		tint = (ASN1_INTEGER **)pval;
		if (!c2i_ASN1_INTEGER(tint, &cont, len))
			goto err;
		/* Fixup type to match the expected form */
		(*tint)->type = utype | ((*tint)->type & V_ASN1_NEG);
		break;

		case V_ASN1_OCTET_STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_OTHER:
		case V_ASN1_SET:
		case V_ASN1_SEQUENCE:
		default:
		if (utype == V_ASN1_BMPSTRING && (len & 1))
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
					ASN1_R_BMPSTRING_IS_WRONG_LENGTH);
			goto err;
			}
		if (utype == V_ASN1_UNIVERSALSTRING && (len & 3))
			{
			ASN1err(ASN1_F_ASN1_EX_C2I,
					ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH);
			goto err;
			}
		/* All based on ASN1_STRING and handled the same */
		if (!*pval)
			{
			stmp = ASN1_STRING_type_new(utype);
			if (!stmp)
				{
				ASN1err(ASN1_F_ASN1_EX_C2I,
							ERR_R_MALLOC_FAILURE);
				goto err;
				}
			*pval = (ASN1_VALUE *)stmp;
			}
		else
			{
			stmp = (ASN1_STRING *)*pval;
			stmp->type = utype;
			}
		/* If we've already allocated a buffer use it */
		if (*free_cont)
			{
			if (stmp->data)
				OPENSSL_free(stmp->data);
			stmp->data = (unsigned char *)cont; /* UGLY CAST! RL */
			stmp->length = len;
			*free_cont = 0;
			}
		else
			{
			if (!ASN1_STRING_set(stmp, cont, len))
				{
				ASN1err(ASN1_F_ASN1_EX_C2I,
							ERR_R_MALLOC_FAILURE);
				ASN1_STRING_free(stmp);
				*pval = NULL;
				goto err;
				}
			}
		break;
		}
	/* If ASN1_ANY and NULL type fix up value */
	if (typ && (utype == V_ASN1_NULL))
		 typ->value.ptr = NULL;

	ret = 1;
	err:
	if (!ret)
		{
		ASN1_TYPE_free(typ);
		if (opval)
			*opval = NULL;
		}
	return ret;
	}

//////////////ASN1_template_free////////////////////////////

void ASN1_template_free(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	int i;
	if (tt->flags & ASN1_TFLG_SK_MASK)
		{
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++)
			{
			ASN1_VALUE *vtmp;
			vtmp = sk_ASN1_VALUE_value(sk, i);
			asn1_item_combine_free(&vtmp, ASN1_ITEM_ptr(tt->item),
									0);
			}
		sk_ASN1_VALUE_free(sk);
		*pval = NULL;
		}
	else
		asn1_item_combine_free(pval, ASN1_ITEM_ptr(tt->item),
						tt->flags & ASN1_TFLG_COMBINE);
	}


void reset_D2I_reset(void)
{
	k=0;
}/* crypto/asn1/a_int.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



long ASN1_INTEGER_get(ASN1_INTEGER *a)
{
	int neg=0,i;
	long r=0;

	if (a == NULL) return(0L);
	i=a->type;
	if (i == V_ASN1_NEG_INTEGER)
		neg=1;
	else if (i != V_ASN1_INTEGER)
		return -1;

	if (a->length > (int)sizeof(long))
		{
		/* hmm... a bit ugly, return all ones */
		return -1;
		}
	if (a->data == NULL)
		return 0;

	for (i=0; i<a->length; i++)
		{
		r<<=8;
		r|=(unsigned char)a->data[i];
		}
	if (neg) r= -r;
	return(r);
}


int ASN1_STRING_mem(char *bp, const ASN1_STRING *v)
{
	int i,n;
	char *buf = bp;
	const char *p;

	if (v == NULL) return(0);
	n = 0;
	p=(const char *)v->data;
	for (i=0; i<v->length; i++)
		{
//		if ((p[i] > '~') || ((p[i] < ' ') &&
//			(p[i] != '\n') && (p[i] != '\r')))
//			buf[n++]='.';
//		else
			buf[n++]=p[i];
		}
	return(v->length);
}

ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp,
	     long len)
{
	ASN1_INTEGER *ret=NULL;
	const unsigned char *p, *pend;
	unsigned char *to,*s;
	int i;

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=M_ASN1_INTEGER_new()) == NULL) return(NULL);	//interger
		ret->type=V_ASN1_INTEGER;
		}
	else
		ret=(*a);

	p= *pp;	//0x42c5cc?
	pend = p + len;
	s=(unsigned char *)OPENSSL_malloc((int)len+1);
	if (s == NULL)
		{
		i=ERR_R_MALLOC_FAILURE;
		goto err;
		}
	to=s;
	if(!len) {

		ret->type=V_ASN1_INTEGER;
	} else if (*p & 0x80) /* a negative number */
		{
		ret->type=V_ASN1_NEG_INTEGER;
		if ((*p == 0xff) && (len != 1)) {
			p++;
			len--;
		}
		i = len;
		p += i - 1;
		to += i - 1;
		while((!*p) && i) {
			*(to--) = 0;
			i--;
			p--;
		}

		if(!i) {
			*s = 1;
			s[len] = 0;
			len++;
		} else {
			*(to--) = (*(p--) ^ 0xff) + 1;
			i--;
			for(;i > 0; i--) *(to--) = *(p--) ^ 0xff;
		}
	} else {
		ret->type=V_ASN1_INTEGER;
		if ((*p == 0) && (len != 1))
			{
			p++;
			len--;
			}
		memcpy(s,p,(int)len);
	}

	if (ret->data != NULL) OPENSSL_free(ret->data);
	ret->data=s;
	ret->length=(int)len;
	if (a != NULL) (*a)=ret;
	*pp=pend;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_INTEGER,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		M_ASN1_INTEGER_free(ret);
	return(NULL);
	}

///////////////////c2i_ASN1_BIT_STRING////////////////////////////////ok

ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
	const unsigned char **pp, long len)
	{
	ASN1_BIT_STRING *ret=NULL;
	const unsigned char *p;
	unsigned char *s;
	int i;

	if (len < 1)
		{
		i=ASN1_R_STRING_TOO_SHORT;
		goto err;
		}

	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=M_ASN1_BIT_STRING_new()) == NULL) return(NULL);
		}
	else
		ret=(*a);

	p= *pp;
	i= *(p++);

	ret->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07); /* clear */
	ret->flags|=(ASN1_STRING_FLAG_BITS_LEFT|(i&0x07)); /* set */

	if (len-- > 1)
		{
		s=(unsigned char *)OPENSSL_malloc((int)len);
		if (s == NULL)
			{
			i=ERR_R_MALLOC_FAILURE;
			goto err;
			}
		memcpy(s,p,(int)len);
		s[len-1]&=(0xff<<i);
		p+=len;
		}
	else
		s=NULL;

	ret->length=(int)len;
	if (ret->data != NULL) OPENSSL_free(ret->data);
	ret->data=s;
	ret->type=V_ASN1_BIT_STRING;
	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_BIT_STRING,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		M_ASN1_BIT_STRING_free(ret);
	return(NULL);
	}

////////////////c2i_ASN1_OBJECT//////////////////////////ok

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
	     long len)
	{
	ASN1_OBJECT *ret=NULL;
	const unsigned char *p;
	int i;
	for (i = 0, p = *pp + 1; i < len - 1; i++, p++)
		{
		if (*p == 0x80 && (!i || !(p[-1] & 0x80)))
			{
			ASN1err(ASN1_F_C2I_ASN1_OBJECT,ASN1_R_INVALID_OBJECT_ENCODING);
			return NULL;
			}
		}


	if ((a == NULL) || ((*a) == NULL) ||
		!((*a)->flags & ASN1_OBJECT_FLAG_DYNAMIC))
		{
		if ((ret=ASN1_OBJECT_new()) == NULL) return(NULL);
		}
	else	ret=(*a);

	p= *pp;
	if ((ret->data == NULL) || (ret->length < len))
		{
		if (ret->data != NULL) OPENSSL_free(ret->data);
		ret->data=(unsigned char *)OPENSSL_malloc(len ? (int)len : 1);
		ret->flags|=ASN1_OBJECT_FLAG_DYNAMIC_DATA;
		if (ret->data == NULL)
			{ i=ERR_R_MALLOC_FAILURE; goto err; }
		}
	memcpy(ret->data,p,(int)len);
	ret->length=(int)len;
	ret->sn=NULL;
	ret->ln=NULL;
	/* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
	p+=len;

	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
err:
	ASN1err(ASN1_F_C2I_ASN1_OBJECT,i);
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
		ASN1_OBJECT_free(ret);
	return(NULL);
	}

////////////////ASN1_OBJECT_new//////////////////////////ok

ASN1_OBJECT *ASN1_OBJECT_new(void)
	{
	ASN1_OBJECT *ret;
	ret=(ASN1_OBJECT *)OPENSSL_malloc(sizeof(ASN1_OBJECT));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_OBJECT_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->data=NULL;
	ret->nid=0;
	ret->sn=NULL;
	ret->ln=NULL;
	ret->flags=ASN1_OBJECT_FLAG_DYNAMIC;
	return(ret);
	}

//////////ASN1_OBJECT_free/////////////////////ok

void ASN1_OBJECT_free(ASN1_OBJECT *a)
	{

	if (a == NULL) return;
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_STRINGS)
		{
#ifndef CONST_STRICT /* disable purely for compile-time strict const checking. Doing this on a "real" compile will cause memory leaks */
		if (a->sn != NULL) OPENSSL_free((void *)a->sn);
		if (a->ln != NULL) OPENSSL_free((void *)a->ln);
#endif
		a->sn=a->ln=NULL;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC_DATA)
		{
		if (a->data != NULL) OPENSSL_free(a->data);
		a->data=NULL;
		a->length=0;
		}
	if (a->flags & ASN1_OBJECT_FLAG_DYNAMIC)
		OPENSSL_free(a);
	}



///////////////BIO_write////////////////////ok

int BIO_write(BIO *b, const void *in, int inl)
	{
	int i;
	long (*cb)(BIO *,int,const char *,int,long,long);

	if (b == NULL)
		return(0);

	cb=b->callback;
	if ((b->method == NULL) || (b->method->bwrite == NULL))
		{
		return(-2);
		}

	if ((cb != NULL) &&
		((i=(int)cb(b,BIO_CB_WRITE,in,inl,0L,1L)) <= 0))
			return(i);

	if (!b->init)
		{
		return(-2);
		}

	i=b->method->bwrite(b,in,inl);

	if (i > 0) b->num_write+=(unsigned long)i;

	if (cb != NULL)
		i=(int)cb(b,BIO_CB_WRITE|BIO_CB_RETURN,in,inl,
			0L,(long)i);
	return(i);
	}


///////////i2a_ASN1_INTEGER////////////////////ok

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a)
	{
	int i,n=0;
	static const char *h="0123456789ABCDEF";
	char buf[2];

	if (a == NULL) return(0);

	if (a->type & V_ASN1_NEG)
		{
		if (BIO_write(bp, "-", 1) != 1) goto err;
		n = 1;
		}

	if (a->length == 0)
		{
		if (BIO_write(bp,"00",2) != 2) goto err;
		n += 2;
		}
	else
		{
		for (i=0; i<a->length; i++)
			{
			if ((i != 0) && (i%35 == 0))
				{
				if (BIO_write(bp,"\\\n",2) != 2) goto err;
				n+=2;
				}
			buf[0]=h[((unsigned char)a->data[i]>>4)&0x0f];
			buf[1]=h[((unsigned char)a->data[i]   )&0x0f];
			if (BIO_write(bp,buf,2) != 2) goto err;
			n+=2;
			}
		}
	return(n);
err:
	return(-1);
	}
#ifndef OPENSSL_NO_RSA
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


////////////////////////////////////////////////////ok

ASN1_STRING *ASN1_STRING_type_new(int type)
{
	ASN1_STRING *ret;
	ret=(ASN1_STRING *)OPENSSL_malloc(sizeof(ASN1_STRING));
	if (ret == NULL)
		{
		ASN1err(ASN1_F_ASN1_STRING_TYPE_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->length=0;
	ret->type=type;
	ret->data=NULL;
	ret->flags=0;
	return(ret);
}
///////////////ASN1_STRING_set/////////////////////////////////ok


int ASN1_STRING_set(ASN1_STRING *str, const void *_data, int len)
	{
	unsigned char *c;
	const char *data=_data;
	if (len < 0)
		{
		if (data == NULL)
			return(0);
		else
			len=strlen(data);
		}
	if ((str->length < len) || (str->data == NULL))
		{
		c=str->data;
		if (c == NULL)
			str->data=OPENSSL_malloc(len+1);
		else
			str->data=OPENSSL_realloc(c,len+1);

		if (str->data == NULL)
			{
			ASN1err(ASN1_F_ASN1_STRING_SET,ERR_R_MALLOC_FAILURE);
			str->data=c;
			return(0);
			}
		}
	str->length=len;
	if (data != NULL)
		{
		memcpy(str->data,data,len);
		/* an allowance for strings :-) */
		str->data[len]='\0';
		}
	return(1);
	}

//////////////ASN1_STRING_free////////////////////////

void ASN1_STRING_free(ASN1_STRING *a)
	{

	if (a == NULL) return;
	if (a->data != NULL) OPENSSL_free(a->data);
	OPENSSL_free(a);
	}


///////////X509_get_serialNumber///////////////////ok

ASN1_INTEGER *X509_get_serialNumber(X509 *a)
	{
	return(a->cert_info->serialNumber);
	}


/////////////////d2i_PublicKey////////////////////////////////////ok

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
	     long length)
	{
	EVP_PKEY *ret;
	
	if ((a == NULL) || (*a == NULL))
		{
		if ((ret=EVP_PKEY_new()) == NULL)
			{
			ASN1err(ASN1_F_D2I_PUBLICKEY,ERR_R_EVP_LIB);
			return(NULL);
			}
		}
	else	ret= *a;

	ret->save_type=type;
	ret->type=EVP_PKEY_type(type);
	switch (ret->type)
		{
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		if ((ret->pkey.rsa=d2i_RSAPublicKey(NULL,
			(const unsigned char **)pp,length)) == NULL) /* TMP UGLY CAST */
			{
			ASN1err(ASN1_F_D2I_PUBLICKEY,ERR_R_ASN1_LIB);
			goto err;
			}
		break;
#endif

	default:
		ASN1err(ASN1_F_D2I_PUBLICKEY,ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
		goto err;
		/* break; */
		}
	if (a != NULL) (*a)=ret;
	return(ret);
err:
	if ((ret != NULL) && ((a == NULL) || (*a != ret)))
			EVP_PKEY_free(ret);
	return(NULL);
	}




static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,int combine);
static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt);
static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);
void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it);


/////////////////ASN1_item_ex_new/////////////////////////ok

int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	
	return asn1_item_ex_combine_new(pval, it, 0);
}

////////////ASN1_item_new//////////////////////////////////ok

ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)
	{
	ASN1_VALUE *ret = NULL;
	
	if (ASN1_item_ex_new(&ret, it) > 0)
		return ret;
	return NULL;
	}
///////////////asn1_item_ex_combine_new//////////////////////////ok

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it,
								int combine)
	{
	const ASN1_TEMPLATE *tt = NULL;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	ASN1_VALUE **pseqval;
	int i;
	
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;//x509_cb
	else
		asn1_cb = 0;

	if (!combine) *pval = NULL;

	switch(it->itype)
		{

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_new)
			{
			if (!ef->asn1_ex_new(pval, it))
				goto memerr;
			}
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (cf && cf->asn1_new) {
			*pval = cf->asn1_new();
			if (!*pval)
				goto memerr;
		}
		break;

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			{
			if (!ASN1_template_new(pval, it->templates))
				goto memerr;
			}
		else if (!ASN1_primitive_new(pval, it))
				goto memerr;
		break;

		case ASN1_ITYPE_MSTRING:
		if (!ASN1_primitive_new(pval, it))
				goto memerr;
		break;

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it);
			if (!i)
				goto auxerr;
			if (i==2)
				{

				return 1;
				}
			}
		if (!combine)
			{
			*pval = OPENSSL_malloc(it->size);
			if (!*pval)
				goto memerr;
			memset(*pval, 0, it->size);
			}
		//asn1_set_choice_selector(pval, -1, it);//samyang delete
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
		break;

		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_NEW_PRE, pval, it);
			if (!i)
				goto auxerr;
			if (i==2)
				{
				return 1;
				}
			}
		if (!combine)
			{
			*pval = OPENSSL_malloc(it->size);//接收结构体的地址
			if (!*pval)
				goto memerr;
			memset(*pval, 0, it->size);
			//asn1_do_lock(pval, 0, it);
			asn1_enc_init(pval, it);//?
			}
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)//x509_seq_tt[]
			{
				pseqval = asn1_get_field_ptr(pval, tt);//返回"接收结构体"中的偏移地址	
			
				if (!ASN1_template_new(pseqval, tt))	//创建子item,根据x509_seq_tt[]中的xx_it
					goto memerr;
			
			}
		if (asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
	
		break;
	}

	return 1;

	memerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ERR_R_MALLOC_FAILURE);
	return 0;

	auxerr:
	ASN1err(ASN1_F_ASN1_ITEM_EX_COMBINE_NEW, ASN1_R_AUX_ERROR);
	return 0;

	}

///////////////////ASN1_template_new///////////////////////////////ok

int ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	const ASN1_ITEM *it = ASN1_ITEM_ptr(tt->item);//
	
	int ret;

	if (tt->flags & ASN1_TFLG_OPTIONAL)
		{
		asn1_template_clear(pval, tt);
		return 1;
		}

	if (tt->flags & ASN1_TFLG_ADB_MASK)
		{
		*pval = NULL;
		return 1;
		}
	
	if (tt->flags & ASN1_TFLG_SK_MASK)
		{
		STACK_OF(ASN1_VALUE) *skval;
		skval = sk_ASN1_VALUE_new_null();
		if (!skval)
			{
			ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
			ret = 0;
			goto done;
			}
		*pval = (ASN1_VALUE *)skval;
		ret = 1;
		goto done;
		}
	
	ret = asn1_item_ex_combine_new(pval, it, tt->flags & ASN1_TFLG_COMBINE);//判断子item结构的类型，长度
	done:
	return ret;
	}

///////////////asn1_template_clear///////////////////////////ok

static void asn1_template_clear(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
	{
	
	if (tt->flags & (ASN1_TFLG_ADB_MASK|ASN1_TFLG_SK_MASK)) 
		*pval = NULL;
	else
		asn1_item_clear(pval, ASN1_ITEM_ptr(tt->item));
	}


////////////////ASN1_primitive_new///////////////////////ok

int ASN1_primitive_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_TYPE *typ;
	int utype;
	
	if (it && it->funcs)
		{
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_new)
			return pf->prim_new(pval, it);
		}

	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = -1;
	else
		utype = it->utype;
	switch(utype)
		{
		case V_ASN1_OBJECT:
		*pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
		return 1;

		case V_ASN1_BOOLEAN:
		if (it)
			*(ASN1_BOOLEAN *)pval = it->size;
		else
			*(ASN1_BOOLEAN *)pval = -1;
		return 1;

		case V_ASN1_NULL:
		*pval = (ASN1_VALUE *)1;
		return 1;

		case V_ASN1_ANY:
		typ = OPENSSL_malloc(sizeof(ASN1_TYPE));
		if (!typ)
			return 0;
		typ->value.ptr = NULL;
		typ->type = -1;
		*pval = (ASN1_VALUE *)typ;
		break;

		default:
		*pval = (ASN1_VALUE *)ASN1_STRING_type_new(utype);
		break;
		}
	if (*pval)
		return 1;
	return 0;
	}


///////////////asn1_item_clear///////////////////////////////ok

static void asn1_item_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	const ASN1_EXTERN_FUNCS *ef;
	
	switch(it->itype)
		{

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_clear)
			ef->asn1_ex_clear(pval, it);
		else *pval = NULL;
		break;


		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			asn1_template_clear(pval, it->templates);
		else
			asn1_primitive_clear(pval, it);
		break;

		case ASN1_ITYPE_MSTRING:
		asn1_primitive_clear(pval, it);
		break;

		case ASN1_ITYPE_COMPAT:
		case ASN1_ITYPE_CHOICE:
		case ASN1_ITYPE_SEQUENCE:
		case ASN1_ITYPE_NDEF_SEQUENCE:
		*pval = NULL;
		break;
		}
	}

////////////asn1_primitive_clear///////////////////////ok

void asn1_primitive_clear(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	int utype;
	
	if (it && it->funcs)
		{
		const ASN1_PRIMITIVE_FUNCS *pf = it->funcs;
		if (pf->prim_clear)
			pf->prim_clear(pval, it);
		else
			*pval = NULL;
		return;
		}
	if (!it || (it->itype == ASN1_ITYPE_MSTRING))
		utype = -1;
	else
		utype = it->utype;
	if (utype == V_ASN1_BOOLEAN)
		*(ASN1_BOOLEAN *)pval = it->size;
	else *pval = NULL;
	}





static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
					const ASN1_ITEM *it,
					int tag, int aclass);
static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
					const ASN1_TEMPLATE *tt,
					int tag, int aclass);
static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
					const ASN1_ITEM *it, int flags);


//////////////////ASN1_item_i2d//////////////////////////////////////////ok

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
	{

	return asn1_item_flags_i2d(val, out, it, 0);
	}

/////////////////asn1_item_flags_i2d/////////////////////////////////////////ok

static int asn1_item_flags_i2d(ASN1_VALUE *val, unsigned char **out,
					const ASN1_ITEM *it, int flags)
	{
	/*if (out && !*out)
		{
		unsigned char *p, *buf;
		int len;
		len = ASN1_item_ex_i2d(&val, NULL, it, -1, flags);
		if (len <= 0)
			return len;
		buf = OPENSSL_malloc(len);
		if (!buf)
			return -1;
		p = buf;
		ASN1_item_ex_i2d(&val, &p, it, -1, flags);
		*out = buf;
		return len;
		}
*/
	return ASN1_item_ex_i2d(&val, out, it, -1, flags);
	}

///////////////// ASN1_item_ex_i2d//////////////////////////////////ok

int ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
			const ASN1_ITEM *it, int tag, int aclass)
	{
	const ASN1_TEMPLATE *tt = NULL;
	unsigned char *p = NULL;
	int i, seqcontlen, seqlen, ndef = 1;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb = 0;

	if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
		return 0;

	if (aux && aux->asn1_cb)
		 asn1_cb = aux->asn1_cb;

	switch(it->itype)
		{

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			return asn1_template_ex_i2d(pval, out, it->templates,
								tag, aclass);
		return asn1_i2d_ex_primitive(pval, out, it, tag, aclass);
		break;

		case ASN1_ITYPE_MSTRING:
		return asn1_i2d_ex_primitive(pval, out, it, -1, aclass);

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it))
				return 0;


		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_POST, pval, it))
				return 0;
		break;

		case ASN1_ITYPE_EXTERN:
		/* If new style i2d it does all the work */
		ef = it->funcs;
		return ef->asn1_ex_i2d(pval, out, it, tag, aclass);

		case ASN1_ITYPE_COMPAT:
		/* old style hackery... */
		cf = it->funcs;
		if (out)
			p = *out;
		i = cf->asn1_i2d(*pval, out);

		if (out && (tag != -1))
			*p = aclass | tag | (*p & V_ASN1_CONSTRUCTED);
		return i;

		case ASN1_ITYPE_NDEF_SEQUENCE:

		if (aclass & ASN1_TFLG_NDEF) ndef = 2;


		case ASN1_ITYPE_SEQUENCE:
		i = asn1_enc_restore(&seqcontlen, out, pval, it);
		/* An error occurred */
		if (i < 0)
			return 0;
		/* We have a valid cached encoding... */
		if (i > 0)
			return seqcontlen;
		/* Otherwise carry on */
		seqcontlen = 0;
		/* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
		if (tag == -1)
			{
			tag = V_ASN1_SEQUENCE;
			/* Retain any other flags in aclass */
			aclass = (aclass & ~ASN1_TFLG_TAG_CLASS)
					| V_ASN1_UNIVERSAL;
			}
		if (asn1_cb && !asn1_cb(ASN1_OP_I2D_PRE, pval, it))
				return 0;
		/* First work out sequence content length */
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			/* FIXME: check for errors in enhanced version */
			seqcontlen += asn1_template_ex_i2d(pseqval, NULL, seqtt,
								-1, aclass);
			}

		seqlen = ASN1_object_size(ndef, seqcontlen, tag);
		if (!out)
			return seqlen;

		ASN1_put_object(out, ndef, seqcontlen, tag, aclass);
		for (i = 0, tt = it->templates; i < it->tcount; tt++, i++)
			{
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 1);
			if (!seqtt)
				return 0;
			pseqval = asn1_get_field_ptr(pval, seqtt);

			asn1_template_ex_i2d(pseqval, out, seqtt, -1, aclass);
			}
		//if (ndef == 2)
		//	ASN1_put_eoc(out);//samyang delete
		if (asn1_cb  && !asn1_cb(ASN1_OP_I2D_POST, pval, it))
				return 0;
		return seqlen;

		default:
		return 0;

		}
	return 0;
	}


/////////////////asn1_template_ex_i2d/////////////////////////////////////ok

static int asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
				const ASN1_TEMPLATE *tt, int tag, int iclass)
	{
	int i, ret, flags, ttag, tclass, ndef;
	flags = tt->flags;

	if (flags & ASN1_TFLG_TAG_MASK)
		{
		if (tag != -1)
			return -1;
		ttag = tt->tag;
		tclass = flags & ASN1_TFLG_TAG_CLASS;
		}
	else if (tag != -1)
		{
		ttag = tag;
		tclass = iclass & ASN1_TFLG_TAG_CLASS;
		}
	else
		{
		ttag = -1;
		tclass = 0;
		}

	iclass &= ~ASN1_TFLG_TAG_CLASS;

	if ((flags & ASN1_TFLG_NDEF) && (iclass & ASN1_TFLG_NDEF))
		ndef = 2;
	else ndef = 1;

	if (flags & ASN1_TFLG_SK_MASK)
		{
		/* SET OF, SEQUENCE OF */
		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
		int isset, sktag, skaclass;
		int skcontlen, sklen;
		ASN1_VALUE *skitem;

		if (!*pval)
			return 0;

		if (flags & ASN1_TFLG_SET_OF)
			{
			isset = 1;
			/* 2 means we reorder */
			if (flags & ASN1_TFLG_SEQUENCE_OF)
				isset = 2;
			}
		else isset = 0;
		if ((ttag != -1) && !(flags & ASN1_TFLG_EXPTAG))
			{
			sktag = ttag;
			skaclass = tclass;
			}
		else
			{
			skaclass = V_ASN1_UNIVERSAL;
			if (isset)
				sktag = V_ASN1_SET;
			else sktag = V_ASN1_SEQUENCE;
			}

		/* Determine total length of items */
		skcontlen = 0;
		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++)
			{
			skitem = sk_ASN1_VALUE_value(sk, i);
			skcontlen += ASN1_item_ex_i2d(&skitem, NULL,
						ASN1_ITEM_ptr(tt->item),
							-1, iclass);
			}
		sklen = ASN1_object_size(ndef, skcontlen, sktag);
		/* If EXPLICIT need length of surrounding tag */
		if (flags & ASN1_TFLG_EXPTAG)
			ret = ASN1_object_size(ndef, sklen, ttag);
		else ret = sklen;

		if (!out)
			return ret;


		if (flags & ASN1_TFLG_EXPTAG)
			ASN1_put_object(out, ndef, sklen, ttag, tclass);

		ASN1_put_object(out, ndef, skcontlen, sktag, skaclass);



		return ret;
		}

	if (flags & ASN1_TFLG_EXPTAG)
		{

		i = ASN1_item_ex_i2d(pval, NULL, ASN1_ITEM_ptr(tt->item),
								-1, iclass);
		if (!i)
			return 0;

		ret = ASN1_object_size(ndef, i, ttag);
		if (out)
			{

			ASN1_put_object(out, ndef, i, ttag, tclass);
			ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
								-1, iclass);
			//if (ndef == 2)
				//ASN1_put_eoc(out);//samyang delete
			}
		return ret;
		}

	return ASN1_item_ex_i2d(pval, out, ASN1_ITEM_ptr(tt->item),
						ttag, tclass | iclass);

}


////////////////////asn1_i2d_ex_primitive/////////////////////////////////ok

static int asn1_i2d_ex_primitive(ASN1_VALUE **pval, unsigned char **out,
				const ASN1_ITEM *it, int tag, int aclass)
	{
	int len;
	int utype;
	int usetag;
	int ndef = 0;

	utype = it->utype;

	len = asn1_ex_i2c(pval, NULL, &utype, it);


	if ((utype == V_ASN1_SEQUENCE) || (utype == V_ASN1_SET) ||
	   (utype == V_ASN1_OTHER))
		usetag = 0;
	else usetag = 1;

	if (len == -1)
		return 0;


	if (len == -2)
		{
		ndef = 2;
		len = 0;
		}


	if (tag == -1) tag = utype;


	if (out)
		{
		if (usetag)
			ASN1_put_object(out, ndef, len, tag, aclass);
		asn1_ex_i2c(pval, *out, &utype, it);
		//if (ndef)
			//ASN1_put_eoc(out);//samyang delete
		//else
			*out += len;
		}

	if (usetag)
		return ASN1_object_size(ndef, len, tag);
	return len;
	}

////////////////asn1_ex_i2c//////////////////////////////////ok

int asn1_ex_i2c(ASN1_VALUE **pval, unsigned char *cout, int *putype,
				const ASN1_ITEM *it)
	{
	ASN1_BOOLEAN *tbool = NULL;
	ASN1_STRING *strtmp;
	ASN1_OBJECT *otmp;
	int utype;
	unsigned char *cont=NULL, c;
	int len=0;
	const ASN1_PRIMITIVE_FUNCS *pf;
	pf = it->funcs;

	if (pf && pf->prim_i2c)
		return pf->prim_i2c(pval, cout, putype, it);

	if ((it->itype != ASN1_ITYPE_PRIMITIVE)
		|| (it->utype != V_ASN1_BOOLEAN))
		{
		if (!*pval) return -1;
		}

	if (it->itype == ASN1_ITYPE_MSTRING)
		{

		strtmp = (ASN1_STRING *)*pval;
		utype = strtmp->type;
		*putype = utype;
		}
	else if (it->utype == V_ASN1_ANY)
		{
		ASN1_TYPE *typ;
		typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		*putype = utype;
		pval = &typ->value.asn1_value;
		}
	else utype = *putype;

	switch(utype)
		{
		case V_ASN1_OBJECT:
		otmp = (ASN1_OBJECT *)*pval;
		cont = otmp->data;
		len = otmp->length;
		break;

		case V_ASN1_NULL:
		cont = NULL;
		len = 0;
		break;

		case V_ASN1_BOOLEAN:
		tbool = (ASN1_BOOLEAN *)pval;
		if (*tbool == -1)
			return -1;
		if (it->utype != V_ASN1_ANY)
			{
			if (*tbool && (it->size > 0))
				return -1;
			if (!*tbool && !it->size)
				return -1;
			}
		c = (unsigned char)*tbool;
		cont = &c;
		len = 1;
		break;

		case V_ASN1_BIT_STRING:
			;

		break;

		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
					;
		//return i2c_ASN1_INTEGER((ASN1_INTEGER *)*pval,
							//cout ? &cout : NULL);
		break;

		case V_ASN1_OCTET_STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_SEQUENCE:
		case V_ASN1_SET:
		default:
		/* All based on ASN1_STRING and handled the same */
		strtmp = (ASN1_STRING *)*pval;
		/* Special handling for NDEF */
		if ((it->size == ASN1_TFLG_NDEF)
			&& (strtmp->flags & ASN1_STRING_FLAG_NDEF))
			{
			if (cout)
				{
				strtmp->data = cout;
				strtmp->length = 0;
				}
			/* Special return code */
			return -2;
			}
		cont = strtmp->data;
		len = strtmp->length;

		break;

		}
	if (cout && len)
		memcpy(cout, cont, len);
	return len;
	}

#undef MIN_NODES
#define MIN_NODES	4

/////////////////////sk_new_null//////////////////////////////////ok

STACK *sk_new_null(void)
{
	
	return sk_new((int (*)(const char * const *, const char * const *))0);
}
/////////////////sk_new//////////////////////////////////ok

STACK *sk_new(int (*c)(const char * const *, const char * const *))
{
	STACK *ret;
	int i;
	
	if ((ret=(STACK *)OPENSSL_malloc(sizeof(STACK))) == NULL)
		goto err;
	if ((ret->data=(char **)OPENSSL_malloc(sizeof(char *)*MIN_NODES)) == NULL)
		goto err;
	for (i=0; i<MIN_NODES; i++)
		ret->data[i]=NULL;
	ret->comp=c;
	ret->num_alloc=MIN_NODES;
	ret->num=0;
	ret->sorted=0;
	return(ret);
err:
	if(ret)
		OPENSSL_free(ret);
	return(NULL);
}

///////////////sk_insert////////////////////////////ok

int sk_insert(STACK *st, char *data, int loc)
	{
	char **s;

	if(st == NULL) return 0;
	if (st->num_alloc <= st->num+1)
		{
		s=(char **)OPENSSL_realloc((char *)st->data,
			(unsigned int)sizeof(char *)*st->num_alloc*2);
		if (s == NULL)
			return(0);
		st->data=s;
		st->num_alloc*=2;
		}
	if ((loc >= (int)st->num) || (loc < 0))
		st->data[st->num]=data;
	else
		{
		int i;
		char **f,**t;

		f=(char **)st->data;
		t=(char **)&(st->data[1]);
		for (i=st->num; i>=loc; i--)
			t[i]=f[i];

		st->data[loc]=data;
		}
	st->num++;
	st->sorted=0;
	return(st->num);
	}

////////////sk_push//////////////////////////ok

int sk_push(STACK *st, char *data)
	{
		
	return(sk_insert(st,data,st->num));
	}

//////////////sk_free////////////////////////ok

void sk_free(STACK *st)
	{
		
	if (st == NULL) return;
	if (st->data != NULL) OPENSSL_free(st->data);
	OPENSSL_free(st);
	}

/////////////sk_pop_free////////////////////////ok

void sk_pop_free(STACK *st, void (*func)(void *))
	{
	/*int i;
	if (st == NULL) return;
	for (i=0; i<st->num; i++)
		if (st->data[i] != NULL)
			func(st->data[i]);
	sk_free(st);*/
	}


static void asn1_put_length(unsigned char **pp, int length);
static int asn1_get_length(const unsigned char **pp,int *inf,long *rl,int max);

/////////////ASN1_put_object/////////////////////////////////////////ok

void ASN1_put_object(unsigned char **pp, int constructed, int length, int tag,
	     int xclass)
{
	unsigned char *p= *pp;
	int i, ttag;

	i=(constructed)?V_ASN1_CONSTRUCTED:0;
	i|=(xclass&V_ASN1_PRIVATE);
	if (tag < 31)
		*(p++)=i|(tag&V_ASN1_PRIMITIVE_TAG);
	else
		{
		*(p++)=i|V_ASN1_PRIMITIVE_TAG;
		for(i = 0, ttag = tag; ttag > 0; i++) ttag >>=7;
		ttag = i;
		while(i-- > 0)
			{
			p[i] = tag & 0x7f;
			if(i != (ttag - 1)) p[i] |= 0x80;
			tag >>= 7;
			}
		p += ttag;
		}
	if (constructed == 2)
		*(p++)=0x80;
	else
		asn1_put_length(&p,length);
	*pp=p;
}

//////////////asn1_put_length///////////////////////////////////////ok

static void asn1_put_length(unsigned char **pp, int length)
	{
	unsigned char *p= *pp;
	int i,l;

	if (length <= 127)
		*(p++)=(unsigned char)length;
	else
		{
		l=length;
		for (i=0; l > 0; i++)
			l>>=8;
		*(p++)=i|0x80;
		l=i;
		while (i-- > 0)
			{
			p[i]=length&0xff;
			length>>=8;
			}
		p+=l;
		}
	*pp=p;
	}


////////////////ASN1_object_size//////////////////////////////////ok

int ASN1_object_size(int constructed, int length, int tag)
	{
	int ret;

	ret=length;
	ret++;
	if (tag >= 31)
		{
		while (tag > 0)
			{
			tag>>=7;
			ret++;
			}
		}
	if (constructed == 2)
		return ret + 3;
	ret++;
	if (length > 127)
		{
		while (length > 0)
			{
			length>>=8;
			ret++;
			}
		}
	return(ret);
	}

/////////ASN1_get_object//////////////////////////////////////////////ok
//	--YXY	获得证书是什么结构类型，例如sequence
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
	int *pclass, long omax)
	{
	int i,ret;
	long l;
	const unsigned char *p= *pp;
	int tag,xclass,inf;
	long max=omax;

	if (!max) goto err;
	ret=(*p&V_ASN1_CONSTRUCTED);//0x20
	xclass=(*p&V_ASN1_PRIVATE);//0xc0
	i= *p&V_ASN1_PRIMITIVE_TAG;//0x1f
	if (i == V_ASN1_PRIMITIVE_TAG)
		{		/* high-tag */
		p++;
		if (--max == 0) goto err;
		l=0;
		while (*p&0x80)
			{
			l<<=7L;
			l|= *(p++)&0x7f;
			if (--max == 0) goto err;
			if (l > (INT_MAX >> 7L)) goto err;
			}
		l<<=7L;
		l|= *(p++)&0x7f;
		tag=(int)l;
		if (--max == 0) goto err;
		}
	else
		{
		tag=i;//确定是什么类型,即universal的值
		p++;
		if (--max == 0) goto err;
		}
	*ptag=tag;
	*pclass=xclass;
	if (!asn1_get_length(&p,&inf,plength,(int)max)) goto err;//intenger

	if (*plength > (omax - (p - *pp)))//判断证书剩余的大小
		{
		ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_TOO_LONG);
		ret|=0x80;
		}
	*pp=p;//证书的偏移地址
	return(ret|inf);
err:
	ASN1err(ASN1_F_ASN1_GET_OBJECT,ASN1_R_HEADER_TOO_LONG);
	return(0x80);
	}

/////////////////asn1_get_length//////////////////////////////////////////ok
//--YXY	获取证书的结构中的长度
static int asn1_get_length(const unsigned char **pp, int *inf, long *rl, int max)
	{
	const unsigned char *p= *pp;
	unsigned long ret=0;
	unsigned int i;

	if (max-- < 1) return(0);
	if (*p == 0x80)
		{
		*inf=1;
		ret=0;
		p++;
		}
	else
		{
		*inf=0;
		i= *p&0x7f;//获得多少个字节0x82，即2个字节
		if (*(p++) & 0x80)//获得长度0x04,0x51,即1105
			{
			if (i > sizeof(long))
				return 0;
			if (max-- == 0) return(0);
			while (i-- > 0)
				{
				ret<<=8L;
				ret|= *(p++);
				if (max-- == 0) return(0);
				}
			}
		else
			ret=i;
		}
	if (ret > LONG_MAX)
		return 0;
	*pp=p;//返回证书的偏移地址
	*rl=(long)ret;//返回长度值



	return(1);
	}



#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

////////////////asn1_get_field_ptr///////////////////////////////////ok由tt中的offset计算要读取数据在"接收结构体"里面的偏移

ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	ASN1_VALUE **pvaltmp;

	if (tt->flags & ASN1_TFLG_COMBINE)
		return pval;
	pvaltmp = offset2ptr(*pval, tt->offset);

	return pvaltmp;
}


////////////////asn1_get_enc_ptr/////////////////////////ok

static ASN1_ENCODING *asn1_get_enc_ptr(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	const ASN1_AUX *aux;

	if (!pval || !*pval)
		return NULL;
	aux = it->funcs;
	if (!aux || !(aux->flags & ASN1_AFLG_ENCODING))
		return NULL;
	return offset2ptr(*pval, aux->enc_offset);
}
////////////////asn1_enc_save//////////////////////////////ok

int asn1_enc_save(ASN1_VALUE **pval, const unsigned char *in, int inlen,
							 const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;

	enc = asn1_get_enc_ptr(pval, it);
	if (!enc)
		return 1;

	if (enc->enc)
		OPENSSL_free(enc->enc);
	enc->enc = OPENSSL_malloc(inlen);
	if (!enc->enc)
		return 0;
	memcpy(enc->enc, in, inlen);
	enc->len = inlen;
	enc->modified = 0;

	return 1;
	}

////////////////asn1_do_adb//////////////////////////////////////ok

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt,int nullerr)
	{
	const ASN1_ADB *adb;
	const ASN1_ADB_TABLE *atbl;
	long selector = 0;
	ASN1_VALUE **sfld;
	int i;

	if (!(tt->flags & ASN1_TFLG_ADB_MASK))
		return tt;//??

	adb = ASN1_ADB_ptr(tt->item);

	sfld = offset2ptr(*pval, adb->offset);

	if (!sfld)
		{
		if (!adb->null_tt)
			goto err;
		return adb->null_tt;
		}

	if (tt->flags & ASN1_TFLG_ADB_OID)
		selector = OBJ_obj2nid((ASN1_OBJECT *)*sfld);
	else
		//selector = ASN1_INTEGER_get((ASN1_INTEGER *)*sfld);
		;


	for (atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
		if (atbl->value == selector)
			return &atbl->tt;


	if (!adb->default_tt)
		goto err;
	return adb->default_tt;

	err:
	if (nullerr)
		ASN1err(ASN1_F_ASN1_DO_ADB,
			ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE);
	return NULL;
	}



///////////////asn1_enc_init////////////////////////////////////ok

void asn1_enc_init(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	ASN1_ENCODING *enc;
	enc = asn1_get_enc_ptr(pval, it);
	if (enc)
		{
		enc->enc = NULL;
		enc->len = 0;
		enc->modified = 1;
		}
	}


int ASN1_STRING_print(BIO *bp, ASN1_STRING *v)
	{
	int i,n;
	char buf[80],*p;

	if (v == NULL) return(0);
	n=0;
	p=(char *)v->data;
	for (i=0; i<v->length; i++)
		{
//		if ((p[i] > '~') || ((p[i] < ' ') &&
//			(p[i] != '\n') && (p[i] != '\r')))
//			buf[n]='.';
//		else
			buf[n]=p[i];
		n++;
		if (n >= 80)
			{
			if (BIO_write(bp,buf,n) <= 0)
				return(0);
			n=0;
			}
		}
	if (n > 0)
		if (BIO_write(bp,buf,n) <= 0)
			return(0);
	return(1);
	}


/////////////////////rsa_cb/////////////////////////////////

static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	if(operation == ASN1_OP_NEW_PRE) {
		*pval = (ASN1_VALUE *)RSA_new();
		if(*pval) return 2;
		return 0;
	} else if(operation == ASN1_OP_FREE_PRE) {
		//RSA_free((RSA *)*pval);//samyang delete
		*pval = NULL;
		return 2;
	}
	return 1;
}


////////////////RSAPublicKey_it//////////////////////////////////////

ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
	ASN1_SIMPLE(RSA, n, BIGNUM),
	ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPublicKey, RSAPublicKey)


void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine);

///////////////ASN1_item_free//////////////////////////ok

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)
	{

	asn1_item_combine_free(&val, it, 0);
	}

//////////////ASN1_TYPE_set//////////////////////ok
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value)
{

	if (a->value.ptr != NULL)
		{
		ASN1_TYPE **tmp_a = &a;
		ASN1_primitive_free((ASN1_VALUE **)tmp_a, NULL);
		}
	a->type=type;
	a->value.ptr=value;
}

/////////////////ASN1_primitive_free//////////////////////////ok

void ASN1_primitive_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
	{
	int utype;

	if (it)
		{
		const ASN1_PRIMITIVE_FUNCS *pf;
		pf = it->funcs;
		if (pf && pf->prim_free)
			{
			pf->prim_free(pval, it);
			return;
			}
		}

	if (!it)
		{
		ASN1_TYPE *typ = (ASN1_TYPE *)*pval;
		utype = typ->type;
		pval = &typ->value.asn1_value;
		if (!*pval)
			return;
		}
	else if (it->itype == ASN1_ITYPE_MSTRING)
		{
		utype = -1;
		if (!*pval)
			return;
		}
	else
		{
		utype = it->utype;
		if ((utype != V_ASN1_BOOLEAN) && !*pval)
			return;
		}

	switch(utype)
		{
		case V_ASN1_OBJECT:
		ASN1_OBJECT_free((ASN1_OBJECT *)*pval);
		break;

		case V_ASN1_BOOLEAN:
		if (it)
			*(ASN1_BOOLEAN *)pval = it->size;
		else
			*(ASN1_BOOLEAN *)pval = -1;
		return;

		case V_ASN1_NULL:
		break;

		case V_ASN1_ANY:
		ASN1_primitive_free(pval, NULL);
		OPENSSL_free(*pval);
		break;

		default:
		ASN1_STRING_free((ASN1_STRING *)*pval);
		*pval = NULL;
		break;
		}
	*pval = NULL;
	}


////////////////asn1_item_combine_free///////////////////////////ok

 void asn1_item_combine_free(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
	{
	const ASN1_TEMPLATE *tt = NULL, *seqtt;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	int i=0;

	if (!pval)
		return;
	if ((it->itype != ASN1_ITYPE_PRIMITIVE) && !*pval)
		return;
	if (aux && aux->asn1_cb)
		asn1_cb = aux->asn1_cb;
	else
		asn1_cb = 0;

	switch(it->itype)
		{

		case ASN1_ITYPE_PRIMITIVE:
		if (it->templates)
			ASN1_template_free(pval, it->templates);
		else
			ASN1_primitive_free(pval, it);
		break;

		case ASN1_ITYPE_MSTRING:
		ASN1_primitive_free(pval, it);
		break;

		case ASN1_ITYPE_CHOICE:
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it);
			if (i == 2)
				return;
			}
		//i = asn1_get_choice_selector(pval, it);//samyang delete
		if ((i >= 0) && (i < it->tcount))
			{
			ASN1_VALUE **pchval;
			tt = it->templates + i;
			pchval = asn1_get_field_ptr(pval, tt);
			ASN1_template_free(pchval, tt);
			}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it);
		if (!combine)
			{
			OPENSSL_free(*pval);
			*pval = NULL;
			}
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if (cf && cf->asn1_free)
			cf->asn1_free(*pval);
		break;

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if (ef && ef->asn1_ex_free)
			ef->asn1_ex_free(pval, it);
		break;

		case ASN1_ITYPE_NDEF_SEQUENCE:
		case ASN1_ITYPE_SEQUENCE:
		//if (asn1_do_lock(pval, -1, it) > 0)//samyang delete
		//	return;
		if (asn1_cb)
			{
			i = asn1_cb(ASN1_OP_FREE_PRE, pval, it);
			if (i == 2)
				return;
			}
		asn1_enc_free(pval, it);

		tt = it->templates + it->tcount - 1;
		for (i = 0; i < it->tcount; tt--, i++)
			{
			ASN1_VALUE **pseqval;
			seqtt = asn1_do_adb(pval, tt, 0);
			if (!seqtt)
				continue;
			pseqval = asn1_get_field_ptr(pval, seqtt);
			ASN1_template_free(pseqval, seqtt);
			}
		if (asn1_cb)
			asn1_cb(ASN1_OP_FREE_POST, pval, it);
		if (!combine)
			{
			OPENSSL_free(*pval);
			*pval = NULL;
			}
		break;
		}
	}



#define BN_SENSITIVE	1

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it);
static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it);

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it);
static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len, int utype, char *free_cont, const ASN1_ITEM *it);

static ASN1_PRIMITIVE_FUNCS bignum_pf = {
	NULL, 0,
	bn_new,
	bn_free,
	0,
	bn_c2i,
	bn_i2c
};

////////////////////////BIGNUM_it//////////////////////////////////////////////

ASN1_ITEM_start(BIGNUM)
	ASN1_ITYPE_PRIMITIVE, V_ASN1_INTEGER, NULL, 0, &bignum_pf, 0, "BIGNUM"
ASN1_ITEM_end(BIGNUM)

//////////////////bn_new//////////////////////////////////ok

static int bn_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
		
	*pval = (ASN1_VALUE *)BN_new();
	if(*pval) return 1;
	else return 0;
}

////////////////bn_free//////////////////////////////////

static void bn_free(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
		;
}

//////////////////bn_i2c/////////////////////////////////////////////////////////////ok

static int bn_i2c(ASN1_VALUE **pval, unsigned char *cont, int *putype, const ASN1_ITEM *it)
{
	BIGNUM *bn;
	int pad;
		
	if(!*pval) return -1;
	bn = (BIGNUM *)*pval;
	/* If MSB set in an octet we need a padding byte */
	if(BN_num_bits(bn) & 0x7) pad = 0;
	else pad = 1;
	if(cont) {
		if(pad) *cont++ = 0;
		BN_bn2bin(bn, cont);
	}
	return pad + BN_num_bytes(bn);
}

////////////////////bn_c2i/////////////////////////////////////////////ok

static int bn_c2i(ASN1_VALUE **pval, const unsigned char *cont, int len,
		  int utype, char *free_cont, const ASN1_ITEM *it)
{
	BIGNUM *bn;
		
	if(!*pval) bn_new(pval, it);
	bn  = (BIGNUM *)*pval;
	if(!BN_bin2bn(cont, len, bn)) {
		bn_free(pval, it);
		return 0;
	}
	return 1;
}


/* crypto/x509/x509_ext.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



int X509_get_ext_count(X509 *x)
	{
	return(X509v3_get_ext_count(x->cert_info->extensions));
	}


#define sk_X509_EXTENSION_value(st, i) SKM_sk_value(X509_EXTENSION, (st), (i))
#define sk_X509_EXTENSION_num(st) SKM_sk_num(X509_EXTENSION, (st))

////////////sk_num//////////////////////////////////ok

int sk_num(const STACK *st)
{

	if(st == NULL) return -1;
	return st->num;
}
//////////sk_value//////////////////////////////ok

char *sk_value(const STACK *st, int i)
{

	if(!st || (i < 0) || (i >= st->num)) return NULL;
	return st->data[i];
}
/////////X509v3_get_ext_count//////////////////////////////ok


/* crypto/x509/x509_v3.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)
	{
	if (x == NULL) return(0);
	return(sk_X509_EXTENSION_num(x));
	}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
	{
	if (ex == NULL) return(NULL);
	return(ex->object);
	}






#undef MIN_NODES
#define MIN_NODES	16
#define UP_LOAD		(2*LH_LOAD_MULT)
#define DOWN_LOAD	(LH_LOAD_MULT)

static LHASH_NODE **getrn(LHASH *lh, const void *data, unsigned long *rhash);


////////////////getrn//////////////////////////ok

static LHASH_NODE **getrn(LHASH *lh, const void *data, unsigned long *rhash)
	{
	LHASH_NODE **ret,*n1;
	unsigned long hash,nn;
	LHASH_COMP_FN_TYPE cf;

	//DMSG_DEBUG("============getrn=================--1--\n");

	hash=(*(lh->hash))(data);
	lh->num_hash_calls++;
	*rhash=hash;

	//DMSG_DEBUG("============getrn=================--2--\n");

	nn=hash%lh->pmax;

	if (nn < lh->p)
		nn=hash%lh->num_alloc_nodes;

	cf=lh->comp;
	ret= &(lh->b[(int)nn]);

	//DMSG_DEBUG("============getrn=================--3--\n");

	for (n1= *ret; n1 != NULL; n1=n1->next)
		{
#ifndef OPENSSL_NO_HASH_COMP
		lh->num_hash_comps++;
		if (n1->hash != hash)
			{
			ret= &(n1->next);
			continue;
			}
#endif
		lh->num_comp_calls++;
		if(cf(n1->data,data) == 0)
			break;
		ret= &(n1->next);
		}

	//DMSG_DEBUG("============getrn=================--end--\n");

	return(ret);
	}

///////////lh_retrieve//////////////////////////ok

void *lh_retrieve(LHASH *lh, const void *data)
{
	unsigned long hash;
	LHASH_NODE **rn;
	void *ret;

	lh->error=0;
	rn=getrn(lh,data,&hash);

	if (*rn == NULL)
		{
		lh->num_retrieve_miss++;
		return(NULL);
		}
	else
		{
		ret= (*rn)->data;
		lh->num_retrieve++;
		}
	return(ret);
}


///////////////lh_insert//////////////////////////ok

void *lh_insert(LHASH *lh, void *data)
	{
	unsigned long hash;
	LHASH_NODE *nn,**rn;
	void *ret;

	lh->error=0;

	rn=getrn(lh,data,&hash);

	if (*rn == NULL)
		{
		if ((nn=(LHASH_NODE *)OPENSSL_malloc(sizeof(LHASH_NODE))) == NULL)
			{
			lh->error++;
			return(NULL);
			}
		nn->data=data;
		nn->next=NULL;
#ifndef OPENSSL_NO_HASH_COMP
		nn->hash=hash;
#endif
		*rn=nn;
		ret=NULL;
		lh->num_insert++;
		lh->num_items++;
		}
	else /* replace same key */
		{
		ret= (*rn)->data;
		(*rn)->data=data;
		lh->num_replace++;
		}
	return(ret);
	}


///////////lh_new/////////////////////////////ok

LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c)
	{
	LHASH *ret;
	int i;

	if ((ret=(LHASH *)OPENSSL_malloc(sizeof(LHASH))) == NULL)
		goto err0;
	if ((ret->b=(LHASH_NODE **)OPENSSL_malloc(sizeof(LHASH_NODE *)*MIN_NODES)) == NULL)
		goto err1;
	for (i=0; i<MIN_NODES; i++)
		ret->b[i]=NULL;
	ret->comp=((c == NULL)?(LHASH_COMP_FN_TYPE)strcmp:c);
	ret->hash=h;//((h == NULL)?(LHASH_HASH_FN_TYPE)lh_strhash:h);//samyang delete
	ret->num_nodes=MIN_NODES/2;
	ret->num_alloc_nodes=MIN_NODES;
	ret->p=0;
	ret->pmax=MIN_NODES/2;
	ret->up_load=UP_LOAD;
	ret->down_load=DOWN_LOAD;
	ret->num_items=0;

	ret->num_expands=0;
	ret->num_expand_reallocs=0;
	ret->num_contracts=0;
	ret->num_contract_reallocs=0;
	ret->num_hash_calls=0;
	ret->num_comp_calls=0;
	ret->num_insert=0;
	ret->num_replace=0;
	ret->num_delete=0;
	ret->num_no_delete=0;
	ret->num_retrieve=0;
	ret->num_retrieve_miss=0;
	ret->num_hash_comps=0;

	ret->error=0;
	return(ret);
err1:
	OPENSSL_free(ret);
err0:
	return(NULL);
	}

/* crypto/x509/x509_ext.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



int X509_get_ext_count(X509 *x)
{
	return(X509v3_get_ext_count(x->cert_info->extensions));
}

/* crypto/x509/x509_v3.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


int X509v3_get_ext_count(const STACK_OF(X509_EXTENSION) *x)
	{
	if (x == NULL) return(0);
	return(sk_X509_EXTENSION_num(x));
	}

ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex)
	{
	if (ex == NULL) return(NULL);
	return(ex->object);
	}



unsigned char cleanse_ctr = 0;

void OPENSSL_cleanse(void *ptr, size_t len)
{
	unsigned char *p = ptr;
	size_t loop = len, ctr = cleanse_ctr;
	while(loop--)
		{
		*(p++) = (unsigned char)ctr;
		ctr += (17 + ((size_t)p & 0xF));
		}
	p=memchr(ptr, (unsigned char)ctr, len);
	if(p)
		ctr += (63 + (size_t)p);
	cleanse_ctr = (unsigned char)ctr;
}


void *CRYPTO_malloc(int num, const char *file, int line)
	{
	if (num <= 0) return NULL;

	return malloc(num);
	}

void *CRYPTO_realloc(void *str, int num, const char *file, int line)
	{
	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	return realloc(str, num);
	}

void *CRYPTO_realloc_clean(void *str, int old_len, int num, const char *file,
			   int line)
	{
	void *ret = NULL;

	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	/* We don't support shrinking the buffer. Note the memcpy that copies
	 * |old_len| bytes to the new buffer, below. */
	if (num < old_len) return NULL;

	ret =  malloc(num);
	if(ret)
		{
		memcpy(ret,str,old_len);
		OPENSSL_cleanse(str,old_len);
		free(str);
		}

	return ret;
	}

void CRYPTO_free(void *str)
	{
	free(str);
	}

void *CRYPTO_remalloc(void *a, int num, const char *file, int line)
	{
	if (a != NULL) free(a);
	a=(char *)malloc(num);
	return(a);
	}


void reset_CRYPTO_reset(void)
{
	cleanse_ctr = 0;
}

//static RSA_METHOD rsa_pkcs1_eay_meth={		//--hgl--20140331--RW mem to const mem
const RSA_METHOD rsa_pkcs1_eay_meth={
	"Eric Young's PKCS#1 RSA",
	0, /* flags */
	NULL,
	0, /* rsa_sign */
	0, /* rsa_verify */
	NULL /* rsa_keygen */
	};
/////////////////////RSA_new////////////////////////////////////////ok

RSA *RSA_new(void)
	{
		
	RSA *r=RSA_new_method(NULL);
	
	return r;
	}

///////////////////RSA_new_method///////////////////////////////////////ok

RSA *RSA_new_method(ENGINE *engine)
	{
	RSA *ret;
	
	ret=(RSA *)OPENSSL_malloc(sizeof(RSA));
	if (ret == NULL)
		{
		RSAerr(RSA_F_RSA_NEW_METHOD,ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	ret->meth = &rsa_pkcs1_eay_meth;

	ret->pad=0;
	ret->version=0;
	ret->n=NULL;
	ret->e=NULL;
	ret->d=NULL;
	ret->p=NULL;
	ret->q=NULL;
	ret->dmp1=NULL;
	ret->dmq1=NULL;
	ret->iqmp=NULL;
	ret->references=1;
	ret->_method_mod_n=NULL;
	ret->_method_mod_p=NULL;
	ret->_method_mod_q=NULL;
	ret->blinding=NULL;
	ret->mt_blinding=NULL;
	ret->bignum_data=NULL;
	ret->flags=ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
	if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data))
		{
		OPENSSL_free(ret);
		return(NULL);
		}

	if ((ret->meth->init != NULL) && !ret->meth->init(ret))
		{
		CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data);
		OPENSSL_free(ret);
		ret=NULL;
		}
	return(ret);
	}




////////////ERR_put_error/////////////////////////////////////

void ERR_put_error(int lib, int func, int reason, const char *file,
	     int line)
{

	;
}


#define ADDED_NID	3
#define ADDED_DATA	0

//#define OBJerr(f,r)  ERR_PUT_error(ERR_LIB_OBJ,(f),(r),__FILE__,__LINE__)

typedef struct added_obj_st
{
	int type;
	ASN1_OBJECT *obj;
} ADDED_OBJ;

static LHASH *added=NULL;

void reset_OBJ_nid2ln_reset(void)
{
	added=NULL;
}
/////////////OBJ_nid2ln/////////////////////////ok

const char *OBJ_nid2ln(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			return(NULL);
			}
		return(nid_objs[n].ln);
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj->ln);
		else
		{
			return(NULL);
		}
	}
}
///////////////OBJ_bsearch/////////////////ok

const char *OBJ_bsearch(const char *key, const char *base, int num, int size,
	int (*cmp)(const void *, const void *))
{

	return OBJ_bsearch_ex(key, base, num, size, cmp, 0);
}

//////////////////////////////////////////////////////////////////ok

const char *OBJ_bsearch_ex(const char *key, const char *base, int num,
	int size, int (*cmp)(const void *, const void *), int flags)
{
	int l,h,i=0,c=0;
	const char *p = NULL;

	if (num == 0) return(NULL);
	l=0;
	h=num;
	while (l < h)
		{
		i=(l+h)/2;
		p= &(base[i*size]);
		c=(*cmp)(key,p);
		if (c < 0)
			h=i;
		else if (c > 0)
			l=i+1;
		else
			break;
}
//#ifdef CHARSET_EBCDIC			//###samyang  modity
/* THIS IS A KLUDGE - Because the *_obj is sorted in ASCII order, and
 * I don't have perl (yet), we revert to a *LINEAR* search
 * when the object wasn't found in the binary search.
 */
	if (c != 0)
		{
		for (i=0; i<num; ++i)
			{
			p= &(base[i*size]);
			c = (*cmp)(key,p);
			if (c == 0 || (c < 0 && (flags & OBJ_BSEARCH_VALUE_ON_NOMATCH)))
				return p;
			}
		}
//#endif		////###samyang  modity
	if (c != 0 && !(flags & OBJ_BSEARCH_VALUE_ON_NOMATCH))
		p =NULL;//&(base[78*size]);
	else if (c == 0 && (flags & OBJ_BSEARCH_FIRST_VALUE_ON_MATCH))
		{
		while(i > 0 && (*cmp)(key,&(base[(i-1)*size])) == 0)
			i--;
		p = &(base[i*size]);
		}
	return(p);
	}

//////////////////obj_cmp//////////////////ok

static int obj_cmp(const void *ap, const void *bp)
{
	int j;
	const ASN1_OBJECT *a= *(ASN1_OBJECT * const *)ap;
	const ASN1_OBJECT *b= *(ASN1_OBJECT * const *)bp;

	j=(a->length - b->length);
        if (j) return(j);
	return(memcmp(a->data,b->data,a->length));
  }
///////////////////OBJ_obj2nid//////////////////////ok

int OBJ_obj2nid(const ASN1_OBJECT *a)
	{
	ASN1_OBJECT **op;
	ADDED_OBJ ad,*adp;

	if (a == NULL)
		return(NID_undef);
	if (a->nid != 0)
		return(a->nid);

	if (added != NULL)
		{
		ad.type=ADDED_DATA;
		ad.obj=(ASN1_OBJECT *)a; /* XXX: ugly but harmless */
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL) return (adp->obj->nid);
		}
	op=(ASN1_OBJECT **)OBJ_bsearch((const char *)&a,(const char *)obj_objs,
		NUM_OBJ, sizeof(ASN1_OBJECT *),obj_cmp);
	if (op == NULL)
		return(NID_undef);
	return((*op)->nid);
	}


///////////////OBJ_nid2obj////////////////////////////////ok

ASN1_OBJECT *OBJ_nid2obj(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
		{

			return(NULL);
		}
		return((ASN1_OBJECT *)&(nid_objs[n]));
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=(ADDED_OBJ *)lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj);
		else
		{
			return(NULL);
		}
	}
}

const char *OBJ_nid2sn(int n)
{
	ADDED_OBJ ad,*adp;
	ASN1_OBJECT ob;

	if ((n >= 0) && (n < NUM_NID))
	{
		if ((n != NID_undef) && (nid_objs[n].nid == NID_undef))
			{
			OBJerr(OBJ_F_OBJ_NID2SN,OBJ_R_UNKNOWN_NID);
			return(NULL);
			}
		return(nid_objs[n].sn);
	}
	else if (added == NULL)
		return(NULL);
	else
	{
		ad.type=ADDED_NID;
		ad.obj= &ob;
		ob.nid=n;
		adp=lh_retrieve(added,&ad);
		if (adp != NULL)
			return(adp->obj->sn);
		else
			{
				return(NULL);
			}
	}
}


int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name)
{
//	int i,n=0,len,nid, first, use_bn;
//	BIGNUM *bl;
//	unsigned long l;
//	const unsigned char *p;
//	char tbuf[DECIMAL_SIZE(i)+DECIMAL_SIZE(l)+2];
//
//	if ((a == NULL) || (a->data == NULL)) {
//		buf[0]='\0';
//		return(0);
//	}
//
//	if (!no_name && (nid=OBJ_obj2nid(a)) != NID_undef)
//		{
//		const char *s;
//		s=OBJ_nid2ln(nid);
//		if (s == NULL)
//			s=OBJ_nid2sn(nid);
//		if (s)
//			{
//			if (buf)
//				strncpy(buf,s,buf_len);
//			n=strlen(s);
//			return n;
//			}
//		}
//
//	len=a->length;
//	p=a->data;
//
//	first = 1;
//	bl = NULL;
//
//	while (len > 0)
//		{
//		l=0;
//		use_bn = 0;
//		for (;;)
//			{
//			unsigned char c = *p++;
//			len--;
//			if ((len == 0) && (c & 0x80))
//				goto err;
//			if (use_bn)
//				{
//				if (!BN_add_word(bl, c & 0x7f))
//					goto err;
//				}
//			else
//				l |= c  & 0x7f;
//			if (!(c & 0x80))
//				break;
//			if (!use_bn && (l > (ULONG_MAX >> 7L)))
//				{
//				if (!bl && !(bl = BN_new()))
//					goto err;
//				if (!BN_set_word(bl, l))
//					goto err;
//				use_bn = 1;
//				}
//			if (use_bn)
//				{
//				if (!BN_lshift(bl, bl, 7))
//					goto err;
//				}
//			else
//				l<<=7L;
//			}
//
//		if (first)
//			{
//			first = 0;
//			if (l >= 80)
//				{
//				i = 2;
//				if (use_bn)
//					{
//					if (!BN_sub_word(bl, 80))
//						goto err;
//					}
//				else
//					l -= 80;
//				}
//			else
//				{
//				i=(int)(l/40);
//				l-=(long)(i*40);
//				}
//			if (buf && (buf_len > 0))
//				{
//				*buf++ = i + '0';
//				buf_len--;
//				}
//			n++;
//			}
//
//		if (use_bn)
//			{
//			char *bndec;
//			bndec = BN_bn2dec(bl);
//			if (!bndec)
//				goto err;
//			i = strlen(bndec);
//			if (buf)
//				{
//				if (buf_len > 0)
//					{
//					*buf++ = '.';
//					buf_len--;
//					}
//				strncpy(buf,bndec,buf_len);
//				if (i > buf_len)
//					{
//					buf += buf_len;
//					buf_len = 0;
//					}
//				else
//					{
//					buf+=i;
//					buf_len-=i;
//					}
//				}
//			n++;
//			n += i;
//			OPENSSL_free(bndec);
//			}
//		else
//			{
//			BIO_snprintf(tbuf,sizeof tbuf,".%lu",l);
//			i=strlen(tbuf);
//			if (buf && (buf_len > 0))
//				{
//				strncpy(buf,tbuf,buf_len);
//				if (i > buf_len)
//					{
//					buf += buf_len;
//					buf_len = 0;
//					}
//				else
//					{
//					buf+=i;
//					buf_len-=i;
//					}
//				}
//			n+=i;
//			l=0;
//			}
//		}
//
//	if (bl)
//		BN_free(bl);
//	return n;
//
//	err:
//	if (bl)
//		BN_free(bl);
	return -1;
}

int OBJ_obj2name(char *dst_buf, int buf_len, const ASN1_OBJECT *a)
{
	if(buf_len < a->length)
	{
		printf("OBJ_obj2name err: not enough buffer to store name\n");

		return -1;
	}
	memcpy(dst_buf, a->data, a->length);

	return a->length;
}
//#define BN_ULONG	unsigned long	//samyang add  depend on bn.h
//#define BN_BITS2	32

struct bn_blinding_st
	{
	BIGNUM *A;
	BIGNUM *Ai;
	BIGNUM *e;
	BIGNUM *mod; /* just a reference */
	unsigned long thread_id; /* added in OpenSSL 0.9.6j and 0.9.7b;
				  * used only by crypto/rsa/rsa_eay.c, rsa_lib.c */
	unsigned int  counter;
	unsigned long flags;
	BN_MONT_CTX *m_ctx;
	int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			  const BIGNUM *m, BN_CTX *ctx,
			  BN_MONT_CTX *m_ctx);
	};

typedef struct bn_blinding_st BN_BLINDING;


///////////////BN_new/////////////////////////////////ok

BIGNUM *BN_new(void)
	{
	BIGNUM *ret;
	if ((ret=(BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL)
		{
		BNerr(BN_F_BN_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	ret->flags=BN_FLG_MALLOCED;
	ret->top=0;
	ret->neg=0;
	ret->dmax=0;
	ret->d=NULL;
	bn_check_top(ret);
	return(ret);
	}

////////////////bn_expand_internal//////////////////////////////ok

static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
	{
	BN_ULONG *A,*a = NULL;
	const BN_ULONG *B;
	int i;
	bn_check_top(b);

	if (words > (INT_MAX/(4*BN_BITS2)))
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_BIGNUM_TOO_LONG);
		return NULL;
		}
	if (BN_get_flags(b,BN_FLG_STATIC_DATA))
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return(NULL);
		}
	a=A=(BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG)*words);
	if (A == NULL)
		{
		BNerr(BN_F_BN_EXPAND_INTERNAL,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
#if 1
	B=b->d;

	if (B != NULL)
		{
		for (i=b->top>>2; i>0; i--,A+=4,B+=4)
			{

			BN_ULONG a0,a1,a2,a3;
			a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
			A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
			}
		switch (b->top&3)
			{
		case 3:	A[2]=B[2];
		case 2:	A[1]=B[1];
		case 1:	A[0]=B[0];
		case 0:
			;
			}
		}

#else
	memset(A,0,sizeof(BN_ULONG)*words);
	memcpy(A,b->d,sizeof(b->d[0])*b->top);
#endif

	return(a);
	}

//////////////bn_expand2///////////////////////////////ok

BIGNUM *bn_expand2(BIGNUM *b, int words)
	{
	bn_check_top(b);

	if (words > b->dmax)
		{
		BN_ULONG *a = bn_expand_internal(b, words);
		if(!a) return NULL;
		if(b->d) OPENSSL_free(b->d);
		b->d=a;
		b->dmax=words;
		}
	bn_check_top(b);
	return b;
	}

////////////BN_num_bits_word//////////////////////////ok

int BN_num_bits_word(BN_ULONG l)
	{
	static const char bits[256]={
		0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
		5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		};


#ifdef SIXTY_FOUR_BIT
	if (l & 0xffffffff00000000LL)
		{
		if (l & 0xffff000000000000LL)
			{
			if (l & 0xff00000000000000LL)
				{
				return(bits[(int)(l>>56)]+56);
				}
			else	return(bits[(int)(l>>48)]+48);
			}
		else
			{
			if (l & 0x0000ff0000000000LL)
				{
				return(bits[(int)(l>>40)]+40);
				}
			else	return(bits[(int)(l>>32)]+32);
			}
		}
	else
#endif

		{
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
		if (l & 0xffff0000L)
			{
			if (l & 0xff000000L)
				return(bits[(int)(l>>24L)]+24);
			else	return(bits[(int)(l>>16L)]+16);
			}
		else
#endif
			{
#if defined(SIXTEEN_BIT) || defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
			if (l & 0xff00L)
				return(bits[(int)(l>>8)]+8);
			else
#endif
				return(bits[(int)(l   )]  );
			}
		}
	}

////////////BN_num_bits///////////////////////////ok

int BN_num_bits(const BIGNUM *a)
{
	int i = a->top - 1;
	bn_check_top(a);

	if (BN_is_zero(a)) return 0;
	return ((i*BN_BITS2) + BN_num_bits_word(a->d[i]));
}

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
	{
	BN_ULONG ret = 0;
	int i, j;

	bn_check_top(a);
	w &= BN_MASK2;

	if (!w)
		/* actually this an error (division by zero) */
		return (BN_ULONG)-1;
	if (a->top == 0)
		return 0;

	/* normalize input (so bn_div_words doesn't complain) */
	j = BN_BITS2 - BN_num_bits_word(w);
	w <<= j;
	if (!BN_lshift(a, a, j))
		return (BN_ULONG)-1;

	for (i=a->top-1; i>=0; i--)
		{
		BN_ULONG l,d;

		l=a->d[i];
		d=bn_div_words(ret,l,w);
		ret=(l-((d*w)&BN_MASK2))&BN_MASK2;
		a->d[i]=d;
		}
	if ((a->top > 0) && (a->d[a->top-1] == 0))
		a->top--;
	ret >>= j;
	bn_check_top(a);
	return(ret);
	}


int BN_add_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG l;
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a)) return BN_set_word(a, w);
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_sub_word(a,w);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return(i);
		}
	for (i=0;w!=0 && i<a->top;i++)
		{
		a->d[i] = l = (a->d[i]+w)&BN_MASK2;
		w = (w>l)?1:0;
		}
	if (w && i==a->top)
		{
		if (bn_wexpand(a,a->top+1) == NULL) return 0;
		a->top++;
		a->d[i]=w;
		}
	bn_check_top(a);
	return(1);
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
	{
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w) return 1;
	/* degenerate case: a is zero */
	if(BN_is_zero(a))
		{
		i = BN_set_word(a,w);
		if (i != 0)
			BN_set_negative(a, 1);
		return i;
		}
	/* handle 'a' when negative */
	if (a->neg)
		{
		a->neg=0;
		i=BN_add_word(a,w);
		a->neg=1;
		return(i);
		}

	if ((a->top == 1) && (a->d[0] < w))
		{
		a->d[0]=w-a->d[0];
		a->neg=1;
		return(1);
		}
	i=0;
	for (;;)
		{
		if (a->d[i] >= w)
			{
			a->d[i]-=w;
			break;
			}
		else
			{
			a->d[i]=(a->d[i]-w)&BN_MASK2;
			i++;
			w=1;
			}
		}
	if ((a->d[i] == 0) && (i == (a->top-1)))
		a->top--;
	bn_check_top(a);
	return(1);
	}
/* crypto/bn/bn_shift.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


//int BN_lshift1(BIGNUM *r, const BIGNUM *a)
//	{
//	register BN_ULONG *ap,*rp,t,c;
//	int i;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	if (r != a)
//		{
//		r->neg=a->neg;
//		if (bn_wexpand(r,a->top+1) == NULL) return(0);
//		r->top=a->top;
//		}
//	else
//		{
//		if (bn_wexpand(r,a->top+1) == NULL) return(0);
//		}
//	ap=a->d;
//	rp=r->d;
//	c=0;
//	for (i=0; i<a->top; i++)
//		{
//		t= *(ap++);
//		*(rp++)=((t<<1)|c)&BN_MASK2;
//		c=(t & BN_TBIT)?1:0;
//		}
//	if (c)
//		{
//		*rp=1;
//		r->top++;
//		}
//	bn_check_top(r);
//	return(1);
//	}

//int BN_rshift1(BIGNUM *r, const BIGNUM *a)
//	{
//	BN_ULONG *ap,*rp,t,c;
//	int i,j;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	if (BN_is_zero(a))
//		{
//		BN_zero(r);
//		return(1);
//		}
//	i = a->top;
//	ap= a->d;
//	j = i-(ap[i-1]==1);
//	if (a != r)
//		{
//		if (bn_wexpand(r,j) == NULL) return(0);
//		r->neg=a->neg;
//		}
//	rp=r->d;
//	t=ap[--i];
//	c=(t&1)?BN_TBIT:0;
//	if (t>>=1) rp[i]=t;
//	while (i>0)
//		{
//		t=ap[--i];
//		rp[i]=((t>>1)&BN_MASK2)|c;
//		c=(t&1)?BN_TBIT:0;
//		}
//	r->top=j;
//	bn_check_top(r);
//	return(1);
//	}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
	{
	int i,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l;

	bn_check_top(r);
	bn_check_top(a);

	r->neg=a->neg;
	nw=n/BN_BITS2;
	if (bn_wexpand(r,a->top+nw+1) == NULL) return(0);
	lb=n%BN_BITS2;
	rb=BN_BITS2-lb;
	f=a->d;
	t=r->d;
	t[a->top+nw]=0;
	if (lb == 0)
		for (i=a->top-1; i>=0; i--)
			t[nw+i]=f[i];
	else
		for (i=a->top-1; i>=0; i--)
			{
			l=f[i];
			t[nw+i+1]|=(l>>rb)&BN_MASK2;
			t[nw+i]=(l<<lb)&BN_MASK2;
			}
	memset(t,0,nw*sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top=a->top+nw+1;
	bn_correct_top(r);
	bn_check_top(r);
	return(1);
	}

//int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
//	{
//	int i,j,nw,lb,rb;
//	BN_ULONG *t,*f;
//	BN_ULONG l,tmp;
//
//	bn_check_top(r);
//	bn_check_top(a);
//
//	nw=n/BN_BITS2;
//	rb=n%BN_BITS2;
//	lb=BN_BITS2-rb;
//	if (nw >= a->top || a->top == 0)
//		{
//		BN_zero(r);
//		return(1);
//		}
//	i = (BN_num_bits(a)-n+(BN_BITS2-1))/BN_BITS2;
//	if (r != a)
//		{
//		r->neg=a->neg;
//		if (bn_wexpand(r,i) == NULL) return(0);
//		}
//	else
//		{
//		if (n == 0)
//			return 1; /* or the copying loop will go berserk */
//		}
//
//	f= &(a->d[nw]);
//	t=r->d;
//	j=a->top-nw;
//	r->top=i;
//
//	if (rb == 0)
//		{
//		for (i=j; i != 0; i--)
//			*(t++)= *(f++);
//		}
//	else
//		{
//		l= *(f++);
//		for (i=j-1; i != 0; i--)
//			{
//			tmp =(l>>rb)&BN_MASK2;
//			l= *(f++);
//			*(t++) =(tmp|(l<<lb))&BN_MASK2;
//			}
//		if ((l = (l>>rb)&BN_MASK2)) *(t) = l;
//		}
//	bn_check_top(r);
//	return(1);
//	}

/////////////////// BN_bn2bin////////////////////////////////////////ok

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
	{
	int n,i;
	BN_ULONG l;
	
	bn_check_top(a);
	n=i=BN_num_bytes(a);
	while (i--)
		{
		l=a->d[i/BN_BYTES];
		*(to++)=(unsigned char)(l>>(8*(i%BN_BYTES)))&0xff;
		}
	return(n);
	}

////////////////BN_bin2bn/////////////////////////////////////////////////ok

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
	{
	unsigned int i,m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM  *bn = NULL;
	
	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL) return(NULL);
	bn_check_top(ret);
	l=0;
	n=len;
	if (n == 0)
		{
		ret->top=0;
		return(ret);
		}
	i=((n-1)/BN_BYTES)+1;
	m=((n-1)%(BN_BYTES));
	if (bn_wexpand(ret, (int)i) == NULL)
		{
		//if (bn) BN_free(bn);
		return NULL;
		}
	ret->top=i;
	ret->neg=0;
	while (n--)
		{
		l=(l<<8L)| *(s++);
		if (m-- == 0)
			{
			ret->d[--i]=l;
			l=0;
			m=BN_BYTES-1;
			}
		}

	bn_correct_top(ret);
	return(ret);
	}

/* crypto/bn/bn_print.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


extern int BIO_snprintf(char *buf, size_t n, const char *format, ...);

static const char Hex[]="0123456789ABCDEF";

/* Must 'OPENSSL_free' the returned data */
//char *BN_bn2hex(const BIGNUM *a)
//	{
//	int i,j,v,z=0;
//	char *buf;
//	char *p;
//
//	buf=(char *)OPENSSL_malloc(a->top*BN_BYTES*2+2);
//	if (buf == NULL)
//		{
//		BNerr(BN_F_BN_BN2HEX,ERR_R_MALLOC_FAILURE);
//		goto err;
//		}
//	p=buf;
//	if (a->neg) *(p++)='-';
//	if (BN_is_zero(a)) *(p++)='0';
//	for (i=a->top-1; i >=0; i--)
//		{
//		for (j=BN_BITS2-8; j >= 0; j-=8)
//			{
//			/* strip leading zeros */
//			v=((int)(a->d[i]>>(long)j))&0xff;
//			if (z || (v != 0))
//				{
//				*(p++)=Hex[v>>4];
//				*(p++)=Hex[v&0x0f];
//				z=1;
//				}
//			}
//		}
//	*p='\0';
//err:
//	return(buf);
//	}

/* Must 'OPENSSL_free' the returned data */
char *BN_bn2dec(const BIGNUM *a)
	{
	int i=0,num, ok = 0;
	char *buf=NULL;
	char *p;
	BIGNUM *t=NULL;
	BN_ULONG *bn_data=NULL,*lp;

	/* get an upper bound for the length of the decimal integer
	 * num <= (BN_num_bits(a) + 1) * log(2)
	 *     <= 3 * BN_num_bits(a) * 0.1001 + log(2) + 1     (rounding error)
	 *     <= BN_num_bits(a)/10 + BN_num_bits/1000 + 1 + 1
	 */
	i=BN_num_bits(a)*3;
	num=(i/10+i/1000+1)+1;
	bn_data=(BN_ULONG *)OPENSSL_malloc((num/BN_DEC_NUM+1)*sizeof(BN_ULONG));
	buf=(char *)OPENSSL_malloc(num+3);
	if ((buf == NULL) || (bn_data == NULL))
		{
		goto err;
		}
	if ((t=BN_dup(a)) == NULL) goto err;

#define BUF_REMAIN (num+3 - (size_t)(p - buf))
	p=buf;
	lp=bn_data;
	if (BN_is_zero(t))
		{
		*(p++)='0';
		*(p++)='\0';
		}
	else
		{
		if (BN_is_negative(t))
			*p++ = '-';

		i=0;
		while (!BN_is_zero(t))
			{
			*lp=BN_div_word(t,BN_DEC_CONV);
			lp++;
			}
		lp--;
		/* We now have a series of blocks, BN_DEC_NUM chars
		 * in length, where the last one needs truncation.
		 * The blocks need to be reversed in order. */
		BIO_snprintf(p,BUF_REMAIN,BN_DEC_FMT1,*lp);
		while (*p) p++;
		while (lp != bn_data)
			{
			lp--;
			BIO_snprintf(p,BUF_REMAIN,BN_DEC_FMT2,*lp);
			while (*p) p++;
			}
		}
	ok = 1;
err:
	if (bn_data != NULL) OPENSSL_free(bn_data);
	if (t != NULL) BN_free(t);
	if (!ok && buf)
		{
		OPENSSL_free(buf);
		buf = NULL;
		}

	return(buf);
	}

//int BN_hex2bn(BIGNUM **bn, const char *a)
//	{
//		printf("%s %d %s\n", __FILE__, __LINE__, __func__);
//	BIGNUM *ret=NULL;
//	BN_ULONG l=0;
//	int neg=0,h,m,i,j,k,c;
//	int num;
//
//	if ((a == NULL) || (*a == '\0')) return(0);
//
//	if (*a == '-') { neg=1; a++; }
//
//	for (i=0; isxdigit((unsigned char) a[i]); i++)
//		;
//
//	num=i+neg;
//	if (bn == NULL) return(num);
//
//	/* a is the start of the hex digits, and it is 'i' long */
//	if (*bn == NULL)
//		{
//		if ((ret=BN_new()) == NULL) return(0);
//		}
//	else
//		{
//		ret= *bn;
//		BN_zero(ret);
//		}
//
//	/* i is the number of hex digests; */
//	if (bn_expand(ret,i*4) == NULL) goto err;
//
//	j=i; /* least significant 'hex' */
//	m=0;
//	h=0;
//	while (j > 0)
//		{
//		m=((BN_BYTES*2) <= j)?(BN_BYTES*2):j;
//		l=0;
//		for (;;)
//			{
//			c=a[j-m];
//			if ((c >= '0') && (c <= '9')) k=c-'0';
//			else if ((c >= 'a') && (c <= 'f')) k=c-'a'+10;
//			else if ((c >= 'A') && (c <= 'F')) k=c-'A'+10;
//			else k=0; /* paranoia */
//			l=(l<<4)|k;
//
//			if (--m <= 0)
//				{
//				ret->d[h++]=l;
//				break;
//				}
//			}
//		j-=(BN_BYTES*2);
//		}
//	ret->top=h;
//	bn_correct_top(ret);
//	ret->neg=neg;
//
//	*bn=ret;
//	bn_check_top(ret);
//	return(num);
//err:
//	if (*bn == NULL) BN_free(ret);
//	return(0);
//	}

//int BN_dec2bn(BIGNUM **bn, const char *a)
//	{
//		printf("%s %d %s\n", __FILE__, __LINE__, __func__);
//	BIGNUM *ret=NULL;
//	BN_ULONG l=0;
//	int neg=0,i,j;
//	int num;
//
//	if ((a == NULL) || (*a == '\0')) return(0);
//	if (*a == '-') { neg=1; a++; }
//
//	for (i=0; isdigit((unsigned char) a[i]); i++)
//		;
//
//	num=i+neg;
//	if (bn == NULL) return(num);
//
//	/* a is the start of the digits, and it is 'i' long.
//	 * We chop it into BN_DEC_NUM digits at a time */
//	if (*bn == NULL)
//		{
//		if ((ret=BN_new()) == NULL) return(0);
//		}
//	else
//		{
//		ret= *bn;
//		BN_zero(ret);
//		}
//
//	/* i is the number of digests, a bit of an over expand; */
//	if (bn_expand(ret,i*4) == NULL) goto err;
//
//	j=BN_DEC_NUM-(i%BN_DEC_NUM);
//	if (j == BN_DEC_NUM) j=0;
//	l=0;
//	while (*a)
//		{
//		l*=10;
//		l+= *a-'0';
//		a++;
//		if (++j == BN_DEC_NUM)
//			{
//			BN_mul_word(ret,BN_DEC_CONV);
//			BN_add_word(ret,l);
//			l=0;
//			j=0;
//			}
//		}
//	ret->neg=neg;
//
//	bn_correct_top(ret);
//	*bn=ret;
//	bn_check_top(ret);
//	return(num);
//err:
//	if (*bn == NULL) BN_free(ret);
//	return(0);
//	}

//int BN_asc2bn(BIGNUM **bn, const char *a)
//	{
//	const char *p = a;
//	if (*p == '-')
//		p++;
//
//	if (p[0] == '0' && (p[1] == 'X' || p[1] == 'x'))
//		{
//		if (!BN_hex2bn(bn, p + 2))
//			return 0;
//		}
//	else
//		{
//		if (!BN_dec2bn(bn, p))
//			return 0;
//		}
//	if (*a == '-')
//		(*bn)->neg = 1;
//	return 1;
//	}

//#ifndef OPENSSL_NO_BIO
//
//
//int BN_print(BIO *bp, const BIGNUM *a)
//	{
//	int i,j,v,z=0;
//	int ret=0;
//
//	if ((a->neg) && (BIO_write(bp,"-",1) != 1)) goto end;
//	if (BN_is_zero(a) && (BIO_write(bp,"0",1) != 1)) goto end;
//	for (i=a->top-1; i >=0; i--)
//		{
//		for (j=BN_BITS2-4; j >= 0; j-=4)
//			{
//			/* strip leading zeros */
//			v=((int)(a->d[i]>>(long)j))&0x0f;
//			if (z || (v != 0))
//				{
//				if (BIO_write(bp,&(Hex[v]),1) != 1)
//					goto end;
//				z=1;
//				}
//			}
//		}
//	ret=1;
//end:
//	return(ret);
//	}
//#endif

//char *BN_options(void)
//	{
//	static int init=0;
//	static char data[16];
//
//	if (!init)
//		{
//		init++;
//#ifdef BN_LLONG
//		BIO_snprintf(data,sizeof data,"bn(%d,%d)",
//			     (int)sizeof(BN_ULLONG)*8,(int)sizeof(BN_ULONG)*8);
//#else
//		BIO_snprintf(data,sizeof data,"bn(%d,%d)",
//			     (int)sizeof(BN_ULONG)*8,(int)sizeof(BN_ULONG)*8);
//#endif
//		}
//	return(data);
//	}
/* crypto/bn/bn_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


void BN_free(BIGNUM *a)
	{
	if (a == NULL) return;
	bn_check_top(a);
	if ((a->d != NULL) && !(BN_get_flags(a,BN_FLG_STATIC_DATA)))
		OPENSSL_free(a->d);
	if (a->flags & BN_FLG_MALLOCED)
		OPENSSL_free(a);
	else
		{
		a->d = NULL;
		}
	}

BIGNUM *BN_dup(const BIGNUM *a)
	{
	BIGNUM *t;

	if (a == NULL) return NULL;
	bn_check_top(a);

	t = BN_new();
	if (t == NULL) return NULL;
	if(!BN_copy(t, a))
		{
		BN_free(t);
		return NULL;
		}
	bn_check_top(t);
	return t;
	}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
	{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;

	bn_check_top(b);

	if (a == b) return(a);
	if (bn_wexpand(a,b->top) == NULL) return(NULL);

#if 1
	A=a->d;
	B=b->d;
	for (i=b->top>>2; i>0; i--,A+=4,B+=4)
		{
		BN_ULONG a0,a1,a2,a3;
		a0=B[0]; a1=B[1]; a2=B[2]; a3=B[3];
		A[0]=a0; A[1]=a1; A[2]=a2; A[3]=a3;
		}
	switch (b->top&3)
		{
		case 3: A[2]=B[2];
		case 2: A[1]=B[1];
		case 1: A[0]=B[0];
		case 0: ; /* ultrix cc workaround, see comments in bn_expand_internal */
		}
#else
	memcpy(a->d,b->d,sizeof(b->d[0])*b->top);
#endif

	a->top=b->top;
	a->neg=b->neg;
	bn_check_top(a);
	return(a);
	}

int BN_set_word(BIGNUM *a, BN_ULONG w)
	{
	bn_check_top(a);
	if (bn_expand(a,(int)sizeof(BN_ULONG)*8) == NULL) return(0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	bn_check_top(a);
	return(1);
	}

void BN_set_negative(BIGNUM *a, int b)
	{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
	}
/* crypto/bn/bn_asm.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */



//#if defined(BN_LLONG) || defined(BN_UMULT_HIGH)
//
//BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c1=0;
//
//	assert(num >= 0);
//	if (num <= 0) return(c1);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul_add(rp[0],ap[0],w,c1);
//		mul_add(rp[1],ap[1],w,c1);
//		mul_add(rp[2],ap[2],w,c1);
//		mul_add(rp[3],ap[3],w,c1);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul_add(rp[0],ap[0],w,c1);
//		ap++; rp++; num--;
//		}
//
//	return(c1);
//	}
//
//BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c1=0;
//
//	assert(num >= 0);
//	if (num <= 0) return(c1);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul(rp[0],ap[0],w,c1);
//		mul(rp[1],ap[1],w,c1);
//		mul(rp[2],ap[2],w,c1);
//		mul(rp[3],ap[3],w,c1);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul(rp[0],ap[0],w,c1);
//		ap++; rp++; num--;
//		}
//	return(c1);
//	}
//
//void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
//        {
//	assert(n >= 0);
//	if (n <= 0) return;
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (n&~3)
//		{
//		sqr(r[0],r[1],a[0]);
//		sqr(r[2],r[3],a[1]);
//		sqr(r[4],r[5],a[2]);
//		sqr(r[6],r[7],a[3]);
//		a+=4; r+=8; n-=4;
//		}
//#endif
//	while (n)
//		{
//		sqr(r[0],r[1],a[0]);
//		a++; r+=2; n--;
//		}
//	}
//
//#else /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
//
//BN_ULONG bn_mul_add_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG c=0;
//	BN_ULONG bl,bh;
//
//	assert(num >= 0);
//	if (num <= 0) return((BN_ULONG)0);
//
//	bl=LBITS(w);
//	bh=HBITS(w);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul_add(rp[0],ap[0],bl,bh,c);
//		mul_add(rp[1],ap[1],bl,bh,c);
//		mul_add(rp[2],ap[2],bl,bh,c);
//		mul_add(rp[3],ap[3],bl,bh,c);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul_add(rp[0],ap[0],bl,bh,c);
//		ap++; rp++; num--;
//		}
//	return(c);
//	}
//
//BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
//	{
//	BN_ULONG carry=0;
//	BN_ULONG bl,bh;
//
//	assert(num >= 0);
//	if (num <= 0) return((BN_ULONG)0);
//
//	bl=LBITS(w);
//	bh=HBITS(w);
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (num&~3)
//		{
//		mul(rp[0],ap[0],bl,bh,carry);
//		mul(rp[1],ap[1],bl,bh,carry);
//		mul(rp[2],ap[2],bl,bh,carry);
//		mul(rp[3],ap[3],bl,bh,carry);
//		ap+=4; rp+=4; num-=4;
//		}
//#endif
//	while (num)
//		{
//		mul(rp[0],ap[0],bl,bh,carry);
//		ap++; rp++; num--;
//		}
//	return(carry);
//	}
//
//void bn_sqr_words(BN_ULONG *r, const BN_ULONG *a, int n)
//        {
//	assert(n >= 0);
//	if (n <= 0) return;
//
//#ifndef OPENSSL_SMALL_FOOTPRINT
//	while (n&~3)
//		{
//		sqr64(r[0],r[1],a[0]);
//		sqr64(r[2],r[3],a[1]);
//		sqr64(r[4],r[5],a[2]);
//		sqr64(r[6],r[7],a[3]);
//		a+=4; r+=8; n-=4;
//		}
//#endif
//	while (n)
//		{
//		sqr64(r[0],r[1],a[0]);
//		a++; r+=2; n--;
//		}
//	}
//
//#endif /* !(defined(BN_LLONG) || defined(BN_UMULT_HIGH)) */
//
//
///* Divide h,l by d and return the result. */
///* I need to test this some more :-( */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
	{
	BN_ULONG dh,dl,q,ret=0,th,tl,t;
	int i,count=2;

	if (d == 0) return(BN_MASK2);

	i=BN_num_bits_word(d);
	assert((i == BN_BITS2) || (h <= (BN_ULONG)1<<i));

	i=BN_BITS2-i;
	if (h >= d) h-=d;

	if (i)
		{
		d<<=i;
		h=(h<<i)|(l>>(BN_BITS2-i));
		l<<=i;
		}
	dh=(d&BN_MASK2h)>>BN_BITS4;
	dl=(d&BN_MASK2l);
	for (;;)
		{
		if ((h>>BN_BITS4) == dh)
			q=BN_MASK2l;
		else
			q=h/dh;

		th=q*dh;
		tl=dl*q;
		for (;;)
			{
			t=h-th;
			if ((t&BN_MASK2h) ||
				((tl) <= (
					(t<<BN_BITS4)|
					((l&BN_MASK2h)>>BN_BITS4))))
				break;
			q--;
			th-=dh;
			tl-=dl;
			}
		t=(tl>>BN_BITS4);
		tl=(tl<<BN_BITS4)&BN_MASK2h;
		th+=t;

		if (l < tl) th++;
		l-=tl;
		if (h < th)
			{
			h+=d;
			q--;
			}
		h-=th;

		if (--count == 0) break;

		ret=q<<BN_BITS4;
		h=((h<<BN_BITS4)|(l>>BN_BITS4))&BN_MASK2;
		l=(l&BN_MASK2l)<<BN_BITS4;
		}
	ret|=q;
	return(ret);
	}


