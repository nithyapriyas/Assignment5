#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <math.h>
#include <gmp.h>
#include "ecc.h"

#define P "1332297598440044874827085558802491743757193798159"
#define A "297190522446607939568481567949428902921613329152"
#define B "173245649450172891208247283053495198538671808088"
#define XG "1089473557631435284577962539738532515920566082499"
#define YG "127912481829969033206777085249718746721365418785"
#define Block 10
#define Size 10000
#define PS (Size /(Block * 2) + 1)

mpz_t private_key;
char message[Size] = "\0";
char decMsg[10000] = "\0";
elliptic_curve *ec;
point* Public_Key, *PC1;
point PM1[PS], PD1[PS], PC21[PS];

char *my_itoa(int num, char *str)
{
    if(str == NULL)
    {
        return NULL;
    }
    sprintf(str, "%d", num);
    return str;
}

char * pad(char * str, int len, char c)
{
    if(len <= 0)
    {
        return str;
    }

    char padStr[Block * 4] = "\0";
    for(int i=0; i<len;i++)
    {
        strcat(padStr, "0");
    }

    strcat(padStr, str);
    memcpy(str, padStr, strlen(padStr));
    return str;
}

void convertStrToAscii(char * str, char* dst)
{
   for (int i=0; i<strlen(str); i++)
   {
       char temp[5];
       my_itoa(str[i], temp);
       char* t = pad(temp, 3-strlen(temp), '0');
       strcat(dst, t );
   }
}

void convertAsciiToStr(char * str, char* dst)
{
   for (int i=0; i<strlen(str); i=i+3)
   {
        char temp[5] = "\0", ch[2] = "\0";
        memcpy(temp, str+i, 3);
        ch[0] =atoi(temp);
        strcat(dst, ch );
   }
}

void GetMessagePoints()
{
    printf("\nMessage to be encrypted  : %s", message);

    int j=0;
    for(int i=0; i<strlen(message); i=i+Block)
    {
        char temp[Block * 4] = "\0", temp1[Block * 4] = "\0";
        memcpy(temp, message+i, Block);
        convertStrToAscii(temp, temp1);
        if(i%(Block * 2) == 0)
        {
            mpz_set_str(PM1[j].x, temp1, 10);
        }
        else
        {
            mpz_set_str(PM1[j].y, temp1, 10);
            j++;
        }
    }

    j=0;
    for(int i=0; i<strlen(message); i=i+Block*2)
    {
        gmp_printf("\nMessage Points PM%d       : (%50Zd, %50Zd)",j+1, PM1[j].x, PM1[j].y);
        j++;
    }
}

void RecoverMessage()
{
    char temp[Block * 4] = "\0";
    int j=0;
    for(int i=0; i<strlen(message); i=i+Block)
    {
        char * temp1;
        char temp[100] = "\0";

        if(i%20 == 0)
        {
            temp1 = mpz_get_str(NULL,10,PD1[j].x);
        }
        else
        {
            temp1 = mpz_get_str(NULL,10,PD1[j++].y);
        }

        memcpy(temp, temp1, strlen(temp1));

        int pl =  strlen(temp) % 3;
        if( pl != 0)
        {
            pad(temp, 3-pl, '0');
        }

        convertAsciiToStr(temp, decMsg);
    }
}

void generate_key()
{
    /*gmp_randstate_t k_state;
    gmp_randinit_mt(k_state);

    srand(time(0));
    int seed = rand();
    gmp_randseed_ui(k_state, seed);
    mpz_urandomb(private_key, k_state, 1000);*/

    mpz_set_str(private_key,"668803973771348696521102690459022921527186523653" ,10);
    mpz_t tmp;
    mpz_init_set(tmp, private_key);
    Public_Key = ecc_scalar_mul(ec, tmp, ec->base);
    mpz_clears(tmp, NULL);
}


void Decryption()
{
    printf("\n\n\n***********************************************************Decryption***********************************************************");

    // Calculating (Xm,Ym) = ((PC1->x*private_key)%p , (PC1->y*private_key)%p)
    point *t;
    t = ecc_scalar_mul(ec, private_key, PC1);
    mpz_neg(t->y, t->y);

    int j=0;
    for(int i=0; i< strlen(message); i = i+(Block * 2))
    {
        point tmp;
        mpz_init_set(tmp.x, t->x);
        mpz_init_set(tmp.y, t->y);

        point* dd = ecc_addition(ec, &PC21[j], &tmp);
        mpz_init_set(PD1[j].x, dd->x);
        mpz_init_set(PD1[j].y, dd->y);
        j++;
    }


    j=0;
    for(int i=0; i<strlen(message); i=i+Block*2)
    {
        gmp_printf("\nDecrypted Points PD%d     : (%50Zd, %50Zd)",j+1, PD1[j].x, PD1[j].y);
        j++;
    }

    RecoverMessage();
    printf("\n\nDecrypted Message        : %s", decMsg);
}

void Encryption()
{
    mpz_t tmp, r;
    mpz_inits(r, NULL);

    printf("\n\n\n***********************************************************Encryption***********************************************************\n");
    GetMessagePoints();
    // generating r randomly
    gmp_randstate_t r_state;

    gmp_randinit_mt(r_state);
    srand(time(0));
    int seed = rand();
    gmp_randseed_ui(r_state, seed);
    mpz_urandomb(r, r_state, 100);

    gmp_printf("\n\nRandom key generated     : %Zd", r);

    mpz_init_set(tmp, r);
    // Calculating C1(x,y) = r*G(x,y)
    PC1 = ecc_scalar_mul(ec, tmp, ec->base);
    mpz_init_set(tmp, r);
    
    gmp_printf("\nC1(x,y)                  : (%50Zd, %50Zd)\n", PC1->x, PC1->y);
    // Calculating C2(x,y) = r*Q(x,y) + Pm(x,y)
    int j=0;
    for(int i=0; i< strlen(message); i = i+(Block * 2))
    {
        point *t;

        mpz_init_set(tmp, r);
        t = ecc_scalar_mul(ec, tmp, Public_Key);
        t = ecc_addition(ec, t, &PM1[j]);
        mpz_init_set(PC21[j].x, t->x);
        mpz_init_set(PC21[j].y, t->y);

        gmp_printf("\nCypher Points %d(x,y)     : (%50Zd, %50Zd)",j, PC21[j].x, PC21[j].y);
        j++;
    }
    mpz_clears(tmp, NULL);
}

void Destroy_ECC()
{
    free(ec->base);
    free(ec);
}

void Init_ECC()
{
    mpz_inits(private_key, NULL);

    ec = (elliptic_curve*) malloc(sizeof(elliptic_curve));
    ec->base = (point*) malloc(sizeof(point));

    mpz_set_str(ec->p, P, 10);
    mpz_set_str(ec->base->x, XG,10);
    mpz_set_str(ec->base->y, YG,10);
    mpz_set_str(ec->a,A,10);
    mpz_set_str(ec->b,B,10);

    // generate random key
    generate_key();

    printf("\n\n***********************************************************System Elements***********************************************************");
    gmp_printf("\nPrime Number generated   : %Zd", ec->p);
    gmp_printf("\nElliptic Curve Eq(a,b)   : y2 = x3 + (%Zd)x + %Zd", ec->a, ec->b);
    gmp_printf("\nGenerator G(x,y)         : (%50Zd, %50Zd)", ec->base->x,ec->base->y);

    printf("\n\n\n***********************************************************Key Generation***********************************************************");
    gmp_printf("\nPrivate key              : %Zd", private_key);
    gmp_printf("\nPublic key Q(x,y)        : (%50Zd, %50Zd)", Public_Key->x, Public_Key->y);
}

int main()
{
    printf("\n\nEnter message            :");
    gets(message);

    Init_ECC();

    //encryption
    Encryption();

    //decryption
    Decryption();

    Destroy_ECC();
}
