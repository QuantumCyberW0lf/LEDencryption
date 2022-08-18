/**
 * Convention: all functions will fowllow the style:
 * func(output,input);
 */


#include <inttypes.h>


#define WORD_LENGTH 0x04
#define LED_PARAMETER 0x80
#define ROUNDS_NUMBER 0x30

static const uint8_t MixColMatrix[4][4] =
{
    {0x04,0x01,0x02,0x02},
    {0x08,0x06,0x05,0x06},
    {0x0b,0x0e,0x0a,0x09},
    {0x02,0x02,0x0f,0x0b},
};

static const uint8_t SBOX[16] = 
{
    0x0c,0x05,0x06,0x0b,0x09,0x00,0x0a,0x0d,0x03,0x0e,0x0f,0x08,0x04,0x07,0x01,0x02
};

static const uint8_t IRR_POLY = 0x03;
static const uint8_t RC[48] = 
{
   0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,                                         
   0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,
   0x16,0x2C,0x18,0x30,0x21,0x02,0x05,0x0B,0x17,0x2E,
   0x1C,0x38,0x31,0x23,0x06,0x0D,0x1B,0x36,0x2D,0x1A,
   0x34,0x29,0x12,0x24,0x08,0x11,0x22,0x04
};

/**
 * Multiply in Galois Field GF(2^3);
 * @param [in] - first_element, second_element in GF(2^3)
 * @param [out] - a pointer points to the result;
 */

static void gf8_mul(uint8_t* result, uint8_t first_element,uint8_t second_element)
{
    uint8_t tmp = first_element, ret = 0;

    for(uint8_t i = 0; i < WORD_LENGTH; i++)
    {
        if((second_element >> i) & 1)
            ret ^= tmp;

        if(tmp & 2*WORD_LENGTH)
        {
            tmp <<= 1;
            tmp ^= IRR_POLY;
        }
        tmp <<= 1;
    }
    *result = ret & 0x0f;
}

/**
 * Add key
 * @param [in] - key = ptr → element in GF(2^3), half = an integer
 * @param [out] - state = 4x4 Matrix
 */

static void add_key(uint8_t** state,uint8_t* key, int half)
{
    if((half & 0x01) == 0)
        for(uint8_t i = 0; i < WORD_LENGTH; i++)
            for(uint8_t j = 0; j < WORD_LENGTH; j++)
                *(*(state+i)+j) ^= *(key + WORD_LENGTH*i + j);

    for(uint8_t i = 0; i < WORD_LENGTH; i++)
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(*(state+i)+j) ^= *(key + WORD_LENGTH*i +j + ((LED_PARAMETER-0x40) >> 0x02));
}

/**
 * Add constant to the state matrix 4x4
 */

static void add_const(uint8_t** state,int round)
{
    uint8_t tmp = (RC[round] >> 0x03) & 0x07;

    *(*(state+1)) ^= 0x01;
    *(*(state+2)) ^= 0x02;
    *(*(state+3)) ^= 0x03;

    *(*(state)+1) ^= tmp;
    *(*(state+2)+1) ^= tmp;
    tmp = RC[round] & 0x07;
    *(*(state+1)+1) ^= tmp;
    *(*(state+3)+1) ^= tmp;
}

/**
 * Manipulate the state matrix
 */

static void cells_substitution(uint8_t** state)
{
    for(uint8_t i = 0; i < WORD_LENGTH; i++)
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(*(state+i)+j) = SBOX[*(*(state+i)+j)];
}

/**
 * Like shift rows in AES
 */

static void shift_rows(uint8_t** state)
{
    uint8_t* tmp;
    for(uint8_t i = 1; i < WORD_LENGTH; i++)
    {
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(tmp+j) = *(*(state+i)+j);

        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(*(state+i)+j) = *(tmp + (i+j)%WORD_LENGTH);
    }
}

/**
 * Like mix_columns in AES
 */

static void mix_columns(uint8_t** state)
{
    uint8_t* tmp;
    for(int i = 0; i < WORD_LENGTH; i++)
    {
        for(int j = 0; i < WORD_LENGTH; j++)
        {
            uint8_t sum = 0x00;
            uint8_t* sum_ptr = &sum; 
            for(uint8_t k = 0; k < WORD_LENGTH; k++)
            {
                gf8_mul(sum_ptr,MixColMatrix[j][k],*(*(state+k)+i));
                sum ^= *sum_ptr;
            }

            *(tmp + j) = sum;
        }
        for(uint8_t ind = 0; ind < WORD_LENGTH; ind++)
            *(*(state+ind)+i) = *(tmp+ind);
    }
}

static void LED_round(uint8_t** state, uint8_t* key)
{
    add_key(state,key,0);
    
    for(uint8_t i = 0; i < ROUNDS_NUMBER/WORD_LENGTH; i ++)
    {
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
        {
            add_const(state,i*WORD_LENGTH+j);
            cells_substitution(state);
            shift_rows(state);
            mix_columns(state);
        }
        add_key(state,key,i+1);
    }
}

/**
 * c ← Enc(k,m)
 */

void encryption(uint8_t* c, uint8_t* key,uint8_t* msg)
{
    uint8_t** state;
    uint8_t* key_ptr;

    for(uint8_t i = 0; i < LED_PARAMETER/WORD_LENGTH; i++)
        *(key_ptr+i) = (*(key + (i >> 0x01)) >> WORD_LENGTH*(1 - i%2)) & 0x0f;


    for(uint8_t i = 0; i < WORD_LENGTH; i++)
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(*(state+i)+j) = (*(msg + (WORD_LENGTH*i + j >> 0x01)) >> (WORD_LENGTH*(1-j%2))) & 0x0f;

    LED_round(state,key_ptr);

    /**
     * Initialize the cipher text
     */

    for(uint8_t i = 0; i < 2*WORD_LENGTH; i++)
        *(c + i) = 0;

    for(uint8_t i = 0; i < WORD_LENGTH; i++)
        for(uint8_t j = 0; j < WORD_LENGTH; j++)
            *(c+((WORD_LENGTH*i+j) >> 0x01)) |= *(*(state+i)+j) << (WORD_LENGTH*(1-j%2));
}
