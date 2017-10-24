// ©.
// https://github.com/sizet/md5

#include <stdio.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>
#include "md5_hash.h"




// MD5 將資料分為 N 組處理, 每組長度 64byte (16 個 4byte).
typedef uint32_t   UNIT_TYPE;
#define UINT_COUNT 16
#define BLOCK_SIZE (sizeof(UNIT_TYPE) * UINT_COUNT)

// 資料結束標誌.
typedef uint8_t     ENDING_TYPE;
#define ENDING_LEN  sizeof(ENDING_TYPE)
#define ENDING_BYTE 0x80

// 資料長度單位.
typedef uint64_t   LENGTH_TYPE;
#define LENGTH_LEN sizeof(LENGTH_TYPE)

// 填充.
#define PADDING_BYTE 0x00

#define RLEFT(x, n) (((x) << (n)) | ((x) >> ((sizeof(UNIT_TYPE) * 8) - (n))))




void md5_hash(
    void *data_con,
    size_t data_len,
    char *out_buf,
    size_t out_size)
{
    UNIT_TYPE h[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};
    UNIT_TYPE a, b, c, d, m[UINT_COUNT], *input_data = NULL;
    uint8_t data_buf[BLOCK_SIZE * 2], *fill_offset = NULL;
    size_t padding_len, input_len, raw_len, i;


    // MD5 將資料分為 64byte 為一組做處理, 所以總長度必須是 64 的倍數, 不足的話需要填充 :
    // [原始資料] + [0x80] + [0x00 x N (N = 0...)] + [原始資料長度 (8byte)]

    // 計算需要多填充幾個 0x00.
    // 1. 計算 [原始資料] + [0x80] + [資料長度 (8byte)] 除 64 會餘多少.
    // 2. 餘的值是 0, 不需要填充 0x00.
    //    餘的值非 0, 需要填充 [64 - 餘] 個 0x00.
    padding_len = (data_len + ENDING_LEN + LENGTH_LEN) % BLOCK_SIZE;
    padding_len = padding_len == 0 ? 0 : BLOCK_SIZE - padding_len;

    // 總共要處理的資料長度.
    input_len = data_len + ENDING_LEN + padding_len + LENGTH_LEN;

    raw_len = data_len;

    while(input_len > 0)
    {
        // 計算要的處理的原始資料長度, 將資料分為 64byte 為一組做處理,
        // 剩餘的原始資料長度 >= 64byte, 直接處理原始資料.
        // 剩餘的原始資料長度 <  64byte, 複製到緩衝處理剩餘的 (後面會加上額外資料一起處理).
        if(raw_len >= BLOCK_SIZE)
        {
            input_data = (UNIT_TYPE *) data_con;
            data_con += BLOCK_SIZE;
            raw_len -= BLOCK_SIZE;
        }
        else
        {
            // 剩餘的原始資料長度 < 64byte 時,
            // 需要補上 [0x80] + [0x00 x N (N = 0...)] + [原始資料長度 (8byte)] 一起處理.
            // 如果剩餘的原始資料長度 <= 55byte, 加上額外資料之後是  64byte, 需要處理一次.
            // 如果剩餘的原始資料長度 >  55byte, 加上額外資料之後是 128byte, 需要處理二次.

            // 加上額外資料.
            if(fill_offset == NULL)
            {
                // 複製剩下的原始資料.
                memcpy(data_buf, data_con, raw_len);
                // 加入 0x80.
                fill_offset = data_buf + raw_len;
                *((ENDING_TYPE *) fill_offset) = ENDING_BYTE;
                // 填充 0x00.
                fill_offset += ENDING_LEN;
                memset(fill_offset, PADDING_BYTE, padding_len);
                // 加入原始資料長度, MD5 要求小端格式, 如果是大端系統需要轉換.
                fill_offset += padding_len;
                *((LENGTH_TYPE *) ((void *) fill_offset)) =
#if __BYTE_ORDER == __LITTLE_ENDIAN
                    ((LENGTH_TYPE) data_len) * 8;
#elif __BYTE_ORDER == __BIG_ENDIAN
                    bswap_64(((LENGTH_TYPE) data_len) * 8);
#else
#error "please check endian type"
#endif
                input_data = (UNIT_TYPE *) ((void *) data_buf);
            }
            // 剩餘的原始資料長度 > 55byte, 處理第二次.
            else
            {
                input_data = (UNIT_TYPE *) ((void *) (data_buf + BLOCK_SIZE));
            }
        }
        input_len -= BLOCK_SIZE;

        // 開始 MD5 處理.

        // MD5 要求小端格式, 如果是大端系統需要轉換.
        for(i = 0; i < UINT_COUNT; i++)
#if __BYTE_ORDER == __LITTLE_ENDIAN
            m[i] = input_data[i];
#elif __BYTE_ORDER == __BIG_ENDIAN
            m[i] = bswap_32(input_data[i]);
#else
#error "please check endian type"
#endif

        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];

        a = RLEFT(a + (((d ^ c) & b) ^ d) + m[ 0] + 0xD76AA478,  7) + b;
        d = RLEFT(d + (((c ^ b) & a) ^ c) + m[ 1] + 0xE8C7B756, 12) + a;
        c = RLEFT(c + (((b ^ a) & d) ^ b) + m[ 2] + 0x242070DB, 17) + d;
        b = RLEFT(b + (((a ^ d) & c) ^ a) + m[ 3] + 0xC1BDCEEE, 22) + c;
        a = RLEFT(a + (((d ^ c) & b) ^ d) + m[ 4] + 0xF57C0FAF,  7) + b;
        d = RLEFT(d + (((c ^ b) & a) ^ c) + m[ 5] + 0x4787C62A, 12) + a;
        c = RLEFT(c + (((b ^ a) & d) ^ b) + m[ 6] + 0xA8304613, 17) + d;
        b = RLEFT(b + (((a ^ d) & c) ^ a) + m[ 7] + 0xFD469501, 22) + c;
        a = RLEFT(a + (((d ^ c) & b) ^ d) + m[ 8] + 0x698098D8,  7) + b;
        d = RLEFT(d + (((c ^ b) & a) ^ c) + m[ 9] + 0x8B44F7AF, 12) + a;
        c = RLEFT(c + (((b ^ a) & d) ^ b) + m[10] + 0xFFFF5BB1, 17) + d;
        b = RLEFT(b + (((a ^ d) & c) ^ a) + m[11] + 0x895CD7BE, 22) + c;
        a = RLEFT(a + (((d ^ c) & b) ^ d) + m[12] + 0x6B901122,  7) + b;
        d = RLEFT(d + (((c ^ b) & a) ^ c) + m[13] + 0xFD987193, 12) + a;
        c = RLEFT(c + (((b ^ a) & d) ^ b) + m[14] + 0xA679438E, 17) + d;
        b = RLEFT(b + (((a ^ d) & c) ^ a) + m[15] + 0x49B40821, 22) + c;

        a = RLEFT(a + (c ^ (d & (b ^ c))) + m[ 1] + 0xF61E2562,  5) + b;
        d = RLEFT(d + (b ^ (c & (a ^ b))) + m[ 6] + 0xC040B340,  9) + a;
        c = RLEFT(c + (a ^ (b & (d ^ a))) + m[11] + 0x265E5A51, 14) + d;
        b = RLEFT(b + (d ^ (a & (c ^ d))) + m[ 0] + 0xE9B6C7AA, 20) + c;
        a = RLEFT(a + (c ^ (d & (b ^ c))) + m[ 5] + 0xD62F105D,  5) + b;
        d = RLEFT(d + (b ^ (c & (a ^ b))) + m[10] + 0x02441453,  9) + a;
        c = RLEFT(c + (a ^ (b & (d ^ a))) + m[15] + 0xD8A1E681, 14) + d;
        b = RLEFT(b + (d ^ (a & (c ^ d))) + m[ 4] + 0xE7D3FBC8, 20) + c;
        a = RLEFT(a + (c ^ (d & (b ^ c))) + m[ 9] + 0x21E1CDE6,  5) + b;
        d = RLEFT(d + (b ^ (c & (a ^ b))) + m[14] + 0xC33707D6,  9) + a;
        c = RLEFT(c + (a ^ (b & (d ^ a))) + m[ 3] + 0xF4D50D87, 14) + d;
        b = RLEFT(b + (d ^ (a & (c ^ d))) + m[ 8] + 0x455A14ED, 20) + c;
        a = RLEFT(a + (c ^ (d & (b ^ c))) + m[13] + 0xA9E3E905,  5) + b;
        d = RLEFT(d + (b ^ (c & (a ^ b))) + m[ 2] + 0xFCEFA3F8,  9) + a;
        c = RLEFT(c + (a ^ (b & (d ^ a))) + m[ 7] + 0x676F02D9, 14) + d;
        b = RLEFT(b + (d ^ (a & (c ^ d))) + m[12] + 0x8D2A4C8A, 20) + c;

        a = RLEFT(a + (b ^ c ^ d) + m[ 5] + 0xFFFA3942,  4) + b;
        d = RLEFT(d + (a ^ b ^ c) + m[ 8] + 0x8771F681, 11) + a;
        c = RLEFT(c + (d ^ a ^ b) + m[11] + 0x6D9D6122, 16) + d;
        b = RLEFT(b + (c ^ d ^ a) + m[14] + 0xFDE5380C, 23) + c;
        a = RLEFT(a + (b ^ c ^ d) + m[ 1] + 0xA4BEEA44,  4) + b;
        d = RLEFT(d + (a ^ b ^ c) + m[ 4] + 0x4BDECFA9, 11) + a;
        c = RLEFT(c + (d ^ a ^ b) + m[ 7] + 0xF6BB4B60, 16) + d;
        b = RLEFT(b + (c ^ d ^ a) + m[10] + 0xBEBFBC70, 23) + c;
        a = RLEFT(a + (b ^ c ^ d) + m[13] + 0x289B7EC6,  4) + b;
        d = RLEFT(d + (a ^ b ^ c) + m[ 0] + 0xEAA127FA, 11) + a;
        c = RLEFT(c + (d ^ a ^ b) + m[ 3] + 0xD4EF3085, 16) + d;
        b = RLEFT(b + (c ^ d ^ a) + m[ 6] + 0x04881D05, 23) + c;
        a = RLEFT(a + (b ^ c ^ d) + m[ 9] + 0xD9D4D039,  4) + b;
        d = RLEFT(d + (a ^ b ^ c) + m[12] + 0xE6DB99E5, 11) + a;
        c = RLEFT(c + (d ^ a ^ b) + m[15] + 0x1FA27CF8, 16) + d;
        b = RLEFT(b + (c ^ d ^ a) + m[ 2] + 0xC4AC5665, 23) + c;

        a = RLEFT(a + ((b | ~ d) ^ c) + m[ 0] + 0xF4292244,  6) + b;
        d = RLEFT(d + ((a | ~ c) ^ b) + m[ 7] + 0x432AFF97, 10) + a;
        c = RLEFT(c + ((d | ~ b) ^ a) + m[14] + 0xAB9423A7, 15) + d;
        b = RLEFT(b + ((c | ~ a) ^ d) + m[ 5] + 0xFC93A039, 21) + c;
        a = RLEFT(a + ((b | ~ d) ^ c) + m[12] + 0x655B59C3,  6) + b;
        d = RLEFT(d + ((a | ~ c) ^ b) + m[ 3] + 0x8F0CCC92, 10) + a;
        c = RLEFT(c + ((d | ~ b) ^ a) + m[10] + 0xFFEFF47D, 15) + d;
        b = RLEFT(b + ((c | ~ a) ^ d) + m[ 1] + 0x85845DD1, 21) + c;
        a = RLEFT(a + ((b | ~ d) ^ c) + m[ 8] + 0x6FA87E4F,  6) + b;
        d = RLEFT(d + ((a | ~ c) ^ b) + m[15] + 0xFE2CE6E0, 10) + a;
        c = RLEFT(c + ((d | ~ b) ^ a) + m[ 6] + 0xA3014314, 15) + d;
        b = RLEFT(b + ((c | ~ a) ^ d) + m[13] + 0x4E0811A1, 21) + c;
        a = RLEFT(a + ((b | ~ d) ^ c) + m[ 4] + 0xF7537E82,  6) + b;
        d = RLEFT(d + ((a | ~ c) ^ b) + m[11] + 0xBD3AF235, 10) + a;
        c = RLEFT(c + ((d | ~ b) ^ a) + m[ 2] + 0x2AD7D2BB, 15) + d;
        b = RLEFT(b + ((c | ~ a) ^ d) + m[ 9] + 0xEB86D391, 21) + c;

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
    }

    h[0] = bswap_32(h[0]);
    h[1] = bswap_32(h[1]);
    h[2] = bswap_32(h[2]);
    h[3] = bswap_32(h[3]);

    snprintf(out_buf, out_size, "%08x%08x%08x%08x", h[0], h[1], h[2], h[3]);
}
