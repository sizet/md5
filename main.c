// ©.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5_hash.h"




#define DMSG(msg_fmt, msg_args...) \
    printf("%s(%04u): " msg_fmt "\n", __FILE__, __LINE__, ##msg_args)




int main(
    int argc,
    char **argv)
{
    char hash_result[MD5_HASH_BUFFER_SIZE];
    char *target_string;
    FILE *file_fp;
    char *target_file;
    int file_size;
    unsigned char *file_buf;


    // 處理字串.

    target_string = "";
    md5_hash(target_string, strlen(target_string), hash_result, sizeof(hash_result));
    DMSG("string (%s) = %s", target_string, hash_result);

    target_string = "hellow";
    md5_hash(target_string, strlen(target_string), hash_result, sizeof(hash_result));
    DMSG("string (%s) = %s", target_string, hash_result);

    // 處理檔案.

    target_file = "md5";
    file_fp = fopen(target_file, "rb");
    if(file_fp == NULL)
    {
        DMSG("call fopen(%s) fail [%s]", target_file, strerror(errno));
        goto FREE_01;
    }

    fseek(file_fp, 0L, SEEK_END);
    file_size = ftell(file_fp);
    fseek(file_fp, 0L, SEEK_SET);

    file_buf = (unsigned char *) malloc(file_size);
    if(file_buf == NULL)
    {
        DMSG("call malloc(%d) fail [%s]", file_size, strerror(errno));
        goto FREE_02;
    }

    fread(file_buf, sizeof(unsigned char), file_size, file_fp);

    md5_hash(file_buf, file_size, hash_result, sizeof(hash_result));
    DMSG("file (%s) = %s", target_file, hash_result);

    free(file_buf);
FREE_02:
    fclose(file_fp);
FREE_01:
    return 0;
}
