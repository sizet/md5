// ©.
// https://github.com/sizet/md5

#ifndef _MD5_HASH_H_
#define _MD5_HASH_H_




#define MD5_HASH_BUFFER_SIZE 33




void md5_hash(
    void *data_con,
    size_t data_len,
    char *out_buf,
    size_t out_size);




#endif
