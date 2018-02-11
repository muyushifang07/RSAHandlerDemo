//
//  FPKeyPairGenerateTool.m
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/5.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

/*
 密钥生成工具类:并转化为纯净字符串
 使用 OpenSSL 方式生成密钥对RSA
 利用方法：PEMFormatRSAKeyRSA将对象转化PEM格式的密钥字符串带有-----BEGIN PUBLIC KEY-----
 然后利用方法：base64EncodedFromPEMFormat 获取纯净的密钥字符串
 */

#import "FPKeyPairGenerateTool.h"
#import <openssl/x509.h>

@implementation FPKeyPairGenerateTool

+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey
{
    if (keySize == 512 || keySize == 1024 || keySize == 2048) {
        /* 产生RSA密钥 */
        RSA *rsa = RSA_new();
        BIGNUM* e = BN_new();
        
        /* 设置随机数长度 */
        BN_set_word(e, 65537);
        
        /* 生成RSA密钥对 */
        RSA_generate_key_ex(rsa, keySize, e, NULL);
        
        if (rsa) {
            *publicKey = RSAPublicKey_dup(rsa);
            *privateKey = RSAPrivateKey_dup(rsa);
            return YES;
        }
    }
    return NO;
}

+ (NSString *)PEMFormatRSAKey:(RSA *)rsaKey isPublic:(BOOL)isPublickey
{
    if (!rsaKey) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (isPublickey) {
        PEM_write_bio_RSA_PUBKEY(bio, rsaKey);
    } else {
        // 此方法生成的是pkcs1格式的,iOS中需要pkcs8格式的,因此通过PEM_write_bio_PrivateKey 方法生成
        // PEM_write_bio_RSAPrivateKey(bio, rsaKey, NULL, NULL, 0, NULL, NULL);
        
        EVP_PKEY* key = NULL;
        key = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(key, rsaKey);
        PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    return [NSString stringWithUTF8String:bptr->data];
}


+ (NSString *)base64EncodedFromPEMFormat:(NSString *)PEMFormat
{
    NSString *keyStr = [[PEMFormat componentsSeparatedByString:@"-----"] objectAtIndex:2];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@" "  withString:@""];
    return keyStr;
}


+ (NSData *)stripPublicKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    {0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00};
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key
{
    // Skip ASN.1 private key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx     = 22; //magic byte at offset 22
    
    if (0x04 != c_key[idx++]) return nil;
    
    //calculate length of the key
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    } else {
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            //rsa length field longer than buffer
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum << 8) + *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    
    // Now make a new NSData from this buffer
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}

@end
