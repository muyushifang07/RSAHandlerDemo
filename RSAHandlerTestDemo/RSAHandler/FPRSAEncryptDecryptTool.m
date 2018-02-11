//
//  FPRSAEncryptDecryptTool.m
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/5.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

/*
 加密/解密以及加签验签工具类
 */

#import "FPRSAEncryptDecryptTool.h"
#import "JDKeyChainWapper.h"

static NSString * const pubkeyTag = @"JDRSAUtil_PubKey_Tag";
static NSString * const privateTag = @"RSAUtil_PrivKey_Tag";


@implementation FPRSAEncryptDecryptTool
{
    RSA *_rsa_pub;
    RSA *_rsa_pri;
}
#pragma mark - Base64编码
static NSString *base64_encode_data(NSData *data){
    data = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

#pragma mark --- 公钥加密 ---
+ (NSString *)encryptSourceString:(NSString *)sourceStr publicKey:(NSString *)pubKeyStr;
{
    if (!sourceStr||!pubKeyStr) {
        NSLog(@"原数据或者公钥字符串为 NULL");
        return nil;
    }

    NSData *data = [FPRSAEncryptDecryptTool encryptData:[sourceStr dataUsingEncoding:NSUTF8StringEncoding] publicKey:pubKeyStr];
    NSString *ret = base64_encode_data(data);
    return ret;
}

+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey
{
    if (!data||!pubKey) {
        NSLog(@"原数据或者公钥字符串为 NULL--%@--%@",data,pubKey);
        return nil;
    }
    // 密钥对象
    SecKeyRef keyRef = [JDKeyChainWapper addKeyChainWithRSAkey:pubKey identifier:pubkeyTag isPublicKey:YES];
    if (!keyRef) {
        NSLog(@"公钥错误");
        return nil;
    }
    NSLog(@"%@",keyRef);
    return [FPRSAEncryptDecryptTool encryptData:data withKeyRef:keyRef isSign:NO];
}

// SecKeyRef密钥 对Data加密
+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef isSign:(BOOL)isSign
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (isSign) {
            status =SecKeyRawSign(keyRef,
                                  kSecPaddingPKCS1,
                                  srcbuf + idx,
                                  data_len,
                                  outbuf,
                                  &outlen
                                  );
        }
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


#pragma mark --- 私钥解密 ---
+ (NSString *)decryptSourceString:(NSString *)encryptedStr privateKey:(NSString *)privKeyStr
{
    if (!encryptedStr) {
        NSLog(@"加密后的数据为 nil");
        return nil;
    }
    NSData *data =[[NSData alloc] initWithBase64EncodedString:encryptedStr options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [FPRSAEncryptDecryptTool decryptData:data privateKey:privKeyStr];
    NSString *ret = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey
{
    if(!data || !privKey){
        return nil;
    }
    SecKeyRef keyRef = [JDKeyChainWapper addKeyChainWithRSAkey:privKey identifier:privateTag isPublicKey:NO];
    if(!keyRef){
        return nil;
    }
    return [FPRSAEncryptDecryptTool decryptData:data withKeyRef:keyRef];
}

// 密钥对 Data 解密
+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef
{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}


#pragma mark --- 私钥加签 ---
- (NSString *)signSHA256String:(NSString *)string
{
    if (!_rsa_pri) {
        NSLog(@"please import private key first");
        return nil;
    }
    
    if (!string) {
        NSLog(@"原数据或者签名数据为 nil");
        return nil;
    }
    
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];
    //int messageLength = (int)strlen(message);
    unsigned char *sig = (unsigned char *)malloc(256);
    unsigned int sig_len;
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, strlen(message));
    SHA256_Final(digest, &ctx);
    
    int rsa_sign_valid = RSA_sign(NID_sha256
                                  , digest, SHA256_DIGEST_LENGTH
                                  , sig, &sig_len
                                  , _rsa_pri);
    
    if (rsa_sign_valid == 1) {
        NSData* data = [NSData dataWithBytes:sig length:sig_len];
        
        NSString * base64String = [data base64EncodedStringWithOptions:0];
        free(sig);
        return base64String;
    }
    
    free(sig);
    return nil;
}

#pragma mark --- 公钥验签 ---
#pragma mark RSA MD5 验证签名
- (BOOL)verifySHA256String:(NSString *)string withSign:(NSString  *)signString
{
    if (!_rsa_pub||!signString) {
        NSLog(@"please import public key first");
        return NO;
    }
    
    if (!signString||!string) {
        NSLog(@"原数据或者签名数据为 nil");
        return NO;
    }
    
    const char *message = [string cStringUsingEncoding:NSUTF8StringEncoding];
    // int messageLength = (int)[string lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [[NSData alloc]initWithBase64EncodedString:signString options:0];
    unsigned char *sig = (unsigned char *)[signatureData bytes];
    unsigned int sig_len = (int)[signatureData length];
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, strlen(message));
    SHA256_Final(digest, &ctx);
    int verify_ok = RSA_verify(NID_sha256
                               , digest, SHA256_DIGEST_LENGTH
                               , sig, sig_len
                               , _rsa_pub);
    if (1 == verify_ok){
        return   YES;
    }
    return NO;
}


- (RSA *)importKeyWithType:(KeyType)type andkeyString:(NSString *)keyString
{
    if (!keyString) {
        return nil;
    }
    BIO *bio = NULL;
    RSA *rsa = NULL;
    bio = BIO_new(BIO_s_file());
    NSString *temPath = NSTemporaryDirectory();
    NSString *rsaFilePath = [temPath stringByAppendingPathComponent:@"RSAKEY"];
    NSString *formatRSAKeyString = [FPRSAEncryptDecryptTool formatRSAKeyWithKeyString:keyString andKeytype:type];
    BOOL writeSuccess = [formatRSAKeyString writeToFile:rsaFilePath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (!writeSuccess) {
        return nil;
    }
    const char* cPath = [rsaFilePath cStringUsingEncoding:NSUTF8StringEncoding];
    BIO_read_filename(bio, cPath);
    if (type == KeyTypePrivate) {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, "");
        _rsa_pri = rsa;
        if (rsa != NULL && 1 == RSA_check_key(rsa)) {
            BIO_free_all(bio);
            [[NSFileManager defaultManager] removeItemAtPath:rsaFilePath error:nil];
            return rsa;
        } else {
            return nil;
        }
        
    } else{
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        _rsa_pub = rsa;
        if (rsa != NULL) {
            BIO_free_all(bio);
            [[NSFileManager defaultManager] removeItemAtPath:rsaFilePath error:nil];
            return rsa;
        } else {
            return nil;
        }
    }
}

+ (NSString*)formatRSAKeyWithKeyString:(NSString*)keyString andKeytype:(KeyType)type
{
    NSInteger lineNum = -1;
    NSMutableString *result = [NSMutableString string];
    
    if (type == KeyTypePrivate) {
        [result appendString:@"-----BEGIN PRIVATE KEY-----\n"];
        lineNum = 79;
    }else if(type == KeyTypePublic){
        [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
        lineNum = 76;
    }
    
    int count = 0;
    for (int i = 0; i < [keyString length]; ++i) {
        unichar c = [keyString characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == lineNum) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    if (type == KeyTypePrivate) {
        [result appendString:@"\n-----END PRIVATE KEY-----"];
        
    }else if(type == KeyTypePublic){
        [result appendString:@"\n-----END PUBLIC KEY-----"];
    }
    return result;
}


@end
