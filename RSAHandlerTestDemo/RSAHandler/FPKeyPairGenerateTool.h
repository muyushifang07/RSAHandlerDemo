//
//  FPKeyPairGenerateTool.h
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/5.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/pem.h>
#import <openssl/rsa.h>

@interface FPKeyPairGenerateTool : NSObject

/*
 @abstract 按位生成密钥对
 @param keySize： 512/1024/2048  我取：1024
 @param publicKey：公钥指针
 @param privateKey：私钥指针
 @return BOOL yes:生成密钥成功
*/
+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey;

/*
 @abstract 从RSA对象提取密钥(NSString类型)
 @param rsaKey： RSA对象：公钥/私钥
 @param isPublickey：yes为公钥
 @return NSString：密钥字符串 包含-----BEGIN PUBLIC KEY-----
 
 -----BEGIN PUBLIC KEY-----
 MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1xrKmDU3DVdoghB62AQdC0xaI
 sVJEj1vvXhT8SpNHuaSz4K+4P7iOew3JDYZL5zAHfa2xxpDD++cSu9W7dUS+uETT
 FBVFplkJJVgJ7wIqRcwAITnt7cjMuickAuluX6TS+TqDcbxKXW2ptu3YxNCdMMiL
 OH1W/316oyOrGNUE1QIDAQAB
 -----END PUBLIC KEY-----

 -----BEGIN PRIVATE KEY-----
 MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALXGsqYNTcNV2iCE
 HrYBB0LTFoixUkSPW+9eFPxKk0e5pLPgr7g/uI57DckNhkvnMAd9rbHGkMP75xK7
 1bt1RL64RNMUFUWmWQklWAnvAipFzAAhOe3tyMy6JyQC6W5fpNL5OoNxvEpdbam2
 7djE0J0wyIs4fVb/fXqjI6sY1QTVAgMBAAECgYEAs4eOM/BZyD3HlGvIxSsY18gR
 rmmrfek0/KGoClFBSwqv/7Q++LN+fMJOKC8CX37y8cMPxM//dIEbhGYdvuogPK7y
 hSTtsYaRTIWqazHqcgxBlk3ZUqKDXTbdAhyOKcdbVtUmbHe68XrQuAWEkcE5KfZg
 75Jf2RJHEp6ph3ucllUCQQDfgTa3rG+/DfRafgDVnJrVAsJpDYsqvGN/Ide4r2pu
 VpF2UOG1J7bZPjPYEkxdZoJkT3For93OQyXQGIEMWoTXAkEA0DRbkTPU8wROCcr/
 uGx4T/77/wq23wLHD07wBxmcM/PAUCLqJDy8uKQHaIsQyv3dj2g5h7pJHCeXta01
 /xgiMwJAackzx82S+n+1Vxtqc7ByzD1JHQXvB6QxB5xSCTTlkCHjKXfwzJhmf/5j
 9XH7uP1q2+WKDP2oYxb/D7Z5Zgp18wJAYdK30xlPTH8RS3idfcE5JhzfuY0HLvDX
 JlIoZK2bvq0gBobhC/WdlgM7l9r/IOD2YJLPtP3Jq/jORwYDAMAOEQJBAIhFcLzd
 7mAJZ6tids56idrQSZBn0aD1mMFAirgbR7CwNzskott6+35bFvbkElPGh+CE8cbE
 +PoGeLTbJWGe/KE=
 -----END PRIVATE KEY-----

 */
+ (NSString *)PEMFormatRSAKey:(RSA *)rsaKey isPublic:(BOOL)isPublickey;


/*
 @abstract 密钥字符串处理将-----BEGIN PRIVATE KEY----- 以及\r\t\n@" " 去除
 @param PEMFormat：含有-----BEGIN PRIVATE KEY-----格式的字符串
 @return NSString 处理后的字符串
 */
+ (NSString *)base64EncodedFromPEMFormat:(NSString *)PEMFormat;



+ (NSData *)stripPublicKeyHeader:(NSData *)d_key;
+ (NSData *)stripPrivateKeyHeader:(NSData *)d_key;

@end
