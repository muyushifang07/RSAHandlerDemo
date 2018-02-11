//
//  FPRSAEncryptDecryptTool.h
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/5.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <openssl/x509.h>

typedef enum {
    KeyTypePublic = 0,
    KeyTypePrivate
}KeyType;


@interface FPRSAEncryptDecryptTool : NSObject

// 导入密钥字符串
- (RSA *)importKeyWithType:(KeyType)type andkeyString:(NSString *)keyString;

// 加密
+ (NSString *)encryptSourceString:(NSString *)sourceStr publicKey:(NSString *)pubKeyStr;

// 解密
+ (NSString *)decryptSourceString:(NSString *)encryptedStr privateKey:(NSString *)privKeyStr;


// 加签
- (NSString *)signSHA256String:(NSString *)string;


// 验签
- (BOOL)verifySHA256String:(NSString *)string withSign:(NSString  *)signString;


@end
