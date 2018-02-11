//
//  RSAHelper.h
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/6.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef void(^CheckSGResultBlock)(id model,id error);

@interface RSAHelper : NSObject

// 判断本地有没有钥匙串
+ (BOOL)checkLocalKeyPairIsExisted;

// 创建密钥并保存到钥匙串
+ (void)creatKeyPairAndSaveKeyChain;


// 存取密钥字符串
+ (void)saveCustomPublicKeyStr:(NSString *)publicKeyStr;

+ (void)saveCustomPrivateKeyStr:(NSString *)privateKeyStr;

+ (void)saveServerPublicKeyStr:(NSString *)publicKeyStr;

+ (NSString *)getCustomPublicKeyStr;

+ (NSString *)getCustomPrivateKeyStr;

+ (NSString *)getServerPublicKeyStr;


// 存取SG
+ (BOOL)isHaveSgToken;

+ (void)saveSgToken:(NSString *)sgToken;

+ (NSString *)getSgToken;

// 校验SG
+ (void)checkSGValidity:(NSString *)sg resultBlock:(CheckSGResultBlock)resultBlock;

// 获取SG
+ (void)generateSGResultBlock:(CheckSGResultBlock)resultBlock;;


@end
