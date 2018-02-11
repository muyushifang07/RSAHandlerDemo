//
//  RSAHelper.m
//  FunctionalTest
//
//  Created by user_lzz on 2018/2/6.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import "RSAHelper.h"
#import "FPKeyPairGenerateTool.h"
#import "FPRSAEncryptDecryptTool.h"
#import "JDKeyChainWapper.h"
#import "RSAHttpRequestHandler.h"

#define USER_DEFAULTS       [NSUserDefaults standardUserDefaults]
#import "GeneralUtils.h"

@interface RSAHelper ()
{
    NSString *_serverPublicKey;
}
@end

@implementation RSAHelper

+ (BOOL)checkLocalKeyPairIsExisted
{
    NSString *publicKeyBase64 = @"";
    NSString *privateKeyBase64 = @"";
    publicKeyBase64 = [self getCustomPublicKeyStr];
    privateKeyBase64 = [self getCustomPrivateKeyStr];
    
    if ([publicKeyBase64 length]==0||[privateKeyBase64 length]==0) {
        return NO;
    } else {
        return YES;
    }
}

+ (void)creatKeyPairAndSaveKeyChain
{
    NSString *publicKeyBase64 = @"";
    NSString *privateKeyBase64 = @"";
    publicKeyBase64 = [self getCustomPublicKeyStr];
    privateKeyBase64 = [self getCustomPrivateKeyStr];
    
    // 如果已经存在就不再生成，直接读取
    NSLog(@"直接读取publicKeyBase64:%@",publicKeyBase64);
    NSLog(@"直接读取privateKeyBase64:%@",privateKeyBase64);
    
    if ([publicKeyBase64 length]==0||[privateKeyBase64 length]==0) {
        // 重新创建密钥对
        [self crateKeyPairWithOpenSSl];
    }
}

#pragma mark - ==============OpenSSL 方式=================
#pragma mark --- 第一步：代码生成密钥对 ------
+ (BOOL)crateKeyPairWithOpenSSl
{
    RSA *openSSLPublicKey;
    RSA *openSSLPrivateKey;
    BOOL yes = [FPKeyPairGenerateTool generateRSAKeyPairWithKeySize:1024 publicKey:&openSSLPublicKey privateKey:&openSSLPrivateKey];
    if (yes) {
        
        // 它是经过Base64编码过的
        NSString *pemPublickey = [FPKeyPairGenerateTool PEMFormatRSAKey:openSSLPublicKey isPublic:YES];
        NSString *pemPrivatekey = [FPKeyPairGenerateTool PEMFormatRSAKey:openSSLPrivateKey isPublic:NO];
        
        // 除去-----PUBLICKEY-----获取的纯key
        NSString *publicKeyBase64 = @"";
        NSString *privateKeyBase64 = @"";
        publicKeyBase64 = [FPKeyPairGenerateTool base64EncodedFromPEMFormat:pemPublickey];
        privateKeyBase64 = [FPKeyPairGenerateTool base64EncodedFromPEMFormat:pemPrivatekey];
        
        [self saveCustomPublicKeyStr:publicKeyBase64];
        [self saveCustomPrivateKeyStr:privateKeyBase64];
        return YES;
    } else {
        return NO;
    }
}




#pragma mark - 保存在Keychian中的客户端的公钥/私钥以及服务端的公钥
+ (void)saveCustomPublicKeyStr:(NSString *)publicKeyStr
{
    if (publicKeyStr==nil) {
        publicKeyStr = @"";
    }
    [JDKeyChainWapper saveStringWithdIdentifier:@"CJH_RSA_PUB_KEY_C" data:publicKeyStr];
}

+ (void)saveCustomPrivateKeyStr:(NSString *)privateKeyStr
{
    if (privateKeyStr==nil) {
        privateKeyStr = @"";
    }
    [JDKeyChainWapper saveStringWithdIdentifier:@"CJH_RSA_PRI_KEY_C" data:privateKeyStr];
}

+ (void)saveServerPublicKeyStr:(NSString *)publicKeyStr
{
    if (publicKeyStr==nil) {
        publicKeyStr = @"";
    }
    [JDKeyChainWapper saveStringWithdIdentifier:@"CJH_RSA_PUB_KEY_S" data:publicKeyStr];
}

+ (NSString *)getCustomPublicKeyStr
{
    NSString *keyStr = @"";
    keyStr = [JDKeyChainWapper loadStringDataWithIdentifier:@"CJH_RSA_PUB_KEY_C"];
    return keyStr;
}

+ (NSString *)getCustomPrivateKeyStr
{
    NSString *keyStr = @"";
    keyStr = [JDKeyChainWapper loadStringDataWithIdentifier:@"CJH_RSA_PRI_KEY_C"];
    return keyStr;
}

+ (NSString *)getServerPublicKeyStr
{
    NSString *keyStr = @"";
    keyStr = [JDKeyChainWapper loadStringDataWithIdentifier:@"CJH_RSA_PUB_KEY_S"];
    return keyStr;
}


#pragma mark -- SG Token 相关操作 --
+ (BOOL)isHaveSgToken
{
    NSString *ret = [USER_DEFAULTS objectForKey:@"CJH_RSA_SG_TOKEN"];
    if(ret == nil||ret.length==0) {
        return NO;
    }
    return YES;
}
+ (void)saveSgToken:(NSString *)sgToken
{
    if(sgToken == nil) {
        sgToken = @"";
    }
    [USER_DEFAULTS setObject:sgToken forKey:@"CJH_RSA_SG_TOKEN"];
    [USER_DEFAULTS synchronize];
}

+ (NSString *)getSgToken
{
    NSString *ret = [USER_DEFAULTS objectForKey:@"CJH_RSA_SG_TOKEN"];
    if(ret == nil) {
        return @"";
    }
    return ret;
}

#pragma mark -- 校验SG合法性 --
+ (void)checkSGValidity:(NSString *)sg resultBlock:(CheckSGResultBlock)resultBlock
{
    NSAssert(resultBlock, @"CheckSGResultBlock不能为空");
    // 准备服务端公钥
    NSString *serverPublicKeyStr = [self getServerPublicKeyStr];

    // 加密SG
    NSDictionary *dataDic = @{@"SG":sg};
    NSString *dataStr = [GeneralUtils transformDictionaryToJsonStr:dataDic];
    NSString *encryptedDataStr = [FPRSAEncryptDecryptTool encryptSourceString:dataStr publicKey:serverPublicKeyStr];
   
    NSDictionary *parameDic = @{@"data":encryptedDataStr};
    [RSAHttpRequestHandler PostWithUrl:@"checkSG" withParameDic:parameDic successedBlock:^(NSDictionary *succeedResult) {
        
        NSDictionary *response = [GeneralUtils transformDictionaryByJson:succeedResult];
        // NSLog(@"checkSG---:%@",response);

        if (response&&[[response allValues] count]>0)
        {
            // 验签
            NSString *dataStr = succeedResult[@"data"];
            NSString *checkStr = succeedResult[@"checkStr"];
            
            FPRSAEncryptDecryptTool *rsaTool = [[FPRSAEncryptDecryptTool alloc]init];
            [rsaTool importKeyWithType:KeyTypePublic andkeyString:serverPublicKeyStr];
            
            BOOL isMatchSHA256 = [rsaTool verifySHA256String:dataStr withSign:checkStr];
            NSLog(@"isMatchSHA256:%d",isMatchSHA256);
            

            if (isMatchSHA256) {
                // Base64 解码
                NSData *decodedData =[[NSData alloc] initWithBase64EncodedString:dataStr options:0];
                NSString *sourceStr = [[NSString alloc]initWithData:decodedData encoding:NSUTF8StringEncoding];
                // NSLog(@"Base64 解码的结果:%@",sourceStr);
                
                NSDictionary *dataDic = [GeneralUtils transformDictionaryByString:sourceStr];
                NSString *codeStr = dataDic[@"code"];
                if ([codeStr isEqualToString:@"0000"])
                {
                    NSDictionary *temDic = dataDic[@"data"];
                    BOOL isExpire = [temDic[@"isExpire"] boolValue];
                    if (isExpire) {
                        // 过期重新获取SG,不过期不处理。
                        // 重新创建密钥对
                        BOOL creatResult = [self crateKeyPairWithOpenSSl];
                        if (creatResult) {
                            [self generateSGResultBlock:resultBlock];
                        } else {
                            NSLog(@"创建密钥失败");
                            resultBlock(nil,nil);
                        }
                    } else {
                        // 不过期
                        NSLog(@"SG不过期");
                        resultBlock(@"",nil);
                    }
                } else {
                    NSLog(@"请求失败");
                    resultBlock(nil,nil);
                }

            } else {
                NSLog(@"验签失败:非法的返回");
                resultBlock(nil,nil);
            }
        }
    } failedBolck:^(NSURLSessionDataTask *__unused task, NSError *error) {
    }];
}

#pragma mark -- 获取SG --
+ (void)generateSGResultBlock:(CheckSGResultBlock)resultBlock
{
    NSAssert(resultBlock, @"generateSGResultBlock不能为空");
    // 准备客户端公钥
    NSString *customPublicKeyStr = [self getCustomPublicKeyStr];
    
    // 准备服务端公钥
    NSString *serverPublicKeyStr = [self getServerPublicKeyStr];
    
    // 加密SG
    NSDictionary *dataDic = @{@"B1":customPublicKeyStr};
    NSString *dataStr = [GeneralUtils transformDictionaryToJsonStr:dataDic];
    NSString *encryptedDataStr = [FPRSAEncryptDecryptTool encryptSourceString:dataStr publicKey:serverPublicKeyStr];
    
    NSDictionary *parameDic = @{@"data":encryptedDataStr};
    [RSAHttpRequestHandler PostWithUrl:@"generateSG" withParameDic:parameDic successedBlock:^(NSDictionary *succeedResult) {
        
        NSDictionary *response = [GeneralUtils transformDictionaryByJson:succeedResult];
        // NSLog(@"generateSG---:%@",response);
        
        if (response&&[[response allValues] count]>0)
        {
            // 验签
            NSString *dataStr = succeedResult[@"data"];
            NSString *checkStr = succeedResult[@"checkStr"];
            
            FPRSAEncryptDecryptTool *rsaTool = [[FPRSAEncryptDecryptTool alloc]init];
            [rsaTool importKeyWithType:KeyTypePublic andkeyString:serverPublicKeyStr];
            
            BOOL isMatchSHA256 = [rsaTool verifySHA256String:dataStr withSign:checkStr];
            NSLog(@"isMatchSHA256:%d",isMatchSHA256);
            
            
            if (isMatchSHA256) {
                NSString *privatKeyStr = [self getCustomPrivateKeyStr];
                // 私钥解密
                NSString *rrrr = [FPRSAEncryptDecryptTool decryptSourceString:dataStr privateKey:privatKeyStr];
                // NSLog(@"私钥解密的结果:%@",rrrr);
                
                NSDictionary *dataDic = [GeneralUtils transformDictionaryByString:rrrr];
                NSString *codeStr = dataDic[@"code"];
                if ([codeStr isEqualToString:@"0000"])
                {
                    NSDictionary *temDic = dataDic[@"data"];
                    NSString *newSG = temDic[@"SG"];
                    [self saveSgToken:newSG];
                    
                    NSLog(@"获取SG成功");
                    resultBlock(newSG,nil);
                } else {
                    NSLog(@"获取SG失败");
                    resultBlock(nil,nil);
                }
                
            } else {
                NSLog(@"验签失败:非法的返回");
                resultBlock(nil,nil);
            }
        }
    } failedBolck:^(NSURLSessionDataTask *__unused task, NSError *error) {
    }];
}


@end
