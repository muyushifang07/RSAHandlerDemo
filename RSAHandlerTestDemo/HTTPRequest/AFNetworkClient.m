//
//  AFNetworkClient.m
//  cjh
//
//  Created by user_lzz on 15/10/28.
//  Copyright © 2015年 njcjh. All rights reserved.
//

#import "AFNetworkClient.h"
#import "RSAHelper.h"
#import "FPRSAEncryptDecryptTool.h"
#import "GeneralUtils.h"

@implementation AFNetworkClient

+ (instancetype)sharedClient
{
    static AFNetworkClient *_sharedClient = nil;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        
        _sharedClient = [[AFNetworkClient alloc] initWithBaseURL:[NSURL URLWithString:@"http://192.168.1.104:8080/"]];
        
        _sharedClient.securityPolicy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeNone];
        _sharedClient.requestSerializer = [AFJSONRequestSerializer serializer];
        _sharedClient.responseSerializer = [AFJSONResponseSerializer serializer];

        
        NSString *userAgent = [NSString stringWithFormat:@"%@/%@ (%@; iOS %@; Scale/%0.2f)",
                               [[NSBundle mainBundle] infoDictionary][(__bridge NSString *)kCFBundleExecutableKey] ?: [[NSBundle mainBundle] infoDictionary][(__bridge NSString *)kCFBundleIdentifierKey],
                               [[NSBundle mainBundle] infoDictionary][(__bridge NSString *)kCFBundleVersionKey],
                               [[UIDevice currentDevice] model],
                               [[UIDevice currentDevice] systemVersion],
                               [[UIScreen mainScreen] scale]];
        
        [_sharedClient.requestSerializer setValue:userAgent forHTTPHeaderField:@"User-Agent"];
    });
    
    return _sharedClient;
    
}

@end


@implementation HttpUtil

// 重要!!!!!----都要返回response,不然前端页面处理异常------

/**
 * @brief POST获取数据
 * @param url               请求地址
 * @param reqDic            请求参数
 * @param successedBlock    成功回调
 * @param failedBolck       失败回调
 **/

+ (void)postWithUrl:(NSString *)url
            withReq:(NSDictionary *)reqDic
     successedBlock:(SuccessedBlock)success
        failedBolck:(FailedBlock)failed
{
    // 临时字典，防止reqDic 为nil时 异常
    NSMutableDictionary *temParams = [[NSMutableDictionary alloc] initWithDictionary:reqDic];
    
    // 准备服务端公钥：加密
    NSString *serverPublicKeyStr = [RSAHelper getServerPublicKeyStr];
    NSString *dataStr = [GeneralUtils transformDictionaryToJsonStr:temParams];
    NSString *encryptedDataStr = [FPRSAEncryptDecryptTool encryptSourceString:dataStr publicKey:serverPublicKeyStr];
    
    NSDictionary *requestParams = @{@"data":encryptedDataStr,@"SG":[RSAHelper getSgToken]};
    [[AFNetworkClient sharedClient] POST:url parameters:requestParams progress:^(NSProgress * _Nonnull uploadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        NSDictionary *response = [GeneralUtils transformDictionaryByJson:responseObject];
        NSLog(@"签名的---:%@",response);
        
        if (response&&[[response allKeys] count]>0)
        {
            // 验签
            NSString *dataStr = response[@"data"];
            NSString *checkStr = response[@"checkStr"];
            
            FPRSAEncryptDecryptTool *rsaTool = [[FPRSAEncryptDecryptTool alloc]init];
            [rsaTool importKeyWithType:KeyTypePublic andkeyString:serverPublicKeyStr];
            
            BOOL isMatchSHA256 = [rsaTool verifySHA256String:dataStr withSign:checkStr];
            NSLog(@"isMatchSHA256:%d",isMatchSHA256);
            
            if (isMatchSHA256) {
                
                if ([[response allKeys] containsObject:@"isExpire"]) {
                    // SG过期，走重新生成SG的步骤
                    [RSAHelper generateSGResultBlock:^(id model, id error) {
                        if (model) {
                            // 获取SG成功，继续下面操作
                            NSLog(@"SG过期,重新生成SG成功");
                        } else {
                            NSLog(@"SG过期,重新生成SG失败");
                        }
                    }];
                    success(response);
                } else {
                    NSString *privatKeyStr = [RSAHelper getCustomPrivateKeyStr];
                    // 私钥解密
                    NSString *rrrr = [FPRSAEncryptDecryptTool decryptSourceString:dataStr privateKey:privatKeyStr];
                    NSLog(@"私钥解密的结果:%@",rrrr);
                    
                    NSDictionary *dataDic = [GeneralUtils transformDictionaryByString:rrrr];
                    success(dataDic);
                }
            }
        } else {
            NSLog(@"http请求返回的结果字典：为空字典");
            success(response);
        }
        
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        failed(task,error);
    }];
}

+ (void)RequestpPostWithUrlNotPortWithCode:(NSString *)url
                                   withReq:(NSDictionary *)reqDic
                            successedBlock:(SuccessedBlock)success
                               failedBolck:(FailedBlock)failed
{
    NSMutableDictionary *requestParams = [[NSMutableDictionary alloc] initWithDictionary:reqDic];
    [[AFNetworkClient sharedClient] POST:url parameters:requestParams progress:^(NSProgress * _Nonnull uploadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        success(responseObject);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        failed(task,error);
    }];
}


@end
