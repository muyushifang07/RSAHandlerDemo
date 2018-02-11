//
//  AFNetworkClient.h
//  cjh
//
//  Created by user_lzz on 15/10/28.
//  Copyright © 2015年 njcjh. All rights reserved.
//

#import <AFNetworking/AFNetworking.h>
#import <AFHTTPSessionManager.h>

@interface AFNetworkClient : AFHTTPSessionManager

+ (instancetype)sharedClient;

@end


///成功回调
typedef void (^SuccessedBlock)(NSDictionary *succeedResult);

///失败回调
typedef void (^FailedBlock)(NSURLSessionDataTask * __unused task, NSError *error);

@interface HttpUtil : NSObject


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
        failedBolck:(FailedBlock)failed;

+ (void)RequestpPostWithUrlNotPortWithCode:(NSString *)url
                                   withReq:(NSDictionary *)reqDic
                            successedBlock:(SuccessedBlock)success
                               failedBolck:(FailedBlock)failed;


@end
