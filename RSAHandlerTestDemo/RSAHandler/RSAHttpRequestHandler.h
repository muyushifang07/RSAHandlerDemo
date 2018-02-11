//
//  RSAHttpRequestHandler.h
//  cjh
//
//  Created by user_lzz on 2018/2/7.
//  Copyright © 2018年 njcjh. All rights reserved.
//

#import <Foundation/Foundation.h>
///成功回调
typedef void (^SuccessedBlock)(NSDictionary *succeedResult);

///失败回调
typedef void (^FailedBlock)(NSURLSessionDataTask * __unused task, NSError *error);

@interface RSAHttpRequestHandler : NSObject

+ (void)PostWithUrl:(NSString *)url
            withParameDic:(NSDictionary *)reqDic
     successedBlock:(SuccessedBlock)success
        failedBolck:(FailedBlock)failed;

@end
