//
//  RSAHttpRequestHandler.m
//  cjh
//
//  Created by user_lzz on 2018/2/7.
//  Copyright © 2018年 njcjh. All rights reserved.
//

#import "RSAHttpRequestHandler.h"
#import "AFNetworkClient.h"

@implementation RSAHttpRequestHandler

+ (void)PostWithUrl:(NSString *)url
      withParameDic:(NSDictionary *)reqDic
     successedBlock:(SuccessedBlock)success
        failedBolck:(FailedBlock)failed
{
    // 临时字典，防止reqDic 为nil时 异常
    NSMutableDictionary *requestParams = [[NSMutableDictionary alloc] initWithDictionary:reqDic];
    
    [[AFNetworkClient sharedClient] POST:url parameters:requestParams progress:^(NSProgress * _Nonnull uploadProgress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObject) {
        
        success(responseObject);
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        failed(task,error);
    }];
}

@end
