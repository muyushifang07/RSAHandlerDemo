//
//  GeneralUtils.m
//  RSAHandlerTestDemo
//
//  Created by user_lzz on 2018/2/10.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import "GeneralUtils.h"

@implementation GeneralUtils

+ (NSString *)transformDictionaryToJsonStr:(NSDictionary *)dic
{
    if ([NSJSONSerialization isValidJSONObject:dic]) {
        NSError *parseError = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic options:0 error:&parseError];
        return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    } else {
        return nil;
    }
}

+ (id)transformDictionaryByJson:(NSDictionary *)jsonDictionary {
    if ([NSJSONSerialization isValidJSONObject:jsonDictionary]) {
        return jsonDictionary;
    }
    else {
        return nil;
    }
}

+ (id)transformDictionaryByString:(NSString *)jsonString
{
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    
    if (jsonData==nil) {
        return nil;
    } else {
        NSError *err;
        NSDictionary *jsonDictionary = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&err];
        if(!err) {
            return jsonDictionary;
        }else {
            return nil;
        }
    }
}
@end
