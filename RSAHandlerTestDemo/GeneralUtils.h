//
//  GeneralUtils.h
//  RSAHandlerTestDemo
//
//  Created by user_lzz on 2018/2/10.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface GeneralUtils : NSObject

+ (NSString *)transformDictionaryToJsonStr:(NSDictionary *)dic;

+ (id)transformDictionaryByJson:(NSDictionary *)jsonDictionary;

+ (id)transformDictionaryByString:(NSString *)jsonString;

@end
