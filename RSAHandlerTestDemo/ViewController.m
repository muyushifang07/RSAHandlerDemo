//
//  ViewController.m
//  RSAHandlerTestDemo
//
//  Created by user_lzz on 2018/2/10.
//  Copyright © 2018年 user_lzz. All rights reserved.
//

#import "ViewController.h"
#import "RSAHelper.h"
#import "RSAHttpRequestHandler.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSLog(@"进来了吧！！！！");
    
    // 请先看工程中  Pasted Graphic.pdf 图解
    
    // 客户端密钥
    if (![RSAHelper checkLocalKeyPairIsExisted]) {
        [RSAHelper creatKeyPairAndSaveKeyChain];
    }
    
    // 服务端密钥
    [self getServerPublicKeyAdvertImage];
    
    
}

// 获取服务端密钥的接口
#pragma mark -- 第一个请求接口很重要 --
- (void)getServerPublicKeyAdvertImage
{
    // 自己的接口地址
    NSString *urlStr = @"activeMember";
    [RSAHttpRequestHandler PostWithUrl:urlStr withParameDic:@{@"member_id":@""} successedBlock:^(NSDictionary *succeedResult)
     {
         NSLog(@"activeMember======%@",succeedResult);
         if ([succeedResult[@"code"] isEqualToString:@"0000"])
         {
             // 存储公钥
             NSString *serverPubKetStr = succeedResult[@"data"][@"A1"];
             [RSAHelper saveServerPublicKeyStr:serverPubKetStr];
             
             // 判断SG,有则校验，没有获取
             if ([RSAHelper isHaveSgToken]) {
                 [RSAHelper checkSGValidity:[RSAHelper getSgToken] resultBlock:^(id model, id error) {
                     if (model) {
                         // 获取SG成功，继续你自己接下来的操作
                         
                     } else {
                         // 失败时怎么处理，看自己需要
                     }
                 }];
             } else {
                 [RSAHelper generateSGResultBlock:^(id model, id error) {
                     if (model) {
                         // 获取SG成功，继续你自己接下来的操作
                     } else {
                         // 失败时怎么处理，看自己需要
                     }
                 }];
             }
         } else {
         }
     } failedBolck:^(NSURLSessionDataTask *__unused task, NSError *error) {
         
     }];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
