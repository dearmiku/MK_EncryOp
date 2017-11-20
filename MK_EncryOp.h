//
//  MK_EncryOp.h
//  加密
//
//  Created by MBP on 2017/11/20.
//  Copyright © 2017年 leqi. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
/*
 * 添加动态库 Security.framework
 */

///常规加密/解密 方法集合
@interface MK_EncryOp : NSObject

#pragma mark Base64 相关

/**
 base64编码

 @param data 需编码数据
 @return 结果
 */
+(NSString*)base64EncodeWithData:(NSData*)data;


/**
 base64解码

 @param str 需解码字符串
 @return 结果
 */
+(NSData*)base64DecodeWithData:(NSString*)str;

#pragma mark AES相关


/**
 进行AES加密 (加密模式: 填充模式:PKCS7Padding CBC模式)

 @param content 要加密的内容
 @param kKeySize 秘钥长度 有 kCCKeySizeAES128 kCCKeySizeAES192 kCCKeySizeAES256
 @param key 秘钥字符串
 @param iv 初始向量
 @return 结果
 */
+(NSData *)AESEncryptWithdData:(NSData *)content andKeySize:(CCOptions)kKeySize andKey:(NSString *)key andIV:(NSString*)iv;

+(NSData *)AESDecryptWithdData:(NSData *)content andKeySize:(CCOptions)kKeySize andKey:(NSString *)key andIV:(NSString*)iv;


#pragma mark 散列函数相关
#pragma mark 字符串散列
/**
 MD5加密

 @param string 需加密字符串
 @return 结果
 */
+(NSString *)md5WithStr:(NSString*)string;
/**
 SHA1加密

 @param string 需加密字符串
 @return 结果
 */
+(NSString *)sha1WithStr:(NSString*)string;
/**
 SHA256加密

 @param string 需加密字符串
 @return 结果
 */
+(NSString *)sha256WithStr:(NSString*)string;
/**
 SHA512加密

 @param string 需加密字符串
 @return 结果
 */
+(NSString *)sha512WithStr:(NSString*)string;

#pragma mark 加盐

/**
 MD5加盐加密

 @param string 加密字符串
 @param key 盐
 @return 结果
 */
+(NSString *)hmacMD5StringWithStr:(NSString*)string andWithKey:(NSString *)key;
/**
 SHA1加盐加密

 @param string 加密字符串
 @param key 盐
 @return 结果
 */
+(NSString *)hmacSHA1WithStr:(NSString*)string andWithKey:(NSString *)key;
/**
 SHA256加盐加密

 @param string 加密字符串
 @param key 盐
 @return 结果
 */
+(NSString *)hmacSHA256WithStr:(NSString*)string andWithKey:(NSString *)key;
/**
 SHA512加盐加密

 @param string 加密字符串
 @param key 盐
 @return 结果
 */
+(NSString *)hmacSHA512WithStr:(NSString*)string andWithKey:(NSString *)key;

#pragma mark 文件散列

/**
 MD5文件散列

 @param path 文件路径
 @return 结果
 */
+(NSString *)md5FileWithPath:(NSString*)path;
/**
 SHA1文件散列

 @param path 文件路径
 @return 结果
 */
+(NSString *)sha1WithPath:(NSString*)path;
/**
 SHA256文件散列

 @param path 文件路径
 @return 结果
 */
+(NSString *)sha256WithPath:(NSString*)path;
/**
 SHA512文件散列

 @param path 文件路径
 @return 结果
 */
+(NSString *)sha512WithPath:(NSString*)path;
#pragma mark RSA相关
/**
 *  加密方法
 *
 *  @param str   需要加密的字符串
 *  @param path  '.der'格式的公钥文件路径
 */
+ (NSString *)RSAencryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;

/**
 *  解密方法
 *
 *  @param str       需要解密的字符串
 *  @param path      '.p12'格式的私钥文件路径
 *  @param password  私钥文件密码
 */
+ (NSString *)RSAdecryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString *)password;

/**
 *  加密方法
 *
 *  @param str    需要加密的字符串
 *  @param pubKey 公钥字符串
 */
+ (NSString *)RSAencryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 *  解密方法
 *
 *  @param str     需要解密的字符串
 *  @param privKey 私钥字符串
 */
+ (NSString *)RSAdecryptString:(NSString *)str privateKey:(NSString *)privKey;
@end
