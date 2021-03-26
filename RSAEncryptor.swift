//
//  RSAEncryptor.swift
//  GIS2020
//
//  Created by boco on 2020/9/23.
//  Copyright © 2020 gemaojing. All rights reserved.
//

import UIKit
import Foundation
import Security

/// GMJ---RSA并.p12加密解密
class RSAEncryptor: NSObject {
    
    enum RSAError: Error {
         case chunkEncryptFailed(index: Int)
         case keyCopyFailed(status: OSStatus)
         case tagEncodingFailed
         case keyCreateFailed(error: CFError?)
        case chunkDecryptFailed(index: Int)
        var localizedDescription: String {
            switch self {
            case .chunkEncryptFailed(let index):
                return "Couldn't encrypt chunk at index \(index)"
            case .keyCopyFailed(let status):
                return "Couldn't copy and retrieve key reference from the keychain: OSStatus \(status)"
            case .tagEncodingFailed:
                return "Couldn't create tag data for key"
            case .keyCreateFailed(let error):
                return "Couldn't create key reference from key data: CFError \(String(describing: error))"
            case .chunkDecryptFailed(let index):
                return "Couldn't decrypt chunk at index \(index)"
            default:
                return "Couldn't encrypt chunk at index"
            }
        }
    }
    
    
static func base64_encode_data(data:Data) -> String {
        let dataT =  data.base64EncodedData(options: .lineLength64Characters)//0
        let ret = String(data: dataT, encoding: .utf8) ?? "数据不存在"
        return ret
    }
    
static func bese64_decode(str:String) -> Data {
        let dateDefaule = "数据不存在".data(using: .utf8)! as Data
        let dataT:Data = Data(base64Encoded: str, options: .ignoreUnknownCharacters) ?? dateDefaule
        return dataT
    }
    
    /**01
    * rsa加密方法
    *
    * @param str  需要加密的字符串
    * @param  path  ‘.der'格式的公钥文件路径
    */
    // 01
    func encryptString(str:String, path:String) ->String {
        /// publicKeyWithContentsOfFile
        if (str.isEmpty || path.isEmpty)  {
            return "空值"
        }
        let seckey = self.getPublicKeyRefWithContentsOfFile(filePath: path)
        let ret = self.encryptString(str: str, publicKeyRef: seckey)
        return ret
    }
    
    // 获取公钥 02
    func getPublicKeyRefWithContentsOfFile(filePath:String) -> SecKey {
        let certData = NSData(contentsOfFile: filePath)
        if certData?.length == 0 {
            return 0 as! SecKey
        }
        let cert = SecCertificateCreateWithData(nil, certData!)
        var key:SecKey?  = nil
        var trust:SecTrust? = nil
        var policy:SecPolicy? = nil
        if cert != nil {
            policy = SecPolicyCreateBasicX509()
            if (policy != nil) {
                if SecTrustCreateWithCertificates(cert as CFTypeRef, policy, &trust) == noErr {
                    var result = SecTrustResultType.invalid
                    if SecTrustEvaluate(trust!, &result) == noErr{
                        key = SecTrustCopyPublicKey(trust!)
                    }
                }
            }
        }
//         if (policy) CFRelease(policy); 释放 Create，Copy 或者 Retain
//         if (trust) CFRelease(trust);
//         if (cert) CFRelease(cert);
        return key!
    }
    
    // 03
    func encryptString(str:String, publicKeyRef:SecKey) -> String {
        if str.data(using: .utf8)!.isEmpty {
            return "空值"
        }
        
        let dataT = self.encryptData(data: str.data(using: .utf8)!, keyRef: publicKeyRef)
        let ret  = RSAEncryptor.base64_encode_data(data: dataT)
        return ret
         
    }
    
    // MARK:==使用'.12'私钥文件解密
    
    /// 使用'.12'私钥文件解密 04 main Decrypt
    func decryptString(str:String, path:String, password:String) -> String {
        if (str.isEmpty || path.isEmpty)  { return "空值" }
        if password.count == 0 {
            return "空密码"
        }
        let privateKeyRef = self.getPrivateKeyRefWithContentsOfFile(filePath: path, password: password)// 获取私钥 05
        let ret =  self.decryptString(str: str, privKeyRef: privateKeyRef)
        return ret
    }
 
    
/// 使用'.12'私钥文件解密 05
    func getPrivateKeyRefWithContentsOfFile(filePath:String, password:String) -> SecKey {
        
        let PKCS12Data = NSData(contentsOfFile:filePath)!
        
//        if p12Data == nil {
//            return 0 as! SecKey
//        }
        var privateKeyRef:SecKey?
        let key:NSString = kSecImportExportPassphrase as NSString
        let options:NSDictionary = [key:password]
        print("==========使用'.12'私钥文件解密 05================")
    
        var items : CFArray? // var items:CFArray? = CFArrayCreate(nil, nil, 0, nil)
        
        var securityError:OSStatus = SecPKCS12Import(PKCS12Data, options, &items)
        
//        if (securityError == noErr) && (CFArrayGetCount(items) > 0) {
//            let identityDict =  CFArrayGetValueAtIndex(items, 0)  as! CFDictionary // :CFDictionary
//            let identityApp:SecIdentity = CFDictionaryGetValue(identityDict, kSecImportItemIdentity as String) as! SecIdentity
//            securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef)
//        }
        
        
         let theArray : CFArray = items!
         if (securityError == noErr) && (CFArrayGetCount(items) > 0) {
            let newArray = theArray as [AnyObject] as NSArray
            let dictionary = newArray.object(at: 0) as! NSDictionary
            let secIdentity = dictionary[kSecImportItemIdentity as String] as! SecIdentity
            let securityError = SecIdentityCopyPrivateKey(secIdentity , &privateKeyRef)
            if securityError != noErr {
                privateKeyRef = nil
            }
        }
        return privateKeyRef ?? 0 as! SecKey
    }
    //获取客户端证书相关信息
    
  
    
    /// 使用'.12'私钥文件解密 06
    func decryptString(str:String, privKeyRef:SecKey) -> String {
        var  data = Data.init(base64Encoded: str, options: .ignoreUnknownCharacters)
//        if privKeyRef == nil {
//            return "空值"
//        }
        // 16
         print("==========使用'.12'私钥文件解密 06================")
        data = self.decryptData(data: data!, keyRef: privKeyRef)
        let ret = String(data: data!, encoding: .utf8)
        return ret ?? "空值"
    }
    
    
    
    
    // 使用'.12'私钥文件解密 11
    func encryptData(data:Data,keyRef:SecKey) -> Data {
        let padding = SecPadding.PKCS1
        let blockSize = SecKeyGetBlockSize(keyRef)
              
              var maxChunkSize: Int
              switch padding {
              case []:
                  maxChunkSize = blockSize
              case .OAEP:
                  maxChunkSize = blockSize - 42
              default:
                  maxChunkSize = blockSize //- 11
              }
              
              var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
              (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
              
              var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
              var idx = 0
              
              while idx < decryptedDataAsArray.count {
                  
                  let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
                  let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
                  
                  var encryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
                  var encryptedDataLength = blockSize
                  
                  let status = SecKeyEncrypt(keyRef, padding, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
                  
                  guard status == noErr else {
                    let error = "第11-encryptDatakeyRef错误 = \(idx)".data(using: .utf8)
                    return error!
                  }
                  
                  encryptedDataBytes += encryptedDataBuffer
                  
                  idx += maxChunkSize
              }
              
              let encryptedData = Data(bytes: encryptedDataBytes, count: encryptedDataBytes.count)
              return encryptedData
        
    }
    
    
     // MARK: - - 使用私钥字符串解密
   /// 使用私钥字符串解密 12
    func decryptString(str:String, privKey:String)-> String{
        if str.count == 0 {
            return "空值"
        }
        var data = Data.init(base64Encoded: str, options: .ignoreUnknownCharacters)
        data = self.decryptData(data: data!, privKey: privKey) // 13
        let ret = String.init(data: data!, encoding: .utf8) ?? "空值"
        return ret
    }
    /// 使用私钥字符串解密 13
    func decryptData(data:Data, privKey:String) -> Data {
//        if data == nil || privKey == nil {
//            return 0
//        }
        let keyRef = self.addPrivateKey(key: privKey)
        let ret = self.decryptData(data: data, keyRef: keyRef)// 16
        return ret
    }
    /// 使用私钥字符串解密 14
    func addPrivateKey(key:String) -> SecKey {
        
        
        if #available(iOS 10.0, *), #available(watchOS 3.0, *), #available(tvOS 10.0, *) {
                         let keyData = key.data(using: .utf8)
                         let tag = "RSAUtil_PrivKey"
                         let isPublic = false
            
            guard tag.data(using: .utf8) != nil else {
                print(RSAError.tagEncodingFailed)
                return 0 as! SecKey  //throw
            }
                         
               let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
            
                 let sizeInBits = keyData!.count * 8
                  let keyDict: [CFString: Any] = [
                      kSecAttrKeyType: kSecAttrKeyTypeRSA,
                      kSecAttrKeyClass: keyClass,
                      kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
                      kSecReturnPersistentRef: true
                  ]
                  
                  var error: Unmanaged<CFError>?
            guard let ret = SecKeyCreateWithData(keyData! as CFData, keyDict as CFDictionary, &error) else {
                      print(RSAError.keyCreateFailed(error: error?.takeRetainedValue()))
                return 0 as! SecKey       //throw
                  }
                  return ret
                  
              // On iOS 9 and earlier, add a persistent version of the key to the system keychain
        } else {
            
            var keyns = key as NSString
                    let spos = keyns.range(of: "-----BEGIN RSA PRIVATE KEY-----")
                    let epos = keyns.range(of: "-----END RSA PRIVATE KEY-----")
                    if (spos.location != NSNotFound) && (epos.location != NSNotFound) {
                        let s = spos.location + spos.length
                        let e = epos.location
                        let range = NSMakeRange(s, e - s)
                        keyns = keyns.substring(with: range) as NSString
                    }
                
                    keyns = keyns.replacingOccurrences(of: "\r", with: "") as NSString
                    keyns = keyns.replacingOccurrences(of: "\n", with: "") as NSString
                    keyns = keyns.replacingOccurrences(of: "\t", with: "")  as NSString
                    keyns = keyns.replacingOccurrences(of: " ", with: "")  as NSString
                    
                    //这将是base64编码，解码。
                    var data = RSAEncryptor.bese64_decode(str: keyns as String)
                    data = self.stripPrivateKeyHeader(d_key: data)
           
                    // 读-写密钥链存储器的标签
                    let tag = "RSAUtil_PrivKey"
                    let d_tag = tag.data(using: .utf8)
                    //删除具有相同标记的任何旧延迟键
                   let privateKey = NSMutableDictionary()
                    privateKey.setObject(kSecClassKey, forKey: kSecClass as! NSCopying)
                    privateKey.setObject(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType as! NSCopying)
            privateKey.setObject(d_tag!, forKey: kSecAttrApplicationTag as! NSCopying)
                    SecItemDelete(privateKey)
                    
                    //将密钥的持久版本添加到系统密钥链
                    privateKey.setObject(data, forKey: kSecValueData as! NSCopying)
                    privateKey.setObject(kSecAttrKeyClassPrivate, forKey: kSecAttrKeyClass as! NSCopying)
                    privateKey.setObject(true, forKey: kSecReturnPersistentRef as! NSCopying)// NSNumber(value: true)
                    
                    var persistKey:CFTypeRef? = nil
            let status:OSStatus = SecItemAdd(privateKey, &persistKey)
                    if persistKey != nil {
                       persistKey = nil
                    }
                    if (status != noErr) && (status != errSecDuplicateItem) {
                        return 0 as! SecKey
                    }
                    privateKey.removeObject(forKey: kSecValueData as! NSCopying)
                    privateKey.removeObject(forKey: kSecReturnPersistentRef as! NSCopying)
                    privateKey.setObject(true, forKey: kSecReturnRef as! NSCopying) // NSNumber(value: true)
                    privateKey.setObject(kSecAttrKeyTypeRSA, forKey: kSecAttrKeyType as! NSCopying)
                    
                  //现在获取密钥的SecKeyRef版本
                   var keyRef: AnyObject?
                   let keyCopyDict = privateKey as CFDictionary
                    let copyStatus = SecItemCopyMatching(keyCopyDict, &keyRef)
                    
                    guard let unwrappedKeyRef = keyRef else {
                        print(RSAError.keyCopyFailed(status: copyStatus))
                        return 0 as! SecKey
                    }
                    return unwrappedKeyRef as! SecKey // swiftlint:disable:this force_cast
        }  //=end else=
    } // =end  func 14
 

    
//    /// 使用私钥字符串解密 15
    func  stripPrivateKeyHeader(d_key:Data) -> Data {
           // Skip ASN.1 private key header
        if d_key == nil {
            return "空值".data(using: .utf8)!
        }
        let len:CUnsignedLong = CUnsignedLong(d_key.count)
        if len == 0  {
            print("  let len:CUnsignedLong = CUnsignedLong(d_key.count) = 0 空值")
        }
        // [UTF8](d_key)
        let bytes = [UInt8](d_key)
        let c_key = bytes as [CUnsignedChar]
        
        
        var idx:CUnsignedInt = 22
        // idx = 22
        if 0x04 != c_key[Int(idx)] {
            return "0x04 error".data(using: .utf8)!  // 22位不是0x04
        }
        
        idx = idx + 1 // 是 0x04
        
        // idx = 23
        //计算键的长度
        var c_len:CUnsignedInt = CUnsignedInt(c_key[Int(idx)])
        idx = idx + 1 // 是
        // idx = 24
        let det:CInt = CInt(c_len & 0x80)
        if det == 0 {
            c_len = c_len & 0x07f
        } else {
            var byteCount:CInt = CInt(c_len & 0x07f)
            if byteCount + CInt(idx) > len {
                return "0x07f error".data(using: .utf8)!  // 24位 return nil;
            }
            var accum:CUnsignedInt = 0

            var ckc = c_key[Int(idx)] //&(c_key[Int(idx)])
            var ptr:CUnsignedChar = address(o: &ckc)
            idx = idx + UInt32(byteCount)
            while byteCount != 0 {
                accum = (accum << 8) + UInt32(ptr)
                ptr = ptr + 1
                byteCount = byteCount - 1
            }
            c_len = accum
        }
        
        let rData = d_key as NSData
        let ret =  rData.subdata(with:NSMakeRange(Int(idx), Int(c_len)))
        return ret as Data
    }
    
    func address(o: UnsafePointer<Void>) -> CUnsignedChar {
        return unsafeBitCast(o, to: CUnsignedChar.self)
    }
    
    
    
    /// 16 私钥方法
    func decryptData(data:Data, keyRef:SecKey) -> Data {
        let blockSize = SecKeyGetBlockSize(keyRef)
        
        var encryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&encryptedDataAsArray, length: data.count)
        
        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
            
            let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
            let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
            
            var decryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var decryptedDataLength = blockSize
            
            let status = SecKeyDecrypt(keyRef, .PKCS1, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            guard status == noErr else {
                print(RSAError.chunkDecryptFailed(index: idx))
                return "空值".data(using: .utf8)!
            }
            
            decryptedDataBytes += [UInt8](decryptedDataBuffer[0..<decryptedDataLength])
            
            idx += blockSize
        }
        
        let decryptedData = Data(bytes: decryptedDataBytes, count: decryptedDataBytes.count)
        return decryptedData
    }

    
   
    
    
    
    
    
    /**02
    * rsa解密方法
    *
    * @param str  需要解密的字符串
    * @param  path  ‘.p12'格式的私钥文件路径
    * @param  password  私钥文件密码
    */
    
    
    /**03
    * rsa加密方法
    *
    * @param str  需要加密的字符串
    * @param  pubKey  公钥字符串
    */
    
    
    
    /**04
    *  解密方法
    *
    *  @param str     需要解密的字符串
    *  @param privKey 私钥字符串
    */
    
    
}









