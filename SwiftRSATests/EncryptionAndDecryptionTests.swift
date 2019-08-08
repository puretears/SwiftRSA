//
//  EncryptionAndDecryptionTests.swift
//  SwiftRSATests
//
//  Created by Mars on 2019/8/7.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation
import XCTest
import Security
@testable import SwiftRSA

class EncryptionAndDecryptionTests: XCTestCase {
  static let tag = "io.boxue.tests.rsa".data(using: .utf8)!
  
  static let pri: SecKey = {
    let queryDic: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits as String: 2048,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag
      ]
    ]
    
    var error: Unmanaged<CFError>?
    return SecKeyCreateRandomKey(queryDic as CFDictionary, &error)!
  }()
  
  static let privateKey = PrivateKey(key: pri)
  
  static let pub: SecKey = { SecKeyCopyPublicKey(pri)! }()
  static let publicKey = PublicKey(key: pub)
  
  override func setUp() {}

  override func tearDown() {}
  
  /// Test `protocol Key`
  
  func testFetchKeyData() throws {
    _ = try EncryptionAndDecryptionTests.publicKey.data()
    _ = try EncryptionAndDecryptionTests.privateKey.data()
  }
  
  func testGetBase64String() throws {
    _ = try EncryptionAndDecryptionTests.publicKey.base64String()
    _ = try EncryptionAndDecryptionTests.privateKey.base64String()
  }
  
  func testCreatePublicKeyFromBase64EncodedKey() throws {
    /// 1. Normal case
    let der = try EncryptionAndDecryptionTests.publicKey.data()
    let base64ed = der.base64EncodedString()
    
    var k = PublicKey(base64Encoded: base64ed)
    
    XCTAssertNotNil(k)
    
    /// 2. Invalid base64 string
    k = PublicKey(base64Encoded: "$")
    XCTAssertNil(k)
  }
  
  func testCreatePrivateKeyFromBase64EncodedKey() throws {
    /// 1. Normal case
    let der = try EncryptionAndDecryptionTests.privateKey.data()
    let base64ed = der.base64EncodedString()
    
    var k = PrivateKey(base64Encoded: base64ed)
    
    XCTAssertNotNil(k)
    
    /// 2. Invalid base64 string
    k = PrivateKey(base64Encoded: "$")
    XCTAssertNil(k)
  }
 
  func testGetPublicKeyInPEM() throws {
    _ = try EncryptionAndDecryptionTests.publicKey.pemString()
  }
  
  func testGetPrivateKeyInPEM() throws {
    _ = try EncryptionAndDecryptionTests.privateKey.pemString()
  }
  
  func testCreatePublicKeyFromPEMEncodedKey() throws {
    /// 1. Normal case
    let pem = try EncryptionAndDecryptionTests.publicKey.pemString()
    var k = PublicKey(pemEncoded: pem)
    
    XCTAssertNotNil(k)
    
    /// 2. Invalid base64 string
    k = PublicKey(pemEncoded: "$")
    XCTAssertNil(k)
  }
  
  func testCreatePrivateKeyFromPEMEncodedKey() throws {
    /// 1. Normal case
    let pem = try EncryptionAndDecryptionTests.privateKey.pemString()
    var k = PrivateKey(pemEncoded: pem)
    
    XCTAssertNotNil(k)
    
    /// 2. Invalid base64 string
    k = PrivateKey(pemEncoded: "$")
    XCTAssertNil(k)
  }
  
  func testEncryptionAndDecryption() throws {
    let ct = ClearText(string: "Hello world")
    let encrypted = try ct.encrypted(with: EncryptionAndDecryptionTests.publicKey, by: .rsaEncryptionOAEPSHA512)
    
    let originText = try encrypted.decrypted(with: EncryptionAndDecryptionTests.privateKey)
    
    XCTAssertEqual(originText.stringValue, "Hello world")
  }
  
  func testEncryptOversizedClearText() throws {
    let size = try ClearText.maxClearTextInLength(
      EncryptionAndDecryptionTests.publicKey.key, algorithm: .rsaEncryptionOAEPSHA512)
    
    var oversized = String(repeating: "A", count: size + 1)
    var ct = ClearText(string: oversized)
    var encrypted = try? ct.encrypted(with: EncryptionAndDecryptionTests.publicKey, by: .rsaEncryptionOAEPSHA512)
    
    XCTAssertNil(encrypted)
    
    oversized = String(repeating: "A", count: size)
    ct = ClearText(string: oversized)
    encrypted = try? ct.encrypted(with: EncryptionAndDecryptionTests.publicKey, by: .rsaEncryptionOAEPSHA512)
    
    XCTAssertNotNil(encrypted)
  }
}
