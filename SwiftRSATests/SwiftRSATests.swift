//
//  SwiftRSATests.swift
//  SwiftRSATests
//
//  Created by Mars on 2019/7/29.
//  Copyright © 2019 Mars. All rights reserved.
//

import XCTest
import Security
@testable import SwiftRSA

class SwiftRSATests: XCTestCase {
  override func setUp() {}

  override func tearDown() {}
  
  func testGetBase64String() {
    let body = "12345"
    let str = """
    -----BEGIN-----
    \(body)
    -----END-----
    """
    
    let base64Part = try? SwiftRSA.base64String(pemEncoded: str)
    
    XCTAssertNotNil(base64Part)
    XCTAssertEqual(base64Part!, body)
  }
  
  func testGetEmptyBase64String() {
    let str = """
    -----BEGIN-----
    -----END-----
    """
    
    let base64Part = try? SwiftRSA.base64String(pemEncoded: str)
    
    XCTAssertNil(base64Part)
  }
  
  func testCreatekey() {
    var base64Body = try! SwiftRSA.base64String(pemEncoded: SwiftRSATests.pri)
    var derData = Data(base64Encoded: base64Body)!
    var key = try? SwiftRSA.createKey(derData, isPublic: false)
    
    XCTAssertNotNil(key)
    
    base64Body = try! SwiftRSA.base64String(pemEncoded: SwiftRSATests.pub)
    derData = Data(base64Encoded: base64Body)!
    key = try? SwiftRSA.createKey(derData, isPublic: true)
    
    XCTAssertNotNil(key)
  }
  
  func testFetchDataFromSecKey() {
    let base64Body = try! SwiftRSA.base64String(pemEncoded: SwiftRSATests.pri)
    let derData = Data(base64Encoded: base64Body)!
    let priKey = try! SwiftRSA.createKey(derData, isPublic: false)
    
    let data = try? SwiftRSA.data(forKey: priKey)
    let based64Encoded = data!.base64EncodedString()
    let expected = try! SwiftRSA.base64String(pemEncoded: SwiftRSATests.pri)
    
    XCTAssertEqual(based64Encoded, expected)
  }
  
  func testPEMFormatted() {
    let body = "12345"
    
    let formatted = SwiftRSA.format(der: body.data(using: .utf8)!, withPemType: "TEST TAG")
    let expected = """
    -----BEGIN TEST TAG-----
    \(body.data(using: .utf8)!.base64EncodedString())
    -----END TEST TAG-----
    """
    
    XCTAssertEqual(formatted, expected)
  }
}

extension SwiftRSATests {
  static let pri = """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA0HRZppSvYCAFTo+ie5z7EXmzFJ9rSpuUJUAAvikOq/lGVqaK
  f/HxCpbNttJSa8euBFyHjl6Y19mMaTiYoGo77iTK0gGIlD1H02b/CZwq8Dkeqtyh
  rsJiVQYaZsuDYlMtO9z4tuH4KV0sG2Z5Bdrbf3ZbsLpd3LDf8EtlRK0HBRMSOXk2
  C64BY17Uzf4RQ9dXsBnB5TN8DzBhTEA84tNOXC7eG2KZxNigpwpBOzgboWr8Sb/R
  rAXuqE7FXw8U+oXIcargQbSC1V1O8soDVa9AK0srxSvpaR+dmuGgq/hkBdBp8jQ9
  51HUWCZ2IKpUWsosAjj+uGFVO/H71REvL6RHmwIDAQABAoIBAQCs8Rq/3XNyqJ4+
  g2QmciLKaNFuNqTpDRJnpSX4nk+R1gnJMfqOE8gLJPoex3eh+9QfwjSkpU7hJZgc
  Y9wcmoaGGPg8KxGJCx5gAX9uFaZ6Dqmmz81EE/lI2PtmdUnXdXJ9y+J8uBUPHEHP
  qcCWXvDkWunPQY9F3WitD6BAzdyZE6zjezJUnQEdq213/O25qNNQD2Kd9AqMAqMY
  4o03BjO5a86uMwi1eGUkVvztKO/CJnc7H8iu2xvYvt7S1UsbA2aMM5sCe2Vtz9eM
  39CCj1eTwOSS0vXs8HCJdk4Rw0dzO+5ctscOHi5RON1qRQlBba+vdmRiWRRO+MAz
  tAPw+aHBAoGBAPqO3S1YtThvqOpP+k/qNJz1IoJVonVGOGLpZ0VloIjRiP/XYT9R
  3guq9CpYUZyursCdA775Z2YcKR+rq7Y7kX+GgNhVwChh4nB9M8PKAMC2EM++p7Ez
  AAsQZ73BFQyvxS1CWIhn6sC94bkOJXK0BCTlVf8/MZmcyI0g+AqFTYbzAoGBANT7
  YoI/52mf3M+GnDO/8c438v+KVlIsl0U9LF6EqLYP/UXR8XaVZpjXkWwWTmnNgqdH
  wWwuR3k3x78xYcKZJOelmlsiyRgFR+GLaugN24lxnBo0ZXrwIMCA/VgxErhHF93b
  z0LkrpDAj3ACyCMaqMsa0vi6RGY2e1eOKsXV37a5AoGAN+/DEweV1ZagCEd4o3Su
  8EeNv7ksfrABkJt48bZBg6n7wtornL5DKymsPvPerHMXEms7VdxKKDKrP6XMvO9J
  iUXW5/Uk5B8ONXzOHKyxRFShJi/zMg0nulCcSHGdqGppQ7RnHXTNpN//T5gH5jao
  IjCM5WIPSbMF1vQATCD8cN8CgYAT5tmxqh8Js7KCgeWewFTsHDZMwrSGQTxxb+Hx
  gxvwx1W3bILPve40YhBotTzmjhmjYAUnArwTC69Sol6sPHtCWisuUPXRlMy+urRm
  ssTM9xzLJhJFhqLI2kTSNOO27I3CYYPgkFXvmM7OfLQO87LKJ9uG+oDhvD2SVOqS
  SgX5oQKBgBq1WoNbMRtqS+lu9z/h/5trZiZ7sRnMBGCCDDdlXCCtyAXbY4iWByNP
  sVXZYZirXowKacHBqMKGefS09/YdsvkKjBGUm+aR87Lm3oTqI6Is1S7UDerE/R+C
  2bhAIUk7eWJTorZYujzXO+HmDt+8/ha+RBAtgQPDFPGHG/QaZik8
  -----END RSA PRIVATE KEY-----
  """
  
  static let pub = """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0HRZppSvYCAFTo+ie5z7
  EXmzFJ9rSpuUJUAAvikOq/lGVqaKf/HxCpbNttJSa8euBFyHjl6Y19mMaTiYoGo7
  7iTK0gGIlD1H02b/CZwq8DkeqtyhrsJiVQYaZsuDYlMtO9z4tuH4KV0sG2Z5Bdrb
  f3ZbsLpd3LDf8EtlRK0HBRMSOXk2C64BY17Uzf4RQ9dXsBnB5TN8DzBhTEA84tNO
  XC7eG2KZxNigpwpBOzgboWr8Sb/RrAXuqE7FXw8U+oXIcargQbSC1V1O8soDVa9A
  K0srxSvpaR+dmuGgq/hkBdBp8jQ951HUWCZ2IKpUWsosAjj+uGFVO/H71REvL6RH
  mwIDAQAB
  -----END PUBLIC KEY-----
  """
}
