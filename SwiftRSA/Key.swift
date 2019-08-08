//
//  Key.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/29.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation
import Security

public protocol Key: class {
  var key: SecKey { get }
  
  init(key: SecKey)
  init?(der data: Data)
  init?(pemEncoded pemString: String)
  init?(base64Encoded base64String: String)
  
  func data() throws -> Data
  func pemString() throws -> String
  func base64String() throws -> String
}

public extension Key {
  /// Create a key from base64 encoded key.
  ///
  /// - parameter base64Encoded
  /// - throws: `SwiftRSAError.invalidBase64String` if the `base64Encoded` cannot be base64 decoded.
  init?(base64Encoded base64String: String) {
    guard let decoded = Data(base64Encoded: base64String, options: [.ignoreUnknownCharacters]) else {
      return nil
    }
    
    self.init(der: decoded)
  }
  
  /// Create a key from a PEM formatted string.
  ///
  /// - parameter pemEncoded a PEM formatted string.
  /// - throws:
  ///   - `SwiftRSAError.invalidBase64String` if the `base64Encoded` cannot be base64 decoded.
  ///   - `SwiftRSAError.emptyPEMKey` if there is nothing between the `BEGIN` and `END` tags.
  init?(pemEncoded pemString: String) {
    do {
      let base64Decoded = try SwiftRSA.base64String(pemEncoded: pemString)
      self.init(base64Encoded: base64Decoded)
    }
    catch {
      return nil
    }
  }
  
  func data() throws -> Data {
    return try SwiftRSA.data(forKey: key)
  }
  
  func base64String() throws -> String {
    return try data().base64EncodedString()
  }
}
