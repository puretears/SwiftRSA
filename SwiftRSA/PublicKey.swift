//
//  PublicKey.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/30.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation

public class PublicKey: Key {
  public let key: SecKey
  
  required public init(key: SecKey) {
    self.key = key
  }
  
  /// Initializer of `PublicKey`
  ///
  /// - parameter derData: DER formatted key data.
  /// - throws: `SwiftRSAError.addKeyFailed(error:)` if creation failed.
  /// - ToDo: We should get rid of the X.509 header if the key is a certificate.
  required public init?(der data: Data) {
    do {
      self.key = try SwiftRSA.createKey(data, isPublic: true)
    }
    catch {
      return nil
    }
  }
  
  public func pemString() throws -> String {
    let data = try self.data()
    return SwiftRSA.format(der: data, withPemType: "RSA PUBLIC KEY")
  }
}
