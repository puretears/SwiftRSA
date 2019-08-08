//
//  EncryptedText.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/31.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation

public class EncryptedText {
  // Data to be encrypted
  public let data: Data
  private let algo: SecKeyAlgorithm
  
  public required init(data: Data, by algo: SecKeyAlgorithm) {
    self.data = data
    self.algo = algo
  }
  
  public func decrypted(with key: PrivateKey) throws -> ClearText {
    var error: Unmanaged<CFError>?
    guard let encrypted = SecKeyCreateDecryptedData(key.key, algo, data as CFData, &error) else {
      throw SwiftRSAError.decryptionFailed(error: error?.takeRetainedValue())
    }
    
    return ClearText(data: encrypted as Data)
  }
}

