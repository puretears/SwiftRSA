//
//  ClearText.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/30.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation

public class ClearText {
  // Data to be encrypted
  public let data: Data
  public var stringValue: String {
    return String(data: data, encoding: .utf8)!
  }
  
  public required init(data: Data) {
    self.data = data
  }
  
  public required init(string: String) {
    self.data = string.data(using: .utf8)!
  }
  
  /// Encrypt the clear text.
  ///
  /// - parameter `with`: Public key used for encryption.
  /// - parameter `by`: The RSA algorithm
  /// - Returns: The encrypted data.
  /// - Throws:
  ///   - `SwiftRSAError.clearTextTooLong` if the clear text is too long.
  ///   - `SwiftRSAError.encryptionFailed` if the encryption is failed.
  public func encrypted(with key: PublicKey, by algorithm: SecKeyAlgorithm) throws -> EncryptedText {
    /// 1. Is the `algorithm` supported by the platform
    guard SecKeyIsAlgorithmSupported(key.key, .encrypt, algorithm) else {
      throw SwiftRSAError.algorithmIsNotSupported
    }
    
    /// 2. Is the data short enough to be encrypted
    let maxCount = try ClearText.maxClearTextInLength(key.key, algorithm: algorithm)
    guard data.count <= maxCount else {
      throw SwiftRSAError.clearTextTooLong
    }
    
    /// 3. Make the encryption
    var error: Unmanaged<CFError>?
    guard let encrypted = SecKeyCreateEncryptedData(key.key, algorithm, data as CFData, &error) else {
      throw SwiftRSAError.encryptionFailed(error: error?.takeRetainedValue())
    }
    
    return EncryptedText(data: encrypted as Data, by: algorithm)
  }
  
  /// Get the overhead of each RSA algorithm in bytes in decimal.
  ///
  /// - parameter `of`: RSA algorithm
  /// - returns: The overhead in bytes in decimal
  /// - Throws: `SwiftRSAError.algorithmIsNotSupported` if the algorithm is not supported.
  /// - ToDo: Add PKCS v1.5 and no padding support
  static func _overhead(of algorithm: SecKeyAlgorithm) throws -> Int {
    func fomulaOfOaep(_ lengthInBits: Int) -> Int {
      return 2 * (lengthInBits / 8) + 2
    }
    
    switch algorithm {
    case .rsaEncryptionOAEPSHA1:
      return fomulaOfOaep(160)
    case .rsaEncryptionOAEPSHA224:
      return fomulaOfOaep(224)
    case .rsaEncryptionOAEPSHA256:
      return fomulaOfOaep(256)
    case .rsaEncryptionOAEPSHA384:
      return fomulaOfOaep(384)
    case .rsaEncryptionOAEPSHA512:
      return fomulaOfOaep(512)
    default:
      throw SwiftRSAError.algorithmIsNotSupported
    }
  }
  
  public static func maxClearTextInLength(_ key: SecKey, algorithm: SecKeyAlgorithm) throws -> Int {
    let keyLength = SecKeyGetBlockSize(key)
    let overhead = try ClearText._overhead(of: algorithm)
    
    return keyLength - overhead
  }
}
