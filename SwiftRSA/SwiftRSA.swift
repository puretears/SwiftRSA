//
//  SwiftRSA.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/29.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation

/// `SwiftRSA` is just a namespace holding these static methods that are used in other types.
public class SwiftRSA {
  /// Extract base64 encoded key from a PEM formatted string.
  ///
  /// - parameter pemEncoded: PEM formatted string
  /// - returns: Base64 encoded key between `-----BEGIN` and `-----END`
  /// - throws: `SwiftRSAError.emptyPEMKey` if there is nothing between the `BEGIN` and `END` tags.
  static func base64String(pemEncoded pemString: String) throws -> String {
    let lines = pemString.components(separatedBy: "\n").filter { line in
      return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
    }
    
    guard lines.count != 0 else {
      throw SwiftRSAError.emptyPEMKey
    }
    
    return lines.joined(separator: "")
  }
  
  /// Create a key from a DER formatted data.
  ///
  /// - parameter derData: DER formatted data
  /// - parameter isPublic: `true` for public key, `false` for private key
  /// - returns: A `SecKey` object representing the key
  /// - throws: `SwiftRSAError.addKeyFailed(error:)` if creation failed.
  static func createKey(_ derData: Data, isPublic: Bool) throws -> SecKey {
    let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
    let sizeInBits = derData.count * 8
    let queryDict: [CFString: Any] = [
      kSecAttrKeyClass: keyClass,
      kSecAttrKeySizeInBits: sizeInBits,
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
    ]
    
    var error: Unmanaged<CFError>?
    
    guard let key = SecKeyCreateWithData(derData as CFData, queryDict as CFDictionary, &error) else {
      throw SwiftRSAError.addKeyFailed(error: error?.takeRetainedValue())
    }
    
    return key
  }
  
  /// Get data contained within a `SecKey` object.
  ///
  /// - parameter `forKey`: The key to be unwrapped.
  /// - returns: The unwrapped `Data` within a key.
  /// - throws: `SwiftRSAError.externalRepresentationFailed` if failed.
  static func data(forKey reference: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    let data = SecKeyCopyExternalRepresentation(reference, &error)
    
    guard let unwrapped = data as Data? else {
      throw SwiftRSAError.externalRepresentationFailed(error: error?.takeRetainedValue())
    }
    
    return unwrapped
  }
  
  /// Convert a DER formatted data to PEM.
  ///
  /// - parameter `derData`: DER formatted data.
  /// - parameter withPemType`: Text in the BEGIN and END tag.
  /// - returns: The PEM formatted key.
  static func format(der data: Data, withPemType pemType: String) -> String {
    func split(_ str: String, chunkOfLength: Int) -> [String] {
      return stride(from: 0, to: str.count, by: chunkOfLength).map { index -> String in
        let startIndex = str.index(str.startIndex, offsetBy: index)
        let endIndex = str.index(
          startIndex, offsetBy: chunkOfLength, limitedBy: str.endIndex) ?? str.endIndex
        
        return String(str[startIndex..<endIndex])
      }
    }
    
    let chunks = split(data.base64EncodedString(), chunkOfLength: 64)
    let pem = [
        "-----BEGIN \(pemType)-----",
        chunks.joined(separator: "\n"),
        "-----END \(pemType)-----"
    ]
    
    return pem.joined(separator: "\n")
  }
}
