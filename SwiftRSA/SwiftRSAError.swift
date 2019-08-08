//
//  SwiftRSAError.swift
//  SwiftRSA
//
//  Created by Mars on 2019/7/29.
//  Copyright © 2019 Mars. All rights reserved.
//

import Foundation

public enum SwiftRSAError: Error {
  case emptyPEMKey
  case invalidBase64String
  case algorithmIsNotSupported
  case clearTextTooLong
  case addKeyFailed(error: CFError?)
  case encryptionFailed(error: CFError?)
  case decryptionFailed(error: CFError?)
  case externalRepresentationFailed(error: CFError?)
}
