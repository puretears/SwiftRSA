
<p align="center">
<img src="https://raw.githubusercontent.com/puretears/SwiftRSA/master/banner%402x.png" alt="SwiftRSA" title="SwiftRSA" width="555"/>
</p>

<p align="center">
<a href="https://github.com/puretears/SwiftRSA">
<img src="https://travis-ci.com/puretears/SwiftRSA.svg?branch=master">
</a>
<a href="https://codecov.io/gh/puretears/SwiftRSA">
<img src="https://codecov.io/gh/puretears/SwiftRSA/branch/master/graph/badge.svg" />
</a>
<a href="https://codebeat.co/projects/github-com-puretears-swiftrsa-master">
<img alt="codebeat badge" src="https://codebeat.co/badges/66a44382-9fc6-4cc3-96e2-d145286f28a5" />
</a>
<a href="https://github.com/Carthage/Carthage/">
<img src="https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat">
</a>
</p>

SwiftRSA is a simple wrapper of Apple Security API which makes RSA encryption and decryption easy to use. It is motivated by creating the app of [boxueio.com](https://boxueio.com).

## Features

- [x] Fully tested.
- [x] Inituitive interface.
- [x] Updated to Swift 5.

## SwiftRSA 101

### Create a public / private key

#### With a PEM encoded string

```swift
let pemPrivate = """
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEA0HRZppSvYCAFTo+ie5z7EXmzFJ9rSpuUJUAAvikOq/lGVqaK
  ...
  2bhAIUk7eWJTorZYujzXO+HmDt+8/ha+RBAtgQPDFPGHG/QaZik8
  -----END RSA PRIVATE KEY-----
  """
let pemPublic = """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0HRZppSvYCAFTo+ie5z7
  ...
  mwIDAQAB
  -----END PUBLIC KEY-----
  """

guard let privateKey = PrivateKey(pemEncoded: pem) else {
  // Invalid pem string
}

guard let publicKey = PublicKey(pemEncoded: pemPublic) else {
  // Invalid pem string
}
```

#### With a DER encoded string

```swift
guard let privateKey = PrivateKey(der: data) else {
  // Invalid DER data
}

guard let publicKey = PublicKey(der: data) else {
  // Invalid DER data
}
```

### Encrypt with a public key

```swift
let ct = ClearText(string: "Hello world")
let encrypted = try ct.encrypted(with: publicKey, by: .rsaEncryptionOAEPSHA512)
/// `encrypted` is an `EncryptedText` object.
```

### Decrypt with a private key

```swift
/// `originText` is a `ClearText` object
let originText = try encrypted.decrypted(with: privateKey)
```

### Get data from an `EncryptedText` object

```swift
let data = encrypted.data
```

### Get string from a `ClearText` object

```swift
let string = originText.stringValue
```

## Installation

To integrate SwiftRSA into your Xcode project using [Carthage](https://github.com/Carthage/Carthage), speicify the following line in your `Cartfile`:

```shell
github "puretears/SwiftRSA" ~> 0.1
```

## Requirements

- iOS 10.0+
- Swift 4.0+

## Next Steps

- Cocoapods and SPM support;
- More RSA algorithm support;
- Add X.509 certificate support;
- Add sign and verify support;

## Release History

- 0.1
  * Initial release

## License

SwiftRSA is released under the MIT license. See LICENSE for details.
