
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
- [x] Simple interface.
- [x] Inituitive interface.
- [x] Updated to Swift 5.

### SwiftRSA 101

The simplest use case is using the `default` singleton. Then save and load data as the way of manipulating `UserDefaults`.

Add values to keychain. All these `set` methods return `Bool` to indicate if the data was saved successfully. If the key already exists, the data will be overritten.

```swift
/// Save data
SwiftRSA.default.set(1, forKey: "key.int.value")
SwiftRSA.default.set([1, 2, 3], forKey: "key.array.value")
SwiftRSA.default.set("string value", forKey: "key.string.value")
```

Retrieve values from keychain. All kinds of getter methods return `T?`, if the data corresponding to `forKey` cannot decoded back to `T`, it returns `nil`.

```swift
/// Load data
SwiftRSA.default.object(of: Int.self, forKey: "key.int.value")
SwiftRSA.default.object(of: Array.self, forKey: "key.array.value")
SwiftRSA.default.string(forKey: "key.string.value")
```

Remove data from keychain. Return `Bool` indicating if the delete was successful.

```swift
SwiftRSA.default.removeObject(forKey: "key.to.be.deleted")
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
- Add X.509 certification support;
- Add sign and verify support;

## Release History

- 0.1
  * Initial release

## License

SwiftRSA is released under the MIT license. See LICENSE for details.
