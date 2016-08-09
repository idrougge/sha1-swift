# sha1-swift

##What?##
An SHA-1 hash implementation in Swift

##Usage##
1. Include SHA1.swift in your project
2. Call a public method:
  ```swift
  let hash:String = SHA1.hexStringFromFile(filename)
  ```
  returns `Optional("84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1")`
  
  
  ```swift
  let hash:[Int] = SHA1.hashFromFile(filename)
  ```
  returns `Optional([2845392438, 1191608682, 3124634993, 2018558572, 2630932637])`
  
  ```swift
  let hash = SHA1.hexStringFromString("abc")
  ```
  returns `Optional("A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D")`
  
  ```swift
  let hash = SHA1.hexStringFromData(data)
  ```
  returns `Optional("A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D")`
  
##Implementation details##
* Implemented as a struct with static methods in order to avoid garbage like 
```swift
let my_sha1_calculator=SHA1()
my_sha1_calculator.hashFromFile(myfile)
```

##Resources##
* Pseudocode on Wikipedia: https://en.wikipedia.org/wiki/SHA-1#Examples_and_pseudocode
* Debug help and inspiration from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA1.pdf
* Further inspiration from https://tools.ietf.org/html/rfc3174

##Check out as well##
* sha1-rexx, an SHA-1 implementation in REXX: https://github.com/idrougge/sha1-rexx