# ByteArk SDK for GO
[![Build Status](https://travis-ci.org/byteark/byteark-sdk-go.svg?branch=master)](https://travis-ci.org/byteark/byteark-sdk-go)
## Table of contents
* [Installation](#Installation)
* [Usage](#Usage)
* [APIs](#APIs)
    * [CreateSigner](#CreateSigner)
    * [Sign](#Sign)
    * [Verify](#Verify)
* [Type](#Type)
    * [SignerOptions](#SignerOptions)
    * [SignOptions](#SignOptions)

## Installation
    go get github.com/byteark/byteark-sdk-go

## Usage

Now the only feature availabled is creating signed URL with ByteArk Signature Version 2.

First, import ByteArk's SDK in your code and call ```CreateSigner()``` to create Signer.

``` GO
import (
    bytearkSignedURL "github.com/byteark/byteark-sdk-go"
)
```
The ```CreateSigner()``` required one parameter ```SignerOptions```, which you can use provided ```SignerOptions``` via SDK.

```GO
signerOptions :=  bytearkSignedURL.SignerOptions{
    AccessID:     "2Aj6Wkge4hi1ZYLp0DBG",
    AccessSecret: "31sX5C0lcBiWuGPTzRszYvjxzzI3aCZjJi85ZyB7",
}

bytearkSignedURL.CreateSigner(signerOptions)
```

After create Signer you can call Sign function via SDK. ```Sign()``` function also consume 3 parameters, url, expires and signOptions. ```SignOptions``` is also provided by the SDK. ```Sign()``` return signedURL and error.
```GO
signOptions := bytearkSignedURL.SignOptions{
    "path_prefix": "/live/",
}

signedURL, err := bytearkSignedURL.Sign(
    "https://example.cdn.byteark.com/path/to/file.png",
    1514764800,
    signOptions,
)
```

[example](https://github.com/byteark/byteark-sdk-go/blob/master/examples/main.go)

## APIs
### CreateSigner
```GO
func CreateSigner(options SignerOptions) error
```
Create and update initial value of signer in sigleton pattern.
### Sign
```GO
func Sign(url string, expires int, options SignOptions) (string, error)
```
Sign input url with expire date and option.
### Verify
```GO
func Verify(url string, now int) (bool, error)
```
Verfiy signedURL that already sign by sign function.

## Type
### SignerOptions
```GO
type SignerOptions struct {
    AccessID        string
    AccessSecret    string
    DefaultAge      int
    SkipURLEncoding bool
}
```
### SignOptions
```GO
type SignOptions map[string]string
```
