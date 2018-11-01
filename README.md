# httpsign

[![Build Status](https://travis-ci.org/gin-contrib/httpsign.svg)](https://travis-ci.org/gin-contrib/httpsign)
[![codecov](https://codecov.io/gh/gin-contrib/httpsign/branch/master/graph/badge.svg)](https://codecov.io/gh/gin-contrib/httpsign)
[![Go Report Card](https://goreportcard.com/badge/github.com/gin-contrib/httpsign)](https://goreportcard.com/report/github.com/gin-contrib/httpsign)
[![GoDoc](https://godoc.org/github.com/gin-contrib/httpsign?status.svg)](https://godoc.org/github.com/gin-contrib/httpsign)
[![Join the chat at https://gitter.im/gin-gonic/gin](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/gin-gonic/gin)

Signing HTTP Messages Middleware base on [HTTP Signatures](https://tools.ietf.org/html/draft-cavage-http-signatures).

## Example
``` go

package main

import (
	"github.com/gin-contrib/httpsign"
	"github.com/gin-contrib/httpsign/crypto"
	"github.com/gin-gonic/gin"
)

func main() {
	// Define algorithm
	hmacsha256 := &crypto.HmacSha256{}
	hmacsha512 := &crypto.HmacSha512{}
	// Init define secret params
	readKeyID := httpsignatures.KeyID("read")
	writeKeyID := httpsignatures.KeyID("write")
	secrets := httpsignatures.Secrets{
		readKeyID: &httpsignatures.Secret{
			Key:       "HMACSHA256-SecretKey",
			Algorithm: hmacsha256, // You could using other algo with interface Crypto
		},
		writeKeyID: &httpsignatures.Secret{
			Key:       "HMACSHA512-SecretKey",
			Algorithm: hmacsha512,
		},
	}

	// Init server
	r := gin.Default()

	//Create middleware with default rule. Could modify by parse Option func
	auth := httpsignatures.NewAuthenticator(secrets)

	r.Use(auth.Authenticated())
	r.GET("/a", a)
	r.POST("/b", b)
	r.POST("/c", c)

	r.Run(":8080")
}

```
