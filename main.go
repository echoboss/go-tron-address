package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/sasaxie/go-client-api/common/base58"
	"golang.org/x/crypto/sha3"
	"math/big"
)

/*
	Tron Address Algorithm
	https://developers.tron.network/docs/account
*/

func main() {
	// Use the ECDSA crypto library to generate the Tron Address
	generateNewKey()

	// Using a hex of a private key extract the Tron Address
	addressFromKey("F43EBCC94E6C257EDBE559183D1A8778B2D5A08040902C0F0A77A3343A1D0EA5") // TWVRXXN5tsggjUCDmqbJ4KxPdJKQiynaG6
	addressFromKey("a24c37ec71cfc4046f617b5011f932c994c863e20ad3b8a20b21a4de943279dd") // TXA74MA1z4669rLBKmJB16AvHxppTLJCdT
	addressFromKey("e36ace9ad7486f6149790e2a95a2a53fe57454b7a083093a0049457baebbabcf") // TKfSBdtyTikWF5XCRdxqNktif3UShzS4ke
}

func generateNewKey() {
	fmt.Println("******************* New Key Using ECDSA *******************")
	// Generate a new key using the ECDSA library
	// #1
	key, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	priv := key.D.Bytes()
	pubX := key.X.Bytes()
	pubY := key.Y.Bytes()
	pub := append(pubX,pubY...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr := base58.Encode(rawAddr)

	fmt.Println("Private key: (" + fmt.Sprintf("%d", len(priv)) + ") " + fmt.Sprintf("%x", priv))
	fmt.Println("tronAddr: (" + fmt.Sprintf("%d", len(tronAddr)) + ") " + tronAddr)

	fmt.Println("******************* New Key Using ECDSA *******************")
}

func addressFromKey(keyStr string) {
	fmt.Println("******************* Get Address from Key *******************")

	// Build the Private Key and extract the Public Key
	keyBytes, _ := hex.DecodeString(keyStr)
	key := new(ecdsa.PrivateKey)
	key.PublicKey.Curve = btcec.S256()
	key.D = new(big.Int).SetBytes(keyBytes)
	key.PublicKey.X, key.PublicKey.Y = key.PublicKey.Curve.ScalarBaseMult(keyBytes)

	// #1
	pub := append(key.X.Bytes(), key.Y.Bytes()...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr := base58.Encode(rawAddr)

	fmt.Println("Private key: (" + fmt.Sprintf("%d", len(keyBytes)) + ") " + fmt.Sprintf("%x", keyBytes))
	fmt.Println("tronAddr: (" + fmt.Sprintf("%d", len(tronAddr)) + ") " + tronAddr)

	fmt.Println("******************* Get Address from Key *******************")
}
