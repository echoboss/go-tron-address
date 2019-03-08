package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sasaxie/go-client-api/common/base58"
	"golang.org/x/crypto/sha3"
)


func main() {
	// https://developers.tron.network/docs/account

	// #1
	key, _ := crypto.GenerateKey()
	priv := key.D.Bytes()
	pubX := key.X.Bytes()
	pubY := key.Y.Bytes()
	pub := append(pubX,pubY...)

	// #2
	hash := sha3.NewLegacyKeccak256() // the missing piece
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum:=hash2562[:4]

	// #5/#6
	naddr := append(addr41, checksum...)
	tronAddr := base58.Encode(naddr)

	fmt.Println("Public key X: (" + fmt.Sprintf("%d", len(pubX)) + ") " + fmt.Sprintf("%x", pubX))
	fmt.Println("Public key Y: (" + fmt.Sprintf("%d", len(pubY)) + ") " + fmt.Sprintf("%x", pubY))
	fmt.Println("Public key xored: (" + fmt.Sprintf("%d", len(pub)) + ") " + fmt.Sprintf("%x", pub))
	fmt.Println("Private key: (" + fmt.Sprintf("%d", len(priv)) + ") " + fmt.Sprintf("%x", priv))
	fmt.Println("hashed: (" + fmt.Sprintf("%d", len(hashed)) + ") " + fmt.Sprintf("%x", hashed))
	fmt.Println("address: (" + fmt.Sprintf("%d", len(last20)) + ") " + fmt.Sprintf("%x", last20))
	fmt.Println("addr41: (" + fmt.Sprintf("%d", len(addr41)) + ") " + fmt.Sprintf("%x", addr41))
	fmt.Println("h2562: (" + fmt.Sprintf("%d", len(hash2562)) + ") " + fmt.Sprintf("%x", hash2562))
	fmt.Println("checksum: (" + fmt.Sprintf("%d", len(naddr)) + ") " + fmt.Sprintf("%x", naddr))
	fmt.Println("b58: (" + fmt.Sprintf("%d", len(tronAddr)) + ") " + tronAddr)
}
