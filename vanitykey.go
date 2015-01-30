package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"bytes"
	"regexp"
	"github.com/btcsuite/btcec"
	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcutil"
	//"github.com/CryptoCurrencyCafe/project1"
)


func generateKeyPair() (*btcec.PublicKey, *btcec.PrivateKey) {

	// Generate a private key, use the curve secpc256k1 and kill the program on
	// any errors
	priv, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		// There was an error. Log it and bail out
		log.Fatal(err)
	}

	return priv.PubKey(), priv
}


func generateAddr(pub *btcec.PublicKey) *btcutil.AddressPubKeyHash {

	net := &btcnet.MainNetParams

	// Serialize the public key into bytes and then run ripemd160(sha256(b)) on it
	b := btcutil.Hash160(pub.SerializeCompressed())

	// Convert the hashed public key into the btcsuite type so that the library
	// will handle the base58 encoding when we call addr.String()
	addr, err := btcutil.NewAddressPubKeyHash(b, net)
	if err != nil {
		log.Fatal(err)
	}

	return addr
}


func generateVanityAddress(pattern string) (*btcec.PublicKey, *btcec.PrivateKey, *btcutil.AddressPubKeyHash){
  
  //generate and store a keypair
  pub, priv := generateKeyPair()
  
  //generate and store the corresponding addres
  addr := generateAddr(pub)
  
  //check if address string contains pattern, store answer in boolean variable
  match, _ := regexp.MatchString((".*" + pattern + ".*"), addr.String())
  
  //match found, return everything
  if match {
    //true printout
    fmt.Printf(match)
    return pub, priv, addr
  }
  
    //false printout
  fmt.Printf(match)
  
  //match not found, run again
  return generateVanityAddress(pattern)


}

func main() {

  pub, priv, addr := generateVanityAddress("xy")

  fmt.Printf("This is a private key in hex:\t[%s]\n",
		hex.EncodeToString(priv.Serialize()))

	fmt.Printf("This is a public key in hex:\t[%s]\n",
		hex.EncodeToString(pub.SerializeCompressed()))

  fmt.Printf("This is the associated Bitcoin address:\t[%s]\n", addr.String())

}
