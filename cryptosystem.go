package tpsi

import (
    "math/big"
    gm "github.com/ontanj/generic-matrix"
)

type AHE_Cryptosystem interface {

    // addition of two elements
    Add(Ciphertext, Ciphertext) (sum Ciphertext, err error)

    // scaling of an element by scalar factor
    Scale(cipher Ciphertext, factor *big.Int) (product Ciphertext, err error)
    
    // encrypt a plaintext message
    Encrypt(*big.Int) (Ciphertext, error)

    // encrypt with a given randomizer
    EncryptFixed(plaintext *big.Int, randomizer *big.Int) (Ciphertext, error)

    // combine partial decryptions to plaintext
    CombinePartials([]Partial_decryption) (*big.Int, error)

    // encrypted matrix evaluation
    EvaluationSpace() gm.Space

    // size of plaintext space
    N() *big.Int
}

type FHE_Cryptosystem interface {
    AHE_Cryptosystem

    // multiplication of two elements
    Multiply(Ciphertext, Ciphertext) (Ciphertext, error)
}

type Secret_key interface {
    PartialDecrypt(Ciphertext) (Partial_decryption, error)
}

type Partial_decryption interface {}

type Ciphertext interface {}