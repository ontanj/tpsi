package tpsi

import (
    "testing"
    "math/big"
    "github.com/niclabs/tcpaillier"
    "fmt"
    "errors"
)

func TestHankelMatrix(t *testing.T) {
    var setting Setting
    items := []int64{2, 3, 5}
    setting.m = 3
    setting.T = 2
    setting.q = big.NewInt(11)
    u := big.NewInt(6)
    H := ComputeHankelMatrix(items, u, setting)
    H_corr := NewBigMatrix(3, 3, sliceToBigInt([]int64{3,9,4,9,4,6,4,6,8}))
    t.Run("check dimensions", func(t *testing.T){
        if H.rows != setting.T + 1 || H.cols != setting.T + 1 {
            t.Error("wrong dimensions")
        }
    })
    t.Run("check elements", func(t *testing.T){
        for i := 0; i < 3; i += 1 {
            for j := 0; j < 3; j += 1 {
                if H.At(i,j).Cmp(H_corr.At(i,j)) != 0 {
                    t.Error("incorrect values")
                }
            }
        }
    })
}

func TestEncryptValue(t *testing.T) {
    sks, pk, error := GenerateKeys(512, 1, 4)
    if error != nil {
        t.Errorf("%v", error)
        return
    }
    var setting Setting
    setting.pk = pk
    plaintext := big.NewInt(32)
    ciphertext, err := EncryptValue(plaintext, setting)
    if err != nil {
        t.Errorf("%v", err)
    }
    decryptShares := make([]*tcpaillier.DecryptionShare, 4)
    for i, sk := range sks {
        dks, err := PartialDecryptValue(ciphertext, sk)
        if err != nil {
            t.Errorf("%v", err)
        }
        decryptShares[i] = dks
    }
    dec_plaintext, err := CombineShares(decryptShares, setting)
    if err != nil {
        t.Errorf("%v", err)
    }
    if plaintext.Cmp(dec_plaintext) != 0 {
        t.Error("decrypted value does not match plaintext")
    }
    if plaintext.Cmp(ciphertext) == 0 {
        t.Error("plaintext didn't encrypt")
    }
}

func TestEncryptMatrix(t *testing.T) {
    var setting Setting
    sks, pk, err := GenerateKeys(512, 1, 4)
    setting.pk = pk
    if err != nil {
        t.Errorf("%v", err)
        return
    }
    vals := []int64{1,2,3,4,5,6,7,8,9}
    a := NewBigMatrix(3, 3, sliceToBigInt(vals))
    a, err = EncryptMatrix(a, setting)
    if err != nil {
        t.Errorf("%v", err)
    }
    b := NewBigMatrix(3, 3, sliceToBigInt([]int64{1,2,3,4,5,6,7,8,9}))
    
    err = CompareEnc(a, b, sks, setting)
    if err != nil {
        t.Errorf("%v", err)
    }
}

// checks if encrypted matrix a is equal to unencrypted matrix b, returns error otherwise
func CompareEnc(a, b BigMatrix, sks []*tcpaillier.KeyShare, setting Setting) error {
    for i := 0; i < a.rows; i += 1 {
        for j := 0; j < a.cols; j += 1 {
            decryptShares := make([]*tcpaillier.DecryptionShare, len(sks))
            for k, sk := range sks {
                dks, err := PartialDecryptValue(a.At(i, j), sk)
                if err != nil {
                    return err
                }
                decryptShares[k] = dks
            }
            dec_plaintext, err := CombineShares(decryptShares, setting)
            if err != nil {
                return err
            }
            if dec_plaintext.Cmp(b.At(i,j)) != 0 {
                return errors.New(fmt.Sprintf("decrypted values is wrong for (%d, %d)", i, j))
            }
        }
    }
    return nil
}