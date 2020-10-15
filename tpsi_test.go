package tpsi

import (
    "testing"
    "math/big"
    "github.com/niclabs/tcpaillier"
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
    
    CompareEnc(a, b, sks, setting, t)
}

func TestDecryptMatrix(t *testing.T) {
    var setting Setting
    sks, pk, err := GenerateKeys(512, 1, 4)
    setting.pk = pk
    if err != nil {
        t.Errorf("%v", err)
        return
    }
    vals := []int64{1,2,3,4,5,6,7,8,9}
    a := NewBigMatrix(3, 3, sliceToBigInt(vals))
    enc, _ := EncryptMatrix(a, setting)
    partial_decrypts := make([]PartialMatrix, len(sks))
    for i, sk := range sks {
        pd, err := PartialDecryptMatrix(enc, sk)
        if err != nil {
            t.Error(err)
        }
        partial_decrypts[i] = pd
    }
    decrypted, err := CombineMatrixShares(partial_decrypts, setting)
    if err != nil {
        return
    }
    for i := 0; i < 3; i += 1 {
        for j := 0; j < 3; j += 1 {
            if decrypted.At(i, j).Cmp(a.At(i, j)) != 0 {
                t.Error("values differ")
            }
        }
    }

}

// checks if encrypted matrix a is equal to unencrypted matrix b, returns error otherwise
func CompareEnc(enc, plain BigMatrix, sks []*tcpaillier.KeyShare, setting Setting, t *testing.T) {
    for i := 0; i < enc.rows; i += 1 {
        for j := 0; j < enc.cols; j += 1 {
            decryptShares := make([]*tcpaillier.DecryptionShare, len(sks))
            for k, sk := range sks {
                dks, err := PartialDecryptValue(enc.At(i, j), sk)
                if err != nil {
                    t.Error(err)
                }
                decryptShares[k] = dks
            }
            dec_plaintext, err := CombineShares(decryptShares, setting)
            if err != nil {
                t.Error(err)
            }
            if dec_plaintext.Cmp(plain.At(i,j)) != 0 {
                t.Errorf("decrypted values is wrong for (%d, %d)", i, j)
            }
        }
    }
}

func TestMMult(t *testing.T) {
    A := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
    B := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 1, 2, 1, 2, 1, 2, 1}))
    AB_corr := MatMul(A, B)
    var setting Setting
    setting.n = 4
    setting.T = 2
    sks, pk, _ := GenerateKeys(512, 1, setting.n)
    setting.pk = pk
    q, err := SamplePrime()
    setting.q = q
    A, _ = EncryptMatrix(A, setting)
    B, _ = EncryptMatrix(B, setting)

    // step1
    RAs_clear := make([]BigMatrix, setting.n)
    RBs_clear := make([]BigMatrix, setting.n)
    RAs_crypt := make([]BigMatrix, setting.n)
    RBs_crypt := make([]BigMatrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        RAi, RBi, err := SampleRMatrices(setting)
        if err != nil {t.Error(err)}
        RAs_clear[i] = RAi
        RBs_clear[i] = RBi
        RAi_crypt, _ := EncryptMatrix(RAi, setting)
        RAs_crypt[i] = RAi_crypt
        RBi_crypt, _ := EncryptMatrix(RBi, setting)
        RBs_crypt[i] = RBi_crypt
    }

    // step 2
    RA, MA, MB, err := GetMulMatrices(A, B, RAs_crypt, RBs_crypt, setting)
    if err != nil {t.Error(err)}

    // step 3
    cts := make([]BigMatrix, setting.n)
    MA_parts := make([]PartialMatrix, setting.n)
    MB_parts := make([]PartialMatrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAs_clear[i], RBs_clear[i], setting, sks[i])
        if err != nil {t.Error(err)}
        cts[i] = cti
        MA_parts[i] = MA_part
        MB_parts[i] = MB_part
    }

    // step 4
    AB, err := CombineMatrixMultiplication(MA_parts, MB_parts, cts, setting)
    CompareEnc(AB, AB_corr, sks, setting, t)
}