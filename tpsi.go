package tpsi

import (
    "github.com/niclabs/tcpaillier"
    "math/big"
)

type Setting struct {
    pk *tcpaillier.PubKey
    n int // number of participants
    m int // set size
    q *big.Int // field size
    T int // threshold
}

// return sum of a slice of big.Ints
func sumSlice(sl []*big.Int, q *big.Int) *big.Int {
    sum := big.NewInt(0)
    for _, val := range sl {
        sum.Add(sum, val)
    }
    return sum.Mod(sum, q);
}

// element-wise addition of big.Int-slice
func elMulSlice(sl1, sl2 []*big.Int, q *big.Int) []*big.Int {
    slProd := make([]*big.Int, len(sl1))
    for i := range slProd {
        slProd[i] = big.NewInt(0)
        slProd[i].Mul(sl1[i], sl2[i]).Mod(slProd[i], q)
    }
    return slProd
}

// compute the Hankel Matrix for items and (random) u.
func ComputeHankelMatrix(items []int64, u *big.Int, setting Setting) BigMatrix {
    u_list := make([]*big.Int, setting.m)
    u1_list := make([]*big.Int, setting.m)
    H := NewBigMatrix(setting.T + 1, setting.T + 1, nil)
    H.Set(0, 0, big.NewInt(int64(setting.m))) //TODO: check
    for i := range u1_list {
        u1_list[i] = big.NewInt(0)
        u1_list[i].Exp(u, big.NewInt(items[i]), setting.q);
    }
    copy(u_list, u1_list)
    for i := 1; ; i += 1 { // each unique element in Hankel matrix
        var stopCol int
        var startCol int
        if i <= setting.T {
            startCol = 0
            stopCol = i + 1
        } else {
            startCol = i - setting.T
            stopCol = 3
        }
        for j := startCol; j < stopCol; j += 1 { // each matrix entry with current element
            H.Set(i-j, j, sumSlice(u_list, setting.q))
        }
        if i >= 2 * setting.T {
            break
        }
        u_list = elMulSlice(u_list, u1_list, setting.q)
    }
    return H
}

// encrypt single value
func EncryptValue(value *big.Int, setting Setting) (*big.Int, error) {
    cipherText, _, err := setting.pk.Encrypt(value)
    return cipherText, err
}

// encrypt matrix item-wise
func EncryptMatrix(a BigMatrix, setting Setting) (b BigMatrix, err error) {
    b = NewBigMatrix(a.rows, a.cols, nil)
    var c *big.Int
    for i := range a.values {
        c, err = EncryptValue(a.values[i], setting)
        if err != nil {
            return
        }
        b.values[i] = c;
    }
    return
}

// perform partial decryption for key share secret_key
func PartialDecryptValue(cipher *big.Int, secret_key *tcpaillier.KeyShare) (*tcpaillier.DecryptionShare, error) {
    return secret_key.PartialDecrypt(cipher)
}

// combine partial decryptions to receive plaintext
func CombineShares(decryptShares []*tcpaillier.DecryptionShare, setting Setting) (*big.Int, error) {
    return setting.pk.CombineShares(decryptShares...)
}