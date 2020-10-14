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

type PartialMatrix struct {
    values []*tcpaillier.DecryptionShare
    rows, cols int
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

// perform partial decryption for key share secret_key
func PartialDecryptMatrix(cipher BigMatrix, secret_key *tcpaillier.KeyShare) (part_mat PartialMatrix, err error) {
    dec_vals := make([]*tcpaillier.DecryptionShare, len(cipher.values))
    var part_val *tcpaillier.DecryptionShare
    for i, enc_val := range cipher.values {
        part_val, err = PartialDecryptValue(enc_val, secret_key)
        if err != nil {
            return
        }
        dec_vals[i] = part_val
    }
    part_mat = PartialMatrix{values: dec_vals, rows: cipher.rows, cols: cipher.cols}
    return
}

// combine partial decryptions to receive plaintext
func CombineShares(decryptShares []*tcpaillier.DecryptionShare, setting Setting) (*big.Int, error) {
    return setting.pk.CombineShares(decryptShares...)
}

// combine partial matrix decryptions to receive plaintext matrix
func CombineMatrixShares(part_mat []PartialMatrix, setting Setting) (decrypted BigMatrix, err error) {
    dec_mat_vals := make([]*big.Int, len(part_mat[0].values))
    var dec *big.Int
    for i := range part_mat[0].values {
        el_vals := make([]*tcpaillier.DecryptionShare, len(part_mat))
        for j := range part_mat {
            el_vals[j] = part_mat[j].values[i]
        }
        dec, err = CombineShares(el_vals, setting)
        if err != nil {
            return
        }
        dec_mat_vals[i] = dec
    }
    decrypted = NewBigMatrix(part_mat[0].rows, part_mat[0].cols, dec_mat_vals)
    return
}

// sample a matrix with size rows x cols, with elements from field defined by q
func SampleMatrix(rows, cols int, q *big.Int) (a BigMatrix, err error) {
    vals := make([]*big.Int, rows*cols)
    var r *big.Int
    for i := range vals {
        r, err = SampleIntFromField(q)
        if err != nil {
            return
        }
        vals[i] = r
    }
    a = NewBigMatrix(rows, cols, vals)
    return
}

//step 1 of MMult
func SampleRMatrices(setting Setting) (RAi, RBi BigMatrix, err error) {
    RAi, err = SampleMatrix(setting.T+1, setting.T+1, setting.q)
    if err != nil {
        return
    }
    RBi, err = SampleMatrix(setting.T+1, setting.T+1, setting.q)    
    if err != nil {
        return
    }
    return
}

// step 3 of MMult
func GetCti(MA, MB, RA, RAi, RBi BigMatrix, setting Setting, secret_key *tcpaillier.KeyShare) (cti BigMatrix, MA_part, MB_part PartialMatrix, err error) {
    prod1, err := MatEncRightMul(RA, RBi, setting.pk)
    if err != nil {
        return
    }
    prod2, err := MatEncRightMul(MA, RBi, setting.pk)
    if err != nil {
        return
    }
    prod3, err := MatEncLeftMul(RAi, MB, setting.pk)
    if err != nil {
        return
    }
    sum2, err := MatEncAdd(prod2, prod3, setting.pk) //avoid extra calculation
    if err != nil {
        return
    }
    cti, err = MatEncSub(prod1, sum2, setting.pk)
    MA_part, err = PartialDecryptMatrix(MA, secret_key)
    MB_part, err = PartialDecryptMatrix(MB, secret_key)
    return
}