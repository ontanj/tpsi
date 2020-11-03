package tpsi

import (
    "github.com/niclabs/tcpaillier"
    "math/big"
    "math"
)

type Setting struct {
    pk *tcpaillier.PubKey
    n int // number of participants
    m int // set size
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

// element-wise multiplication of big.Int-slice
func elMulSlice(sl1, sl2 []*big.Int, q *big.Int) []*big.Int {
    slProd := make([]*big.Int, len(sl1))
    for i := range slProd {
        slProd[i] = big.NewInt(0)
        slProd[i].Mul(sl1[i], sl2[i]).Mod(slProd[i], q)
    }
    return slProd
}

// compute the Hankel Matrix for items and (random) u.
func ComputeHankelMatrix(items []int64, u, q *big.Int, setting Setting) BigMatrix {
    u_list := make([]*big.Int, setting.m) // stores u^a^i for each a
    u1_list := make([]*big.Int, setting.m) // stores u^a for each a
    H := NewBigMatrix(setting.T + 1, setting.T + 1, nil)
    H.Set(0, 0, big.NewInt(int64(setting.m)))
    for i := range u1_list {
        u1_list[i] = big.NewInt(0)
        u1_list[i].Exp(u, big.NewInt(items[i]), q);
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
        el := sumSlice(u_list, q)
        for j := startCol; j < stopCol; j += 1 { // each matrix entry with current element
            H.Set(i-j, j, el)
        }
        if i >= 2 * setting.T {
            break
        }
        u_list = elMulSlice(u_list, u1_list, q)
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
        r, err = SampleInt(q)
        if err != nil {
            return
        }
        vals[i] = r
    }
    a = NewBigMatrix(rows, cols, vals)
    return
}

//step 1 of MMult
func SampleRMatrices(a, b BigMatrix, setting Setting) (RAi_plain, RAi_enc, RBi_plain, RBi_enc BigMatrix, err error) {
    RAi_plain, err = SampleMatrix(a.rows, a.cols, setting.pk.N)
    if err != nil {return}
    RAi_enc, err = EncryptMatrix(RAi_plain, setting)
    if err != nil {return}
    RBi_plain, err = SampleMatrix(b.rows, b.cols, setting.pk.N)
    if err != nil {return}
    RBi_enc, err = EncryptMatrix(RBi_plain, setting)
    if err != nil {return}
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

// calculates how many instances of MMult is needed to get all H,
// according to: n = ceil( log(matrix size) )
// H^2^n being the highest order needed
func NbrMMultInstances(m BigMatrix) int {
    return int(math.Ceil(math.Log(float64(m.cols))))
}

// step 3f of CTest-diff
func SampleHMasks(setting Setting) {
    SampleMatrix(1, 2*(setting.T+1), setting.pk.N)
}

//Additive Secret Sharing

//ASS, step 1
func GetRandomEncrypted(setting Setting) (plain, cipher *big.Int, err error) {
    plain, err = SampleInt(setting.pk.N)
    if err != nil {return}
    cipher, err = EncryptValue(plain, setting)
    return
}

//ASS, step 5 & 6
func SumMasksDecrypt(a *big.Int, ds []*big.Int, sk *tcpaillier.KeyShare, setting Setting) (e_partial *tcpaillier.DecryptionShare, err error) {
    for _, val := range ds {
        a, err = setting.pk.Add(a, val)
        if err != nil {return}
    }
    return PartialDecryptValue(a, sk)
}

//ASS, step 7
func NegateValue(d *big.Int, setting Setting) *big.Int {
    neg := new(big.Int)
    neg.Neg(d)
    neg.Mod(neg, setting.pk.N)
    return neg
}

//Multiplication

//Mult, step 2
func MultiplyEncrypted(encrypted, plain *big.Int, setting Setting) (*big.Int, error) {
    prod, _, err := setting.pk.Multiply(encrypted, plain)
    return prod, err
}

//Mult, step 6
func SumMultiplication(values []*big.Int, setting Setting) (sum *big.Int, err error) {
    sum, err = setting.pk.Add(values...)
    return
}
