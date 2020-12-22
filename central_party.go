package tpsi

import (
    "crypto/rand"
    "math/big"
    gm "github.com/ontanj/generic-matrix"
)

// sample a uniform random integer smaller than q
func SampleInt(q *big.Int) (*big.Int, error) {
    return rand.Int(rand.Reader, q)
}

// compute the encrypted Hankel Matrix for central party
func CPComputeHankelMatrix(items []*big.Int, u, q *big.Int, setting AHE_setting) (H gm.Matrix, err error) {
    H = ComputePlainHankelMatrix(items, u, q, setting)
    H, err = H.Scale(big.NewInt(int64(setting.Parties()-1)))
    if err != nil {return}
    return EncryptMatrix(H, setting)
}

//step 3b of CTest-diff
func SampleVVector(m gm.Matrix, setting AHE_setting) (v gm.Matrix, err error) {
    v_plain, err := SampleMatrix(m.Cols, 1, setting.AHE_cryptosystem().N())
    if err != nil {return}
    return EncryptMatrix(v_plain, setting)
}

// step 2 of MMult
func GetMulMatrices(A, B gm.Matrix, RAs, RBs []gm.Matrix, setting AHE_setting) (RA, MA, MB gm.Matrix, err error) {
    RA = RAs[0]
    RB := RBs[0]
    for i := 1; i < setting.Parties(); i += 1 {
        RA, err = RA.Add(RAs[i])
        if err != nil {
            return
        }
        RB, err = RB.Add(RBs[i])
        if err != nil {
            return
        }
    }
    MA, err = A.Add(RA)
    if err != nil {
        return
    }
    MB, err = B.Add(RB)
    return
}

// step 4 of MMult
func CombineMatrixMultiplication(MA_enc, MB_enc gm.Matrix, MAis, MBis []gm.Matrix, ctis []gm.Matrix, setting AHE_setting) (AB gm.Matrix, err error) { // todo: mai, mbi partial
    MA, err := CombineMatrixShares(MAis, MA_enc, setting)
    if err != nil {return}
    MB, err := CombineMatrixShares(MBis, MB_enc, setting)
    if err != nil {return}
    MAMB, err := MA.Multiply(MB)
    if err != nil {return}
    AB, err = EncryptMatrix(MAMB, setting)
    if err != nil {return}
    for _, val := range ctis {
        AB, err = AB.Add(val)
        if err != nil {return}
    }
    return
} 

// sample u from step 3e of CTest-diff
func SampleUVector(m gm.Matrix, setting AHE_setting) (u gm.Matrix, err error) {
    return SampleMatrix(1, m.Rows, setting.AHE_cryptosystem().N())
}

// step 3e of CTest-diff
func HSeq(Hvs gm.Matrix, mat_size int, setting AHE_setting) (h_seq gm.Matrix, err error) {
    u, err := SampleUVector(Hvs, setting)
    if err != nil {return}
    Hvs = Hvs.CropHorizontally(2*mat_size)
    return u.Multiply(Hvs)
}

// step 3g of CTest-diff
func MaskH(Hs gm.Matrix, HMasks []gm.Matrix, setting AHE_setting) (diff gm.Matrix, err error) {
    sum := HMasks[0]
    for i := 1; i < len(HMasks); i += 1 {
        sum, err = sum.Add(HMasks[i])
        if err != nil {return}
    }
    return Hs.Subtract(sum)
}

//ASS, step 7
func SecretShare(d, e *big.Int, setting AHE_setting) *big.Int {
    neg := new(big.Int)
    neg.Sub(e, d)
    neg.Mod(neg, setting.AHE_cryptosystem().N())
    return neg
}