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
func CPComputeHankelMatrix(items []uint64, u, q *big.Int, setting Setting) (H gm.Matrix, err error) {
    H = ComputePlainHankelMatrix(items, u, q, setting)
    H, err = H.Scale(big.NewInt(int64(setting.n-1)))
    if err != nil {return}
    return EncryptMatrix(H, setting)
}

//step 3b of CTest-diff
func SampleVVector(m gm.Matrix, setting Setting) (v gm.Matrix, err error) {
    v_plain, err := SampleMatrix(m.Cols, 1, setting.cs.N())
    if err != nil {return}
    return EncryptMatrix(v_plain, setting)
}

// step 2 of MMult
func GetMulMatrices(A, B gm.Matrix, RAs, RBs []gm.Matrix, setting Setting) (RA, MA, MB gm.Matrix, err error) {
    RA = RAs[0]
    RB := RBs[0]
    for i := 1; i < setting.n; i += 1 {
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
func CombineMatrixMultiplication(MAis, MBis []gm.Matrix, ctis []gm.Matrix, setting Setting) (AB gm.Matrix, err error) { // todo: mai, mbi partial
    MA, err := CombineMatrixShares(MAis, setting)
    if err != nil {return}
    MB, err := CombineMatrixShares(MBis, setting)
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
func SampleUVector(m gm.Matrix, setting Setting) (u gm.Matrix, err error) {
    return SampleMatrix(1, m.Rows, setting.cs.N())
}

// step 3e of CTest-diff
func HSeq(Hvs gm.Matrix, mat_size int, setting Setting) (h_seq gm.Matrix, err error) {
    u, err := SampleUVector(Hvs, setting)
    if err != nil {return}
    Hvs = Hvs.CropHorizontally(2*mat_size)
    return u.Multiply(Hvs)
}

// step 3g of CTest-diff
func MaskH(Hs gm.Matrix, HMasks []gm.Matrix, setting Setting) (diff gm.Matrix, err error) {
    sum := HMasks[0]
    for i := 1; i < len(HMasks); i += 1 {
        sum, err = sum.Add(HMasks[i])
        if err != nil {return}
    }
    return Hs.Subtract(sum)
}

//ASS, step 7
func SecretShare(d, e *big.Int, setting Setting) *big.Int {
    neg := new(big.Int)
    neg.Sub(e, d)
    neg.Mod(neg, setting.cs.N())
    return neg
}