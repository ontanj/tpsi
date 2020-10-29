package tpsi

import (
    "crypto/rand"
    "math/big"
)

// sample a uniform random integer smaller than q
func SampleInt(q *big.Int) (*big.Int, error) {
    return rand.Int(rand.Reader, q)
}

// compute the unencrypted Hankel Matrix for the central party
func CPComputeHankelMatrix(items []int64, u, q *big.Int, setting Setting) BigMatrix {
    H := ComputeHankelMatrix(items, u, q, setting)
    return MatScaMul(H, int64(setting.n-1))
}

//step 3b of CTest-diff
func SampleVVector(setting Setting) (v BigMatrix, err error) {
    return SampleMatrix(setting.T+1, 1, setting.pk.N)
}

// step 2 of MMult
func GetMulMatrices(A, B BigMatrix, RAs, RBs []BigMatrix, setting Setting) (RA, MA, MB BigMatrix, err error) {
    RA = RAs[0]
    RB := RBs[0]
    for i := 1; i < setting.n; i += 1 {
        RA, err = MatEncAdd(RA, RAs[i], setting.pk)
        if err != nil {
            return
        }
        RB, err = MatEncAdd(RB, RBs[i], setting.pk)
        if err != nil {
            return
        }
    }
    MA, err = MatEncAdd(A, RA, setting.pk)
    if err != nil {
        return
    }
    MB, err = MatEncAdd(B, RB, setting.pk)
    return
}

// step 4 of MMult
func CombineMatrixMultiplication(MAis, MBis []PartialMatrix, ctis []BigMatrix, setting Setting) (AB BigMatrix, err error) {
    MA, err := CombineMatrixShares(MAis, setting)
    if err != nil {return}
    MB, err := CombineMatrixShares(MBis, setting)
    if err != nil {return}
    MAMB := MatMul(MA, MB)
    AB, err = EncryptMatrix(MAMB, setting)
    if err != nil {return}
    for _, val := range ctis {
        AB, err = MatEncAdd(AB, val, setting.pk)
        if err != nil {return}
    }
    return
} 

// sample u from step 3e of CTest-diff
func SampleUVector(setting Setting) (u BigMatrix, err error) {
    return SampleMatrix(1, setting.T+1, setting.pk.N)
}

// step 3e of CTest-diff
func HSeq(Hvs BigMatrix, setting Setting) (h_seq BigMatrix, err error) {
    u, err := SampleUVector(setting)
    if err != nil {return}
    Hvs = CropMatrix(Hvs, 2*(setting.T+1))
    return MatEncLeftMul(u, Hvs, setting.pk)
}

// step 3g of CTest-diff
func MaskH(Hs BigMatrix, HMasks []BigMatrix, setting Setting) (diff BigMatrix, err error) {
    sum := HMasks[0]
    for i := 1; i < len(HMasks); i += 1 {
        sum, err = MatEncAdd(sum, HMasks[i], setting.pk)
        if err != nil {return}
    }
    return MatEncSub(Hs, sum, setting.pk)
}

//ASS, step 7
func SecretShare(d, e *big.Int, setting Setting) *big.Int {
    neg := new(big.Int)
    neg.Sub(e, d)
    neg.Mod(neg, setting.pk.N)
    return neg
}