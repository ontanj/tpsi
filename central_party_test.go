package tpsi

import (
    "testing"
    "math/big"
)

func TestCPHankelMatrix(t *testing.T) {
    n := 4
    T := 2
    pk, sksdj, err := NewDJCryptosystem(n)
    if err != nil {t.Error(err)}
    sks := ConvertDJSKSlice(sksdj)
    settings := createAHESettings(n, T, pk)

    items := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(5)}
    q := big.NewInt(11)
    u := big.NewInt(6)
    H, err := CPComputeHankelMatrix(items, u, q, settings[0])
    if err != nil {t.Error(err)}
    H_corr := []int64{9,27,12,27,12,18,12,18,24}
    t.Run("check dimensions", func(t *testing.T){
        if H.Rows != settings[0].T + 1 || H.Cols != settings[0].T + 1 {
            t.Error("wrong dimensions")
        }
    })
    t.Run("check elements", func(t *testing.T){
        k := 0
        for i := 0; i < 3; i += 1 {
            for j := 0; j < 3; j += 1 {
                h_val, err := decodeBI(H.At(i,j))
                if err != nil {t.Error(err)}
                val := t_decrypt(h_val, sks, settings)
                if val.Cmp(new(big.Int).SetInt64(H_corr[k])) != 0 {
                    t.Error("incorrect values")
                }
                k += 1
            }
        }
    })
}
