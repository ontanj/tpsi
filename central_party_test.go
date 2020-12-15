package tpsi

import (
    "testing"
    "math/big"
)

func TestCPHankelMatrix(t *testing.T) {
    var setting Setting
    items := []uint64{2, 3, 5}
    setting.m = 3
    setting.T = 2
    setting.n = 4
    pk, djsks, eval_space, err := NewDJCryptosystem(setting.n)
    setting.eval_space = eval_space
    sks := ConvertDJSKSlice(djsks)
    if err != nil {t.Error(err)}
    setting.cs = pk
    q := big.NewInt(11)
    u := big.NewInt(6)
    H, err := CPComputeHankelMatrix(items, u, q, setting)
    if err != nil {t.Error(err)}
    H_corr := []int64{9,27,12,27,12,18,12,18,24}
    t.Run("check dimensions", func(t *testing.T){
        if H.Rows != setting.T + 1 || H.Cols != setting.T + 1 {
            t.Error("wrong dimensions")
        }
    })
    t.Run("check elements", func(t *testing.T){
        k := 0
        for i := 0; i < 3; i += 1 {
            for j := 0; j < 3; j += 1 {
                h_val, err := H.At(i,j)
                if err != nil {t.Error(err)}
                val := t_decrypt(h_val.(*big.Int), sks, setting)
                if val.Cmp(new(big.Int).SetInt64(H_corr[k])) != 0 {
                    t.Error("incorrect values")
                }
                k += 1
            }
        }
    })
}
