package tpsi

import (
    "testing"
    "math/big"
)

func TestCPHankelMatrix(t *testing.T) {
    var setting Setting
    items := []int64{2, 3, 5}
    setting.m = 3
    setting.T = 2
    setting.n = 4
    setting.q = big.NewInt(11)
    u := big.NewInt(6)
    H := CPComputeHankelMatrix(items, u, setting)
    H_corr := NewBigMatrix(3, 3, sliceToBigInt([]int64{9,27,12,27,12,18,12,18,24}))
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
