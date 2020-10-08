package tpsi

import (
    "testing"
    "math/big"
)

func sliceToBigInt(values []int64) []*big.Int {
    l := len(values)
    s := make([]*big.Int, l)
    for i := 0; i < l; i += 1 {
        s[i] = big.NewInt(values[i])
    }
    return s
}

func TestValidNewBigMatrix(t *testing.T) {
    t.Run("vanilla", func(t *testing.T){
        var matrixData []*big.Int
        var dval int64
        for dval = 1; dval <= 9; dval++ {
            matrixData = append(matrixData, big.NewInt(dval))
        }
        m := NewBigMatrix(3, 3, matrixData)
        if m.cols != 3 {
            t.Error("wrong column size")
        }
        if m.rows != 3 {
            t.Error("wrong row size")
        }
        for i := 0; i < 9; i++ {
            if m.values[i].Cmp(matrixData[i]) != 0 {
                t.Error("wrong data")
            }
        }
    })
    t.Run("uninitialized data", func(t *testing.T) {
        m := NewBigMatrix(3, 3, nil)
        zero := big.NewInt(0)
        for i := 0; i < 9; i++ {
            if zero.Cmp(m.values[i]) != 0 {
                t.Error("not zeroes for uninitialized data")
            }
        }
    })
}

func TestInvalidNewBigMatrix(t *testing.T) {
    defer func() {
        if recover() == nil {
            t.Error("contructor did not panic on mismatched size")
        }
    }()
    var matrixData []*big.Int
    var dval int64
    for dval = 1; dval <= 8; dval++ {
        matrixData = append(matrixData, big.NewInt(dval))
    }
    NewBigMatrix(3, 3, matrixData)
}

func TestAt(t *testing.T) {
    var matrixData []*big.Int
    var dval int64
    for dval = 1; dval <= 9; dval++ {
        matrixData = append(matrixData, big.NewInt(dval))
    }
    m := NewBigMatrix(3, 3, matrixData)
    row, col := 0, 0
    for _, val := range matrixData {
        if val.Cmp(m.At(row, col)) != 0 {
            t.Error("malformed matrix")
        }
        if col == 2 {
            col = 0
            row += 1
        } else {
            col += 1
        }
    }
}

func TestMultiplication(t *testing.T) {
    a := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,3,4}))
    b := NewBigMatrix(2, 3, sliceToBigInt([]int64{1,2,3,4,5,6}))
    t.Run("vanilla", func(t *testing.T) {
        c := MatMul(a, b)
        d := NewBigMatrix(2, 3, sliceToBigInt([]int64{9,12,15,19,26,33}))
        for i := 0; i < 2; i += 1 {
            for j := 0; j < 3; j += 1 {
                if c.At(i,j).Cmp(d.At(i,j)) != 0 {
                    t.Error("error in matrix multiplication")
                }
            }
        }
    })
    t.Run("dimension mismatch", func(t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("multiplication of mismatched matrices passed")
            }
        }()
        MatMul(b, a)
    })
}

func TestAddition(t *testing.T) {
    a := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,3,4}))
    b := MatAdd(a, a)
    c := NewBigMatrix(2, 2, sliceToBigInt([]int64{2,4,6,8}))
    t.Run("vanilla addition", func(t *testing.T) {
        for i := 0; i < 2; i += 1 {
            for j := 0; j < 2; j += 1 {
                if b.At(i,j).Cmp(c.At(i,j)) != 0 {
                    t.Error("error in matrix addition")
                }
            }
        }
    })
    
    t.Run("row mismatch", func(t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("addition of mismatched matrices passed")
            }
        }()
        d := NewBigMatrix(3,2,nil)
        MatAdd(a, d)
    })
    t.Run("column mismatch", func(t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("addition of mismatched matrices passed")
            }
        }()
        e := NewBigMatrix(2,3,nil)
        MatAdd(a, e)
    })
}

func TestSubtraction(t *testing.T) {
    a := NewBigMatrix(2, 2, sliceToBigInt([]int64{5,3,7,9}))
    b := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,3,4}))
    c := MatSub(a, b)
    d := NewBigMatrix(2, 2, sliceToBigInt([]int64{4,1,4,5}))
    t.Run("vanilla subtraction", func(t *testing.T) {
        for i := 0; i < 2; i += 1 {
            for j := 0; j < 2; j += 1 {
                if c.At(i,j).Cmp(d.At(i,j)) != 0 {
                    t.Error("data error")
                }
            }
        }
    })

    t.Run("row mismatch", func(t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("addition of mismatched matrices passed")
            }
        }()
        e := NewBigMatrix(3,2,nil)
        MatSub(a, e)
    })
    t.Run("column mismatch", func(t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("addition of mismatched matrices passed")
            }
        }()
        f := NewBigMatrix(2,3,nil)	
        MatSub(a, f)
    })
}