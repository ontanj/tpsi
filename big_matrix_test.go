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
    t.Run("index out of bounds", func (t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("didn't panic on index out of bounds")
            }
        }()
        m.At(0,3)
    })
}

func TestSet(t *testing.T) {
    a := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,3,4}))
    b := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,5,4}))
    a.Set(1,0,big.NewInt(5))
    ComparePlain(2, 2, a, b, t)
    t.Run("index out of bounds", func (t *testing.T) {
        defer func() {
            if recover() == nil {
                t.Error("didn't panic on index out of bounds")
            }
        }()
        a.Set(0,3,big.NewInt(10))
    })
}

func TestMultiplication(t *testing.T) {
    a := NewBigMatrix(2, 2, sliceToBigInt([]int64{1,2,3,4}))
    b := NewBigMatrix(2, 3, sliceToBigInt([]int64{1,2,3,4,5,6}))
    t.Run("vanilla", func(t *testing.T) {
        c := MatMul(a, b)
        d := NewBigMatrix(2, 3, sliceToBigInt([]int64{9,12,15,19,26,33}))
        ComparePlain(2, 3, c, d, t)
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
        ComparePlain(2, 2, b, c, t)
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
        ComparePlain(2, 2, c, d, t)
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

func TestScalarMultiplication(t *testing.T) {
    a := NewBigMatrix(2, 3, sliceToBigInt([]int64{3, 4, 2, 1, 8, 5}))
    b := int64(2)
    c := NewBigMatrix(2, 3, sliceToBigInt([]int64{6, 8, 4, 2, 16, 10}))
    d := MatScaMul(a, b)
    ComparePlain(2, 3, c, d, t)
}

func TestEncryptedMatrixAddition(t *testing.T) {
    a := NewBigMatrix(2, 3, sliceToBigInt([]int64{3, 4, 2, 1, 8, 5}))
    b := NewBigMatrix(2, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6}))
    c := NewBigMatrix(2, 3, sliceToBigInt([]int64{4, 6, 5, 5, 13, 11}))
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {
        t.Error(err)
    }
    var setting Setting;
    setting.pk = pk
    a, err = EncryptMatrix(a, setting)
    if err != nil {
        t.Error(err)
    }
    b, err = EncryptMatrix(b, setting)
    if err != nil {
        t.Error(err)
    }
    t.Run("vanilla", func(t *testing.T) {
        sum, err := MatEncAdd(a, b, setting.pk)
        if err != nil {
            t.Error(err)
        }
        err = CompareEnc(sum, c, sks, setting)
        if err != nil {
            t.Error(err)
        }
    })
    t.Run("column mismatch", func(t *testing.T) {
        d := NewBigMatrix(2, 2, sliceToBigInt([]int64{1, 2, 3, 4}))
        d, _ = EncryptMatrix(d, setting)
        defer func() {
            if recover() == nil {
                t.Error("didn't panic")
            }
        }()
        MatEncSub(a, d, setting.pk)
    })
    t.Run("column mismatch", func(t *testing.T) {
        d := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
        d, _ = EncryptMatrix(d, setting)
        defer func() {
            if recover() == nil {
                t.Error("didn't panic")
            }
        }()
        MatEncSub(a, d, setting.pk)
    })
}

func TestEncryptedMatrixSubtraction(t *testing.T) {
    a := NewBigMatrix(2, 3, sliceToBigInt([]int64{3, 4, 2, 1, 8, 5}))
    b := NewBigMatrix(2, 3, sliceToBigInt([]int64{1, 2, 2, 0, 4, 3}))
    c := NewBigMatrix(2, 3, sliceToBigInt([]int64{2, 2, 0, 1, 4, 2}))
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {
        t.Error(err)
    }
    var setting Setting;
    setting.pk = pk
    a, err = EncryptMatrix(a, setting)
    if err != nil {
        t.Error(err)
    }
    b, err = EncryptMatrix(b, setting)
    if err != nil {
        t.Error(err)
    }
    t.Run("vanilla", func(t *testing.T) {
        diff, err := MatEncSub(a, b, setting.pk)
        if err != nil {
            t.Error(err)
        }
        err = CompareEnc(diff, c, sks, setting)
        if err != nil {
            t.Error(err)
        }
    })
    t.Run("column mismatch", func(t *testing.T) {
        d := NewBigMatrix(2, 2, sliceToBigInt([]int64{1, 2, 3, 4}))
        d, _ = EncryptMatrix(d, setting)
        defer func() {
            if recover() == nil {
                t.Error("didn't panic")
            }
        }()
        MatEncSub(a, d, setting.pk)
    })
    t.Run("column mismatch", func(t *testing.T) {
        d := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
        d, _ = EncryptMatrix(d, setting)
        defer func() {
            if recover() == nil {
                t.Error("didn't panic")
            }
        }()
        MatEncSub(a, d, setting.pk)
    })
}

func TestEncryptedMatrixMultiplication(t *testing.T) {
    a := NewBigMatrix(2, 3, sliceToBigInt([]int64{1,2,3,4,5,6}))
    b := NewBigMatrix(3, 2, sliceToBigInt([]int64{1,2,3,4,5,6}))
    sks, pk, _ := GenerateKeys(512, 1, 4)
    var setting Setting
    setting.pk = pk
    ae, _ := EncryptMatrix(a, setting)
    t.Run("plaintext from right", func(t *testing.T) {  
        abe, err := MatEncRightMul(ae, b, setting.pk)
        if err != nil {
            t.Error(err)
        }
        ab := MatMul(a, b)
        err = CompareEnc(abe, ab, sks, setting)
        if err != nil {
            t.Error(err)
        }
    })
    t.Run("plaintext from left", func(t *testing.T) {  
        bae, err := MatEncLeftMul(b, ae, setting.pk)
        if err != nil {
            t.Error(err)
        }
        ba := MatMul(b, a)
        err = CompareEnc(bae, ba, sks, setting)
        if err != nil {
            t.Error(err)
        }
    })
}

func ComparePlain(rows, cols int, a, b BigMatrix, t *testing.T) {
    for i := 0; i < rows; i += 1 {
        for j := 0; j < cols; j += 1 {
            if a.At(i, j).Cmp(b.At(i, j)) != 0 {
                t.Errorf("values differ at (%d, %d)", i, j)
            }
        }
    }
}

func TestConcatenation(t *testing.T) {
    a := NewBigMatrix(3, 2, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6}))
    b := NewBigMatrix(3, 2, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6}))
    c := NewBigMatrix(3, 4, sliceToBigInt([]int64{1, 2, 1, 2, 3, 4, 3, 4, 5, 6, 5, 6}))
    ab := ConcatenateMatrices(a, b)
    ComparePlain(3, 4, c, ab, t)
}

func TestCropMatrix(t *testing.T) {
    a := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
    a = CropMatrix(a, 2)   
    b := NewBigMatrix(3, 2, sliceToBigInt([]int64{2, 3, 5, 6, 8, 9}))
    ComparePlain(3, 2, a, b, t)
}