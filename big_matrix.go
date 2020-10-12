package tpsi

import (
    "math/big"
    "errors"
    "fmt"
)

type BigMatrix struct {
    values []*big.Int
    rows, cols int
}

// Create a new 0-index BigMatrix with the given size and data. Panics if size and data mismatch.
func NewBigMatrix(rows, cols int, data []*big.Int) BigMatrix {
    if data == nil {
        data = make([]*big.Int, rows*cols)
        for i := range data {
            data[i] = big.NewInt(0)
        }
    } else if rows * cols != len(data) {
        panic(errors.New("Data structure not matching matrix size"))
    }
    var m BigMatrix
    m.values = data
    m.rows = rows
    m.cols = cols
    return m
}

func (m BigMatrix) At(row, col int) *big.Int {
    if row >= m.rows || col >= m.cols || row < 0 || col < 0{
        panic(errors.New(fmt.Sprintf("Index out of bounds: (%d, %d)", row, col)))
    }
    valueIndex := m.cols*row + col
    return m.values[valueIndex]
}

func (m BigMatrix) Set(row, col int, value *big.Int) {
    if row >= m.rows || col >= m.cols || row < 0 || col < 0 {
        panic(errors.New(fmt.Sprintf("Index out of bounds: (%d, %d)", row, col)))
    }
    m.values[m.cols*row + col] = value
}

func MatMul(a, b BigMatrix) BigMatrix {
    if a.cols != b.rows {
        panic(errors.New("matrices a and b are not compatible"))
    }
    cRows, cCols := a.rows, b.cols
    values := make([]*big.Int, cRows*cCols)
    r := big.NewInt(0)
    for i := 0; i < cRows; i += 1 {
        for j := 0; j < cCols; j += 1 {
            sum := big.NewInt(0)
            for k := 0; k < a.cols; k += 1 {
                r.Mul(a.At(i, k), b.At(k, j))
                sum.Add(r, sum)
            }
            values[i*cCols+j] = sum
        }
    }
    return NewBigMatrix(cRows, cCols, values)
}

func MatAdd(a, b BigMatrix) BigMatrix {
    if a.rows != b.rows {
        panic(errors.New("row mismatch in addition"))
    } else if a.cols != b.cols {
        panic(errors.New("column mismatch in addition"))
    }
    c := NewBigMatrix(a.rows, a.cols, nil)
    for i := range c.values {
        c.values[i].Add(a.values[i], b.values[i])
    }
    return c
}

func MatSub(a, b BigMatrix) BigMatrix {
    if a.rows != b.rows {
        panic(errors.New("row mismatch in addition"))
    } else if a.cols != b.cols {
        panic(errors.New("column mismatch in addition"))
    }
    c := NewBigMatrix(a.rows, a.cols, nil)
    for i := range c.values {
        c.values[i].Sub(a.values[i], b.values[i])
    }
    return c
}

func MatScaMul(a BigMatrix, b int64) BigMatrix {
    c := NewBigMatrix(a.rows, a.cols, nil)
    bb := big.NewInt(b)
    for i := range c.values {
        c.values[i].Mul(a.values[i], bb)
    }
    return c
}