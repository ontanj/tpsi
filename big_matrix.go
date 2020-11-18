package tpsi

import (
    "math/big"
    "errors"
    "fmt"
    "github.com/niclabs/tcpaillier"
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

// get value of BigMatrix m at (row, col)
func (m BigMatrix) At(row, col int) *big.Int {
    if row >= m.rows || col >= m.cols || row < 0 || col < 0{
        panic(errors.New(fmt.Sprintf("Index out of bounds: (%d, %d)", row, col)))
    }
    valueIndex := m.cols*row + col
    return m.values[valueIndex]
}

// set value of BigMatrix m at (row, col)
func (m BigMatrix) Set(row, col int, value *big.Int) {
    if row >= m.rows || col >= m.cols || row < 0 || col < 0 {
        panic(errors.New(fmt.Sprintf("Index out of bounds: (%d, %d)", row, col)))
    }
    m.values[m.cols*row + col] = value
}

// matrix multiplication of unencrypted matrices
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

// matrix addition of unencrypted matrices
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

// matrix subtraction of unencrypted matrices
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

// scalar multiplication of matrix for unencryted values
func MatScaMul(a BigMatrix, b *big.Int) BigMatrix {
    c := NewBigMatrix(a.rows, a.cols, nil)
    for i := range c.values {
        c.values[i].Mul(a.values[i], b)
    }
    return c
}

// matrix addition for encrypted matrices
func MatEncAdd(a, b BigMatrix, pk *tcpaillier.PubKey) (BigMatrix, error) {
    if a.rows != b.rows {
        panic(errors.New("row mismatch in addition"))
    } else if a.cols != b.cols {
        panic(errors.New("column mismatch in addition"))
    }
    c := NewBigMatrix(a.rows, a.cols, nil)
    for i := range c.values {
        val, err := pk.Add(a.values[i], b.values[i])
        if err != nil {
            return c, err
        }
        c.values[i] = val
    }
    return c, nil
}

// matrix subtraction of encrypted matrices
func MatEncSub(a, b BigMatrix, pk *tcpaillier.PubKey) (BigMatrix, error) {
    if a.rows != b.rows {
        panic(errors.New("row mismatch in subtraction"))
    } else if a.cols != b.cols {
        panic(errors.New("column mismatch in subtraction"))
    }
    c := NewBigMatrix(a.rows, a.cols, nil)
    for i := range c.values {
        negB, _, err := pk.Multiply(b.values[i], big.NewInt(-1))
        if err != nil {
            return c, err
        }
        val, err := pk.Add(a.values[i], negB)
        if err != nil {
            return c, err
        }
        c.values[i] = val
    }
    return c, nil
}

// matrix multiplication encrypted * plain
func MatEncRightMul(encrypted, plain BigMatrix, pk *tcpaillier.PubKey) (c BigMatrix, err error) {
    if encrypted.cols != plain.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", encrypted.rows, encrypted.cols, plain.rows, plain.cols))
    }
    cRows, cCols := encrypted.rows, plain.cols
    values := make([]*big.Int, cRows*cCols)
    r := big.NewInt(0)
    for i := 0; i < cRows; i += 1 {
        for j := 0; j < cCols; j += 1 {
            var sum *big.Int
            sum, _, err = pk.Multiply(encrypted.At(i, 0), plain.At(0, j))
                if err != nil {
                    return
                }
            for k := 1; k < encrypted.cols; k += 1 {
                r, _, err = pk.Multiply(encrypted.At(i, k), plain.At(k, j))
                if err != nil {
                    return
                }
                sum, err = pk.Add(r, sum)
                if err != nil {
                    return
                }
            }
            values[i*cCols+j] = sum
        }
    }
    return NewBigMatrix(cRows, cCols, values), nil
}

// matrix multiplication plain * encrypted
func MatEncLeftMul(plain, encrypted BigMatrix, pk *tcpaillier.PubKey) (c BigMatrix, err error) {
    if plain.cols != encrypted.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", plain.rows, plain.cols, encrypted.rows, encrypted.cols))
    }
    cRows, cCols := plain.rows, encrypted.cols
    values := make([]*big.Int, cRows*cCols)
    r := big.NewInt(0)
    for i := 0; i < cRows; i += 1 {
        for j := 0; j < cCols; j += 1 {
            var sum *big.Int
            sum, _, err = pk.Multiply(encrypted.At(0, j), plain.At(i, 0))
                if err != nil {
                    return
                }
            for k := 1; k < plain.cols; k += 1 {
                r, _, err = pk.Multiply(encrypted.At(k, j), plain.At(i, k))
                if err != nil {
                    return
                }
                sum, err = pk.Add(r, sum)
                if err != nil {
                    return
                }
            }
            values[i*cCols+j] = sum
        }
    }
    return NewBigMatrix(cRows, cCols, values), nil
}

// concatenate matrices as A|B
func ConcatenateMatrices(a, b BigMatrix) BigMatrix {
    if a.rows != b.rows {
        panic("matrices not compatible for concatenation")
    }
    vals := make([]*big.Int, 0, (a.cols + b.cols) * a.rows)
    for i := 0; i < a.rows; i += 1 {
        vals = append(vals, a.values[i*a.cols:(i+1)*a.cols]...)
        vals = append(vals, b.values[i*b.cols:(i+1)*b.cols]...)
    }
    return NewBigMatrix(a.rows, a.cols + b.cols, vals)
}

// create a new matrix from last k columns of a
func CropMatrix(a BigMatrix, k int) BigMatrix {
    vals := make([]*big.Int, 0, k*a.rows)
    d := a.cols - k
    for i := 0; i < a.rows; i += 1 {
        vals = append(vals, a.values[i*a.cols+d:(i+1)*a.cols]...)
    }
    return NewBigMatrix(a.rows, k, vals)
}

func MatMod(a BigMatrix, mod *big.Int) BigMatrix {
    b := NewBigMatrix(a.rows, a.cols, nil)
    for i := range a.values {
        b.values[i].Mod(a.values[i], mod)
    }
    return b
}