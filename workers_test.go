package tpsi

import (
    "testing"
    "math/big"
    "github.com/niclabs/tcpaillier"
)

// create a slice of n chan interface{}
func create_chans(n int) []chan interface{} {
    channels := make([]chan interface{}, n)
    for i := 0; i < n; i += 1 {
        channels[i] = make(chan interface{})
    }
    return channels
}

func TestASSWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(20), setting)
    if err != nil {t.Error(err)}

    go CentralASSWorker(a, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterASSWorker(a, sks[i], setting, channels[i], return_channel)
    }

    sum := big.NewInt(0)
    for i := 0; i < setting.n; i += 1 {
        val := <-return_channel
        sum.Add(sum, val)
        sum.Mod(sum, setting.pk.N)
    }
    if sum.Cmp(big.NewInt(20)) != 0 {
        t.Error("shares don't add up")
    }
}

func TestMultWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(3), setting)
    if err != nil {t.Error(err)}
    b, err := EncryptValue(big.NewInt(4), setting)
    if err != nil {t.Error(err)}

    go CentralMultWorker(a, b, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterMultWorker(a, b, sks[i], setting, channels[i], return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        prod_enc := <-return_channel
        // verify
        parts := make([]*tcpaillier.DecryptionShare, setting.n)
        for i, sk := range sks {
            part, err := PartialDecryptValue(prod_enc, sk)
            if err != nil {t.Error(err)}
            parts[i] = part
        }
        prod, err := CombineShares(parts, setting)
        prod.Mod(prod, setting.pk.N)
        if err != nil {t.Error(err)}
        if prod.Cmp(big.NewInt(12)) != 0 {
            t.Error("multiplication error")
        }
    }
}

func TestZeroTestWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk

    channels := create_chans(setting.n-1)
    return_channel := make(chan bool)

    t.Run("test 0", func (t *testing.T) {
        cipher, err := EncryptValue(big.NewInt(0), setting)
        if err != nil {panic(err)}

        go CentralZeroTestWorker(cipher, sks[setting.n-1], setting, channels, return_channel)
        for i := 0; i < setting.n-1; i += 1 {
            go OuterZeroTestWorker(cipher, sks[i], setting, channels[i], return_channel)
        }

        for i := 0; i < setting.n; i += 1 {
            if !(<-return_channel) {
                t.Error("zero test fail for 0")
            }
        }
    })

    t.Run("test non-0", func (t *testing.T) {
        cipher, err := EncryptValue(big.NewInt(131), setting)
        if err != nil {panic(err)}

        go CentralZeroTestWorker(cipher, sks[setting.n-1], setting, channels, return_channel)
        for i := 0; i < setting.n-1; i += 1 {
            go OuterZeroTestWorker(cipher, sks[i], setting, channels[i], return_channel)
        }

        for i := 0; i < setting.n; i += 1 {
            if (<-return_channel) {
                t.Error("zero test true for 131")
            }
        }
    })
}

func TestDecryptionWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int)

    cipher, err := EncryptValue(big.NewInt(83), setting)
    if err != nil {panic(err)}

    go CentralDecryptionWorker(cipher, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterDecryptionWorker(cipher, sks[i], setting, channels[i], return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        if (<-return_channel).Cmp(big.NewInt(83)) != 0 {
            t.Error("decryption error")
        }
    }
}

func t_decrypt(cipher *big.Int, sks []*tcpaillier.KeyShare, setting Setting) *big.Int {
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int, 4) // only read first return value
    go CentralDecryptionWorker(cipher, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterDecryptionWorker(cipher, sks[i], setting, channels[i], return_channel)
    }
    val := <-return_channel
    return val
}

func t_decryptPoly(num, den BigMatrix, sks []*tcpaillier.KeyShare, setting Setting) BigMatrix {
    p := NewBigMatrix(1, num.cols, nil)
    for i := 0; i < num.cols; i += 1 {
        num_val := t_decrypt(num.At(0,i), sks, setting)
        den_val := t_decrypt(den.At(0,i), sks, setting)
        den_val.ModInverse(den_val, setting.pk.N)
        p.Set(0,i, num_val.Mul(num_val, den_val).Mod(num_val, setting.pk.N))
    }
    return p
}

func TestPolynomialDivisionWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk
    divid := NewBigMatrix(1, 5, sliceToBigInt([]int64{3, 6, 5, 2, 0}))
    divis := NewBigMatrix(1, 4, sliceToBigInt([]int64{1, 3, 2, 0}))
    q := sliceToBigInt([]int64{1, 1})
    r := sliceToBigInt([]int64{2, 2})

    divid_enc, err := EncryptMatrix(divid, setting)
    if err != nil {t.Error(err)}
    divid_den, err := EncryptValue(big.NewInt(1), setting)
    if err != nil {t.Error(err)}
    divis_enc, err := EncryptMatrix(divis, setting)
    if err != nil {t.Error(err)}
    divis_den, err := EncryptValue(big.NewInt(1), setting)
    if err != nil {t.Error(err)}

    channels := create_chans(setting.n-1)

    validator := func(num BigMatrix, den BigMatrix, corr []*big.Int) {
        dec := make([]*big.Int, num.cols)
        var den_i *big.Int // denominator inverse
        
        // if denominator shared among all coefficients -> decrypt it
        if den.cols == 1 {
            den_i = t_decrypt(den.At(0, 0), sks, setting)
            den_i.ModInverse(den_i, setting.pk.N)
        }
        
        // iterate over coefficients
        for j := 0; j < len(corr); j += 1 {
            // decrypt current denominator if not shared
            if den.cols != 1 {
                den_i = t_decrypt(den.At(0, j), sks, setting)
                den_i.ModInverse(den_i, setting.pk.N)
            }
            dec[j] = t_decrypt(num.At(0, j), sks, setting) // decrypt current numerator
            dec[j].Mul(dec[j], den_i).Mod(dec[j], setting.pk.N) // multiply numerator and denominator inverse
            if dec[j].Cmp(corr[j]) != 0 {
                t.Errorf("error in polynomial division, expected %d got %d", corr[j], dec[j])
            }
        }
        if den.cols > len(corr) {
            t.Error("exceeding coefficients")
        }
    }

    returns := make([]chan BigMatrix, setting.n)
    returns[0] = make(chan BigMatrix)
    returns[1] = make(chan BigMatrix) // discard these messages as they are equivalent to returns[0]
    returns[2] = make(chan BigMatrix) // discard these messages as they are equivalent to returns[0]
    returns[3] = make(chan BigMatrix)
    
    go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[setting.n-1], setting, channels, nil, returns[setting.n-1])
    for i := 0; i < setting.n-1; i += 1 {
        go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[i], setting, nil, channels[i], returns[i])
    }
    
    qn := <-returns[0]
    validator(qn, <-returns[0], q)
    rn :=  <-returns[0]
    validator(rn, <-returns[0], r)
    qn = <-returns[3]
    validator(qn, <-returns[3], q)
    rn = <-returns[3]
    validator(rn, <-returns[3], r)
    
}

func TestEncryptedPolyMult(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk

    a_num := NewBigMatrix(1, 3, sliceToBigInt([]int64{3, 9, 3}))
    a_num, err = EncryptMatrix(a_num, setting)
    if err != nil {t.Error(err)}
    a_den := NewBigMatrix(1, 3, sliceToBigInt([]int64{1, 4, 2}))
    a_den, err = EncryptMatrix(a_den, setting)
    if err != nil {t.Error(err)}

    b_num := NewBigMatrix(1, 2, sliceToBigInt([]int64{4, 4}))
    b_num, err = EncryptMatrix(b_num, setting)
    if err != nil {t.Error(err)}
    b_den := NewBigMatrix(1, 2, sliceToBigInt([]int64{3, 1}))
    b_den, err = EncryptMatrix(b_den, setting)
    if err != nil {t.Error(err)}

    corr := NewBigMatrix(1, 4, sliceToBigInt([]int64{4, 15, 11, 6}))

    channels := create_chans(setting.n-1)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[setting.n-1], setting, channels, nil)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < corr.cols; k += 1 {
            if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p.At(0,k), corr.At(0,k))
            }
        }
        return_channel <- 0
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[j], setting, nil, channels[j])
            if err != nil {t.Error(err)}
            p := t_decryptPoly(p_num, p_den, sks, setting)
            for k := 0; k < corr.cols; k += 1 {
                if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                    t.Errorf("non-matching value at %d, expected %d got %d", k, corr.At(0,k), p.At(0,k))
                }
            }
            return_channel <- 0
        }(i)
    }
    for i := 0; i < setting.n; i += 1{
        <-return_channel
    }
}

func TestPolySub(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk

    a_num := NewBigMatrix(1, 2, sliceToBigInt([]int64{5, 4}))
    a_num, err = EncryptMatrix(a_num, setting)
    if err != nil {t.Error(err)}
    a_den := NewBigMatrix(1, 2, sliceToBigInt([]int64{2, 3}))
    a_den, err = EncryptMatrix(a_den, setting)
    if err != nil {t.Error(err)}

    b_num := NewBigMatrix(1, 2, sliceToBigInt([]int64{1, 2}))
    b_num, err = EncryptMatrix(b_num, setting)
    if err != nil {t.Error(err)}
    b_den := NewBigMatrix(1, 2, sliceToBigInt([]int64{2, 6}))
    b_den, err = EncryptMatrix(b_den, setting)
    if err != nil {t.Error(err)}

    corr := NewBigMatrix(1, 2, sliceToBigInt([]int64{2, 1}))

    channels := create_chans(setting.n-1)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[setting.n-1], setting, channels, nil)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < corr.cols; k += 1 {
            if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p.At(0,k), corr.At(0,k))
            }
        }
        return_channel <- 0
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[j], setting, nil, channels[j])
            if err != nil {t.Error(err)}
            p := t_decryptPoly(p_num, p_den, sks, setting)
            for k := 0; k < corr.cols; k += 1 {
                if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                    t.Errorf("non-matching value at %d, expected %d got %d", k, corr.At(0,k), p.At(0,k))
                }
            }
            return_channel <- 0
        }(i)
    }
    for i := 0; i < setting.n; i += 1{
        <-return_channel
    }
}

func TestTDecryptPoly(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, _ := GenerateKeys(512, 1, 4)
    setting.pk = pk
    num := NewBigMatrix(1, 3, sliceToBigInt([]int64{6, 9, 4}))
    num, _ = EncryptMatrix(num, setting)
    den := NewBigMatrix(1, 3, sliceToBigInt([]int64{3, 3, 2}))
    den, _ = EncryptMatrix(den, setting)
    corr := NewBigMatrix(1, 3, sliceToBigInt([]int64{2, 3, 2}))
    dec := t_decryptPoly(num, den, sks, setting)
    for i := 0; i < corr.cols; i += 1 {
        if corr.At(0,i).Cmp(dec.At(0,i)) != 0 {
            t.Errorf("error at %d, expected %d got %d", i, corr.At(0,i), dec.At(0,i))
        }
    }
}

func t_negate(a int64, p *big.Int) *big.Int {
    return big.NewInt(0).Sub(p, big.NewInt(a))
}

func TestMinPolyWorker(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    seq := NewBigMatrix(1, 4, []*big.Int{big.NewInt(51), big.NewInt(-79), big.NewInt(-125), big.NewInt(441)})
    seq, err = EncryptMatrix(seq, setting)
    if err != nil {t.Error(err)}
    rec_ord := 2
    inv4 := big.NewInt(1).ModInverse(big.NewInt(4), setting.pk.N)
    corr := NewBigMatrix(1, 3, []*big.Int{inv4, inv4, big.NewInt(1)})

    channels := create_chans(setting.n-1)
    returns := make([]chan BigMatrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        returns[i] = make(chan BigMatrix, 2)
    }

    go MinPolyWorker(seq, rec_ord, sks[setting.n-1], setting, channels, nil, returns[setting.n-1])
    for i := 0; i < setting.n-1; i += 1 {
        go MinPolyWorker(seq, rec_ord, sks[i], setting, nil, channels[i], returns[i])
    }
    for i := 0; i < 2; i += 1 {
        min_poly_num := <-returns[i]
        min_poly_den := <-returns[i]
        min_poly := t_decryptPoly(min_poly_num, min_poly_den, sks, setting)
        t_normalizePoly(min_poly, setting)
        if corr.cols != min_poly.cols {
            t.Errorf("min poly too long, expected %d got %d", corr.cols, min_poly.cols)
            for j := 0; j < min_poly.cols; j += 1 {
                t.Errorf("min poly coeff: %d\n", min_poly.At(0,j))
            }
        } else {
            for j := 0; j < corr.cols; j += 1 {
                if min_poly.At(0,j).Cmp(corr.At(0,j)) != 0 {
                    t.Errorf("wrong values in minpoly, expected %d got %d", corr.At(0,j), min_poly.At(0,j))
                }
            }
        }
    }
}

func t_normalizePoly(poly BigMatrix, setting Setting) {
    inv := new(big.Int)
    inv.ModInverse(poly.At(0,poly.cols-1), setting.pk.N)
    for i := 0; i < poly.cols; i += 1 {
        val := new(big.Int)
        val.Mul(inv, poly.At(0, i)).Mod(val, setting.pk.N)
        poly.Set(0, i, val)
    }
}

func TestMatrixMultiplicationWorker(t *testing.T) {
    A := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
    B := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 1, 2, 1, 2, 1, 2, 1}))
    AB_corr := MatMul(A, B)
    var setting Setting
    setting.n = 4
    sks, pk, _ := GenerateKeys(512, 1, setting.n)
    setting.pk = pk
    A, _ = EncryptMatrix(A, setting)
    B, _ = EncryptMatrix(B, setting)

    channels := create_chans(setting.n-1)
    return_channel := make(chan BigMatrix)

    go CentralMatrixMultiplicationWorker(A, B, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterMatrixMultiplicationWorker(A, B, sks[i], setting, channels[i], return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        AB := <-return_channel
        CompareEnc(AB, AB_corr, sks, setting, t)
    }
}

func TestSingularityTestWorker(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    sing := NewBigMatrix(4, 4, sliceToBigInt([]int64{1, 2, 3, 5,
                                                     4, 5, 6, 9,
                                                     2, 4, 6, 10,
                                                     7, 11, 15, 24}))
    sing, err = EncryptMatrix(sing, setting)
    if err != nil {t.Error(err)}
    
    non_sing := NewBigMatrix(4, 4, sliceToBigInt([]int64{1, 1, 0, 0,
                                                         2, 0, 1, 2,
                                                         0, 0, 1, 1,
                                                         1, 0, 1, 1}))
    non_sing, err = EncryptMatrix(non_sing, setting)
    if err != nil {t.Error(err)}

    channels := create_chans(setting.n-1)
    return_channel := make(chan bool)

    go CentralSingularityTestWorker(sing, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterSingularityTestWorker(sing, sks[i], setting, channels[i], return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        if !(<-return_channel) {
            t.Error("should be singular")
        }
    }

    go CentralSingularityTestWorker(non_sing, sks[setting.n-1], setting, channels, return_channel)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterSingularityTestWorker(non_sing, sks[i], setting, channels[i], return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        if <-return_channel {
            t.Error("should not be singular")
        }
    }
}

func TestCardinalityTestWorker(t *testing.T) {
    t.Run("below threshold", func (t *testing.T) {
        var setting Setting
        setting.n = 4
        sks, pk, err := GenerateKeys(512, 1, setting.n)
        if err != nil {t.Error(err)}
        setting.pk = pk
        setting.T = 8
        setting.m = 4
        all_items := make([][]int64, setting.n)
        all_items[0] = []int64{1,2,5,6}
        all_items[1] = []int64{1,2,10,11}
        all_items[2] = []int64{1,2,15,16}
        all_items[3] = []int64{1,2,18,19}
        
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go CentralCardinalityTestWorker(all_items[setting.n-1], sks[setting.n-1], setting, channels, return_channel)
        for i := 0; i < setting.n-1; i += 1 {
            go OuterCardinalityTestWorker(all_items[i], sks[i], setting, channels[i], return_channel)
        }

        for i := 0; i < setting.n; i += 1 {
            if !<-return_channel {
                t.Error("cardinality test is false despite below threshold")
            }
        }
    })

    t.Run("above threshold", func (t *testing.T) {
        var setting Setting
        setting.n = 4
        sks, pk, err := GenerateKeys(512, 1, setting.n)
        if err != nil {t.Error(err)}
        setting.pk = pk
        setting.T = 7
        setting.m = 6
        all_items := make([][]int64, setting.n)
        all_items[0] = []int64{1,2,3,4,5,6}
        all_items[1] = []int64{1,2,3,4,10,11}
        all_items[2] = []int64{1,2,3,4,15,16}
        all_items[3] = []int64{1,2,3,4,20,21}
        
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go CentralCardinalityTestWorker(all_items[setting.n-1], sks[setting.n-1], setting, channels, return_channel)
        for i := 0; i < setting.n-1; i += 1 {
            go OuterCardinalityTestWorker(all_items[i], sks[i], setting, channels[i], return_channel)
        }

        for i := 0; i < setting.n; i += 1 {
            if <-return_channel {
                t.Error("cardinality test is true despite above threshold")
            }
        }
    })
}

func TestIntersectionPoly(t *testing.T) {
    items := [][]int64{[]int64{1,3,4,5},
                       []int64{1,3,6,7},
                       []int64{1,3,8,9},
                       []int64{1,3,10,11}}
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {t.Error(err)}
    setting.pk = pk
    setting.T = 8
    roots := make([]BigMatrix, 4)
    for i := range items {
        roots[i] = PolyFromRoots(items[i], setting.pk.N)
    }
    channels := create_chans(setting.n)
    ret := make(chan BigMatrix)
    go CentralIntersectionPolyWorker(roots[setting.n-1], sks[setting.n-1], setting, channels, ret)
    for i := 0; i < setting.n-1; i += 1 {
        go OuterIntersectionPolyWorker(roots[i], sks[i], setting, channels[i], ret)
    }
    for i := 0; i < setting.n; i += 1 {
        v := <-ret
        j := 0
        for ; j < 2; j += 1 {
            if v.At(0,j).Cmp(big.NewInt(0)) != 0 {
                t.Errorf("root lost at %d", j+1)
            }
        }
        for ; j < v.cols; j += 1 {
            if v.At(0,j).Cmp(big.NewInt(0)) == 0 {
                t.Errorf("additional root at %d", j+1)
            }
        }
    }
}

func TestIntersection(t *testing.T) {
    var setting Setting
    setting.n = 4
    items := [][]int64{
        []int64{100,102,202,204,206},
        []int64{100,102,302,304,306},
        []int64{100,102,402,404,406},
        []int64{100,102,502,504,506}}
    no_shared := 2
    no_unique := 3
    setting.T = no_unique * setting.n
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk
    channels := create_chans(setting.n-1)
    return_channels := make([]chan []int64, setting.n)
    for i := 0; i < setting.n-1; i += 1 {
        return_channels[i] = make(chan []int64)
        go IntersectionWorker(items[i], sks[i], setting, false, nil, channels[i], return_channels[i])
    }
    return_channels[setting.n-1] = make(chan []int64)
    go IntersectionWorker(items[setting.n-1], sks[setting.n-1], setting, true, channels, nil, return_channels[setting.n-1])

    for i := 0; i < setting.n; i += 1 {
        shared := <-return_channels[i]
        if len(shared) != no_shared {
            t.Errorf("wrong number of shared elements; expected %d, got %d", no_shared, len(shared))
        } else {
            for j := 0; j < no_shared; j += 1 {
                if shared[j] != items[i][j] {
                    t.Errorf("shared item missed for party %d, expected %d, got %d", i, items[i][j], shared[j])
                }
            }
        }
        unique := <-return_channels[i]
        if len(unique) != no_unique {
            t.Errorf("wrong number of unique elements; expected %d, got %d", no_unique, len(unique))
        } else {
            for j := 0; j < no_unique; j += 1 {
                if unique[j] != items[i][j+no_shared] {
                    t.Errorf("unique item missed for party %d, expected %d, got %d", i, items[i][j+no_shared], unique[j])
                }
            }
        }
    }
}