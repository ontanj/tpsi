package tpsi

import (
    "testing"
    "math/big"
    "github.com/niclabs/tcpaillier"
)

func TestASSWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(20), setting)
    if err != nil {t.Error(err)}

    go CentralASSWorker(a, sks[0], setting, mask_channel, masks_channel, dec_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go ASSWorker(a, sks[i], setting, mask_channel, masks_channel, dec_channel, return_channel)
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
    
    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(3), setting)
    if err != nil {t.Error(err)}
    b, err := EncryptValue(big.NewInt(4), setting)
    if err != nil {t.Error(err)}

    go CentralMultWorker(a, b, sks[0], setting, mask_channel, masks_channel, dec_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go MultWorker(a, b, sks[i], setting, mask_channel, masks_channel, dec_channel, return_channel)
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

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    return_channel := make(chan bool)

    t.Run("test 0", func (t *testing.T) {
        cipher, err := EncryptValue(big.NewInt(0), setting)
        if err != nil {panic(err)}

        go CentralZeroTestWorker(cipher, sks[0], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
        for i := 1; i < setting.n; i += 1 {
            go ZeroTestWorker(cipher, sks[i], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
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

        go CentralZeroTestWorker(cipher, sks[0], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
        for i := 1; i < setting.n; i += 1 {
            go ZeroTestWorker(cipher, sks[i], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
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
    
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)

    cipher, err := EncryptValue(big.NewInt(83), setting)
    if err != nil {panic(err)}

    go CentralDecryptionWorker(cipher, sks[0], setting, dec_channel, shares_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go DecryptionWorker(cipher, sks[i], setting, dec_channel, shares_channel, return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        if (<-return_channel).Cmp(big.NewInt(83)) != 0 {
            t.Error("decryption error")
        }
    }
}

func t_decrypt(cipher *big.Int, sks []*tcpaillier.KeyShare, setting Setting) *big.Int {
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int, 4)
    go CentralDecryptionWorker(cipher, sks[0], setting, dec_channel, shares_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go DecryptionWorker(cipher, sks[i], setting, dec_channel, shares_channel, return_channel)
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

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    mult_channel := make(chan *big.Int)
    sub_channel := make(chan BigMatrix)
    
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

    returns := make([]chan BigMatrix, 4)
    returns[0] = make(chan BigMatrix, 4)
    returns[1] = make(chan BigMatrix, 4)
    returns[2] = make(chan BigMatrix, 100) // discard these messages
    returns[3] = make(chan BigMatrix, 100) // discard these messages
    
    go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[0], setting, true, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[0])
    for i := 1; i < setting.n; i += 1 {
        go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[i], setting, false, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[i])
    }
    
    for i := 0; i < 2; i += 1 {
        select {
        case qn := <-returns[0]:
            validator(qn, <-returns[0], q)
            rn :=  <-returns[0]
            validator(rn, <-returns[0], r)
        case qn := <-returns[1]:
            validator(qn, <-returns[1], q)
            rn := <-returns[1]
            validator(rn, <-returns[1], r)
        }
    }
}

func TestPolyMult(t *testing.T) {
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

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[0], setting, true, mask_channel, masks_channel, dec_channel)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < corr.cols; k += 1 {
            if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p.At(0,k), corr.At(0,k))
            }
        }
        return_channel <- 0
    }()
    for i := 1; i < setting.n; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[j], setting, false, mask_channel, masks_channel, dec_channel)
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

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[0], setting, true, mask_channel, masks_channel, dec_channel)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < corr.cols; k += 1 {
            if p.At(0,k).Cmp(corr.At(0,k)) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p.At(0,k), corr.At(0,k))
            }
        }
        return_channel <- 0
    }()
    for i := 1; i < setting.n; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[j], setting, false, mask_channel, masks_channel, dec_channel)
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

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    mult_channel := make(chan *big.Int)
    sub_channel := make(chan BigMatrix)
    returns := make([]chan BigMatrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        returns[i] = make(chan BigMatrix, 2)
    }

    go MinPolyWorker(seq, rec_ord, sks[0], setting, true, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[0])
    for i := 1; i < setting.n; i += 1 {
        go MinPolyWorker(seq, rec_ord, sks[i], setting, false, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[i])
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

func TestMatrixMultiplicationWorkers(t *testing.T) {
    A := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9}))
    B := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 1, 2, 1, 2, 1, 2, 1}))
    AB_corr := MatMul(A, B)
    var setting Setting
    setting.n = 4
    sks, pk, _ := GenerateKeys(512, 1, setting.n)
    setting.pk = pk
    A, _ = EncryptMatrix(A, setting)
    B, _ = EncryptMatrix(B, setting)

    mats_channels := make([]chan BigMatrix, setting.n-1)
    dec_channels := make([]chan PartialMatrix, setting.n-1)
    return_channel := make(chan BigMatrix)

    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] = make(chan BigMatrix)
        dec_channels[i] = make(chan PartialMatrix)
        go MatrixMultiplicationWorker(A, B, sks[i], setting, mats_channels[i], dec_channels[i], return_channel)
    }
    go CentralMatrixMultiplicationWorker(A, B, sks[setting.n-1], setting, mats_channels, dec_channels, return_channel)

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
    sing := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 2, 3, 4, 5, 6, 2, 4, 6}))
    sing, err = EncryptMatrix(sing, setting)
    if err != nil {t.Error(err)}
    
    non_sing := NewBigMatrix(3, 3, sliceToBigInt([]int64{1, 1, 0, 2, 0, 1, 0, 0, 1}))
    non_sing, err = EncryptMatrix(non_sing, setting)
    if err != nil {t.Error(err)}

    mats_channels := make([]chan BigMatrix, setting.n-1)
    pm_channels := make([]chan PartialMatrix, setting.n-1)
    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    mult_channel := make(chan *big.Int)
    sub_channel := make(chan BigMatrix)
    return_channel := make(chan bool)

    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] = make(chan BigMatrix)
        pm_channels[i] = make(chan PartialMatrix)
        go SingularityTestWorker(sing, sks[i], setting, mats_channels[i], pm_channels[i], mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, return_channel)
    }
    go CentralSingularityTestWorker(sing, sks[setting.n-1], setting, mats_channels, pm_channels, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, return_channel)

    for i := 0; i < setting.n; i += 1 {
        if !(<-return_channel) {
            t.Error("should be singular")
        }
    }

    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] = make(chan BigMatrix)
        pm_channels[i] = make(chan PartialMatrix)
        go SingularityTestWorker(non_sing, sks[i], setting, mats_channels[i], pm_channels[i], mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, return_channel)
    }
    go CentralSingularityTestWorker(non_sing, sks[setting.n-1], setting, mats_channels, pm_channels, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, return_channel)

    for i := 0; i < setting.n; i += 1 {
        if <-return_channel {
            t.Error("should not be singular")
        }
    }
}
