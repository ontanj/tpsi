package tpsi

import (
    "testing"
    "math/big"
    gm "github.com/ontanj/generic-matrix"
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
    pk, sks, err := NewDJCryptosystem(4)
    if err != nil {t.Error(err)}
    setting.cs = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int)
    a, err := setting.cs.Encrypt(big.NewInt(20))
    if err != nil {t.Error(err)}

    go func() {
        return_channel <- CentralASSWorker(a, sks[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            return_channel <- OuterASSWorker(a, sks[i], setting, channels[i])
        }(i)
    }

    sum := big.NewInt(0)
    for i := 0; i < setting.n; i += 1 {
        val := <-return_channel
        sum.Add(sum, val)
        sum.Mod(sum, setting.cs.N())
    }
    if sum.Cmp(big.NewInt(20)) != 0 {
        t.Error("shares don't add up")
    }
}

func TestMultWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sks, err := NewDJCryptosystem(4)
    if err != nil {t.Error(err)}
    setting.cs = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan Ciphertext)
    a, err := setting.cs.Encrypt(big.NewInt(3))
    if err != nil {t.Error(err)}
    b, err := setting.cs.Encrypt(big.NewInt(4))
    if err != nil {t.Error(err)}

    go func() {
        return_channel <- CentralMultWorker(a, b, sks[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            return_channel <- OuterMultWorker(a, b, sks[i], setting, channels[i])
        }(i)
    }

    for i := 0; i < setting.n; i += 1 {
        prod_enc := <-return_channel
        // verify
        parts := make([]Partial_decryption, setting.n)
        for i, sk := range sks {
            part, err := sk.PartialDecrypt(prod_enc)
            if err != nil {t.Error(err)}
            parts[i] = part
        }
        prod, err := setting.cs.CombinePartials(parts)
        prod.Mod(prod, setting.cs.N())
        if err != nil {t.Error(err)}
        if prod.Cmp(big.NewInt(12)) != 0 {
            t.Error("multiplication error")
        }
    }
}

func TestZeroTestWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sks, err := NewDJCryptosystem(setting.n)
    if err != nil {panic(err)}
    setting.cs = pk

    t.Run("test 0", func (t *testing.T) {
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)
        cipher, err := setting.cs.Encrypt(big.NewInt(0))
        if err != nil {panic(err)}
        
        go func() {
            return_channel <- CentralZeroTestWorker(cipher, sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
            return_channel <- OuterZeroTestWorker(cipher, sks[i], setting, channels[i])
            }(i)
        }

        for i := 0; i < setting.n; i += 1 {
            if !(<-return_channel) {
                t.Error("zero test fail for 0")
            }
        }
    })
    
    t.Run("test non-0", func (t *testing.T) {
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)
        cipher, err := setting.cs.Encrypt(big.NewInt(131))
        if err != nil {panic(err)}

        go func() {
            return_channel <- CentralZeroTestWorker(cipher, sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                return_channel <- OuterZeroTestWorker(cipher, sks[i], setting, channels[i])
            }(i)
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
    pk, sks, err := NewDJCryptosystem(setting.n)
    if err != nil {panic(err)}
    setting.cs = pk
    
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int)

    cipher, err := setting.cs.Encrypt(big.NewInt(83))
    if err != nil {panic(err)}

    go func() {
        return_channel <- CentralDecryptionWorker(cipher, sks[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            return_channel <- OuterDecryptionWorker(cipher, sks[i], setting, channels[i])
        }(i)
    }

    for i := 0; i < setting.n; i += 1 {
        if (<-return_channel).Cmp(big.NewInt(83)) != 0 {
            t.Error("decryption error")
        }
    }
}

func t_decrypt(cipher *big.Int, sks []Secret_key, setting Setting) *big.Int {
    channels := create_chans(setting.n-1)
    return_channel := make(chan *big.Int, 4) // only read first return value
    go func() {
        return_channel <- CentralDecryptionWorker(cipher, sks[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            return_channel <- OuterDecryptionWorker(cipher, sks[i], setting, channels[i])
        }(i)
    }
    val := <-return_channel
    return val
}

func t_decryptPoly(num, den gm.Matrix, sks []Secret_key, setting Setting) []*big.Int {
    p := make([]*big.Int, num.Cols)
    for i := 0; i < num.Cols; i += 1 {
        num_enc, _ := decodeBI(num.At(0,i))
        num_val := t_decrypt(num_enc, sks, setting)
        den_enc, _ := decodeBI(den.At(0,i))
        den_val := t_decrypt(den_enc, sks, setting)
        den_val.ModInverse(den_val, setting.cs.N())
        p[i] = num_val.Mul(num_val, den_val).Mod(num_val, setting.cs.N())
    }
    return p
}

func TestPolynomialDivisionWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sksdj, err := NewDJCryptosystem(setting.n)
    sks := ConvertDJSKSlice(sksdj)
    if err != nil {t.Error(err)}
    setting.cs = pk
    divid, err := gm.NewMatrixFromInt(1, 5, []int{3, 6, 5, 2, 0})
    if err != nil {t.Error(err)}
    divis, err := gm.NewMatrixFromInt(1, 4, []int{1, 3, 2, 0})
    if err != nil {t.Error(err)}
    q := []int64{1, 1}
    r := []int64{2, 2}

    divid_enc, err := EncryptMatrix(divid, setting)
    if err != nil {t.Error(err)}
    divid_den, err := setting.cs.Encrypt(big.NewInt(1))
    if err != nil {t.Error(err)}
    divis_enc, err := EncryptMatrix(divis, setting)
    if err != nil {t.Error(err)}
    divis_den, err := setting.cs.Encrypt(big.NewInt(1))
    if err != nil {t.Error(err)}

    channels := create_chans(setting.n-1)

    validator := func(num gm.Matrix, den gm.Matrix, corr []int64) {
        dec := make([]*big.Int, num.Cols)
        var den_i *big.Int // denominator inverse
        
        // if denominator shared among all coefficients -> decrypt it
        if den.Cols == 1 {
            den_val, err := decodeBI(den.At(0, 0))
            if err != nil {t.Error(err)}
            den_i = t_decrypt(den_val, sks, setting)
            den_i.ModInverse(den_i, setting.cs.N())
        }
        
        // iterate over coefficients
        for j := 0; j < len(corr); j += 1 {
            // decrypt current denominator if not shared
            if den.Cols != 1 {
                den_val, err := decodeBI(den.At(0, j))
                if err != nil {t.Error(err)}
                den_i = t_decrypt(den_val, sks, setting)
                den_i.ModInverse(den_i, setting.cs.N())
            }
            num_val, err := decodeBI(num.At(0, j))
            if err != nil {t.Error(err)}
            dec[j] = t_decrypt(num_val, sks, setting) // decrypt current numerator
            dec[j].Mul(dec[j], den_i).Mod(dec[j], setting.cs.N()) // multiply numerator and denominator inverse
            if dec[j].Cmp(new(big.Int).SetInt64(corr[j])) != 0 {
                t.Errorf("error in polynomial division, expected %d got %d", corr[j], dec[j])
            }
        }
        if den.Cols > len(corr) {
            t.Error("exceeding coefficients")
        }
    }

    returns := []chan gm.Matrix{make(chan gm.Matrix), make(chan gm.Matrix, 4), make(chan gm.Matrix, 4), make(chan gm.Matrix)}
    
    go func() {
        qn, qd, rn, rd := PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[setting.n-1], setting, channels, nil)
        returns[setting.n-1] <- qn
        returns[setting.n-1] <- qd
        returns[setting.n-1] <- rn
        rd_ret, _ := gm.NewMatrix(1, 1, []interface{}{rd}, gm.Bigint{})
        returns[setting.n-1] <- rd_ret
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            qn, qd, rn, rd := PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[i], setting, nil, channels[i])
            returns[i] <- qn
            returns[i] <- qd
            returns[i] <- rn
            rd_ret, _ := gm.NewMatrix(1, 1, []interface{}{rd}, gm.Bigint{})
            returns[i] <- rd_ret
        }(i)
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

func TestAnotherPolynomialDivisionWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sksdj, err := NewDJCryptosystem(setting.n)
    sks := ConvertDJSKSlice(sksdj)
    if err != nil {t.Error(err)}
    setting.cs = pk
    divid, err := gm.NewMatrixFromInt(1, 4, []int{51, -79, -125, 441})
    if err != nil {t.Error(err)}
    divis, err := gm.NewMatrixFromInt(1, 3, []int{-6375, -12616, 50464})
    if err != nil {t.Error(err)}
    q := []*big.Int{new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-59), new(big.Int).ModInverse(big.NewInt(4), setting.cs.N())), setting.cs.N()), big.NewInt(441)}
    r := []*big.Int{new(big.Int).Mod(new(big.Int).Mul(big.NewInt(9918531), new(big.Int).ModInverse(big.NewInt(201856), setting.cs.N())), setting.cs.N()),
                    new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-1361367), new(big.Int).ModInverse(big.NewInt(50464), setting.cs.N())), setting.cs.N())}

    divid_enc, err := EncryptMatrix(divid, setting)
    if err != nil {t.Error(err)}
    divid_den, err := setting.cs.Encrypt(big.NewInt(1))
    if err != nil {t.Error(err)}
    divis_enc, err := EncryptMatrix(divis, setting)
    if err != nil {t.Error(err)}
    divis_den, err := setting.cs.Encrypt(big.NewInt(50464))
    if err != nil {t.Error(err)}

    channels := create_chans(setting.n-1)

    validator := func(num gm.Matrix, den gm.Matrix, corr []*big.Int) {
        dec := make([]*big.Int, num.Cols)
        var den_i *big.Int // denominator inverse
        
        // if denominator shared among all coefficients -> decrypt it
        if den.Cols == 1 {
            den_val, err := decodeBI(den.At(0, 0))
            if err != nil {t.Error(err)}
            den_i = t_decrypt(den_val, sks, setting)
            den_i.ModInverse(den_i, setting.cs.N())
        }
        
        // iterate over coefficients
        for j := 0; j < len(corr); j += 1 {
            // decrypt current denominator if not shared
            if den.Cols != 1 {
                den_val, err := decodeBI(den.At(0, j))
                if err != nil {t.Error(err)}
                den_i = t_decrypt(den_val, sks, setting)
                den_i.ModInverse(den_i, setting.cs.N())
            }
            num_val, err := decodeBI(num.At(0, j))
            if err != nil {t.Error(err)}
            dec[j] = t_decrypt(num_val, sks, setting) // decrypt current numerator
            dec[j].Mul(dec[j], den_i).Mod(dec[j], setting.cs.N()) // multiply numerator and denominator inverse
            if dec[j].Cmp(corr[j]) != 0 {
                t.Errorf("error in polynomial division, expected %d got %d", corr[j], dec[j])
            }
        }
        if den.Cols > len(corr) {
            t.Error("exceeding coefficients")
        }
    }

    returns := []chan gm.Matrix{make(chan gm.Matrix), make(chan gm.Matrix, 4), make(chan gm.Matrix, 4), make(chan gm.Matrix)}
    
    go func() {
        qn, qd, rn, rd := PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[setting.n-1], setting, channels, nil)
        returns[setting.n-1] <- qn
        returns[setting.n-1] <- qd
        returns[setting.n-1] <- rn
        rd_ret, _ := gm.NewMatrix(1, 1, []interface{}{rd}, gm.Bigint{})
        returns[setting.n-1] <- rd_ret
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            qn, qd, rn, rd := PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[i], setting, nil, channels[i])
            returns[i] <- qn
            returns[i] <- qd
            returns[i] <- rn
            rd_ret, _ := gm.NewMatrix(1, 1, []interface{}{rd}, gm.Bigint{})
            returns[i] <- rd_ret
        }(i)
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
    pk, djsks, err := NewDJCryptosystem(4)
    sks := ConvertDJSKSlice(djsks)
    if err != nil {t.Error(err)}
    setting.cs = pk

    a_num, err := gm.NewMatrixFromInt(1, 3, []int{3, 9, 3})
    if err != nil {t.Error(err)}
    a_num, err = EncryptMatrix(a_num, setting)
    if err != nil {t.Error(err)}
    a_den, err := gm.NewMatrixFromInt(1, 3, []int{1, 4, 2})
    if err != nil {t.Error(err)}
    a_den, err = EncryptMatrix(a_den, setting)
    if err != nil {t.Error(err)}

    b_num, err := gm.NewMatrixFromInt(1, 2, []int{4, 4})
    if err != nil {t.Error(err)}
    b_num, err = EncryptMatrix(b_num, setting)
    if err != nil {t.Error(err)}
    b_den, err := gm.NewMatrixFromInt(1, 2, []int{3, 1})
    if err != nil {t.Error(err)}
    b_den, err = EncryptMatrix(b_den, setting)
    if err != nil {t.Error(err)}
    
    corr := []int64{4, 15, 11, 6}

    channels := create_chans(setting.n-1)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[setting.n-1], setting, channels, nil)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < len(corr); k += 1 {
            if p[k].Cmp(new(big.Int).SetInt64(corr[k])) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p[k], corr[k])
            }
        }
        return_channel <- 0
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolyMult(a_num, a_den, b_num, b_den, sks[j], setting, nil, channels[j])
            if err != nil {t.Error(err)}
            p := t_decryptPoly(p_num, p_den, sks, setting)
            for k := 0; k < len(corr); k += 1 {
                if p[k].Cmp(new(big.Int).SetInt64(corr[k])) != 0 {
                    t.Errorf("non-matching value at %d, expected %d got %d", k, corr[k], p[k])
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
    pk, djsks, err := NewDJCryptosystem(4)
    sks := ConvertDJSKSlice(djsks)
    if err != nil {t.Error(err)}
    setting.cs = pk

    a_num, err := gm.NewMatrixFromInt(1, 2, []int{5, 4})
    if err != nil {t.Error(err)}
    a_num, err = EncryptMatrix(a_num, setting)
    if err != nil {t.Error(err)}
    a_den, err := gm.NewMatrixFromInt(1, 2, []int{2, 3})
    if err != nil {t.Error(err)}
    a_den, err = EncryptMatrix(a_den, setting)
    if err != nil {t.Error(err)}

    b_num, err := gm.NewMatrixFromInt(1, 2, []int{1, 2})
    if err != nil {t.Error(err)}
    b_num, err = EncryptMatrix(b_num, setting)
    if err != nil {t.Error(err)}
    b_den, err := gm.NewMatrixFromInt(1, 2, []int{2, 6})
    if err !=   nil {t.Error(err)}
    b_den, err = EncryptMatrix(b_den, setting)
    if err != nil {t.Error(err)}

    corr := []int64{2, 1}

    channels := create_chans(setting.n-1)
    return_channel := make(chan int)
    go func() {
        p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[setting.n-1], setting, channels, nil)
        if err != nil {t.Error(err)}
        p := t_decryptPoly(p_num, p_den, sks, setting)
        for k := 0; k < len(corr); k += 1 {
            if p[k].Cmp(new(big.Int).SetInt64(corr[k])) != 0 {
                t.Errorf("non-matching value at %d, got %d expected %d", k, p[k], corr[k])
            }
        }
        return_channel <- 0
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(j int) {
            p_num, p_den, err := PolySub(a_num, a_den, b_num, b_den, sks[j], setting, nil, channels[j])
            if err != nil {t.Error(err)}
            p := t_decryptPoly(p_num, p_den, sks, setting)
            for k := 0; k < len(corr); k += 1 {
                if p[k].Cmp(new(big.Int).SetInt64(corr[k])) != 0 {
                    t.Errorf("non-matching value at %d, expected %d got %d", k, corr[k], p[k])
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
    pk, djsks, _ := NewDJCryptosystem(4)
    sks := ConvertDJSKSlice(djsks)
    setting.cs = pk
    num, _ := gm.NewMatrixFromInt(1, 3, []int{6, 9, 4})
    num, _ = EncryptMatrix(num, setting)
    den, _ := gm.NewMatrixFromInt(1, 3, []int{3, 3, 2})
    den, _ = EncryptMatrix(den, setting)
    corr := []int64{2, 3, 2}
    dec := t_decryptPoly(num, den, sks, setting)
    for i := 0; i < len(corr); i += 1 {
        if new(big.Int).SetInt64(corr[i]).Cmp(dec[i]) != 0 {
            t.Errorf("error at %d, expected %d got %d", i, corr[i], dec[i])
        }
    }
}

func t_negate(a int64, p *big.Int) *big.Int {
    return big.NewInt(0).Sub(p, big.NewInt(a))
}

func TestMinPolyWorker(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, djsks, err := NewDJCryptosystem(setting.n)
    sks := ConvertDJSKSlice(djsks)
    if err != nil {t.Error(err)}
    setting.cs = pk
    seq, err := gm.NewMatrix(1, 4, []interface{}{big.NewInt(51), big.NewInt(-79), big.NewInt(-125), big.NewInt(441)}, gm.Bigint{})
    if err != nil {t.Error(err)}
    seq, err = EncryptMatrix(seq, setting)
    if err != nil {t.Error(err)}
    rec_ord := 2
    inv4 := new(big.Int).ModInverse(big.NewInt(4), setting.cs.N())
    corr := []*big.Int{inv4, inv4, big.NewInt(1)}

    channels := create_chans(setting.n-1)
    returns := make([]chan gm.Matrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        returns[i] = make(chan gm.Matrix, 2)
    }

    go func() {
        num, den := MinPolyWorker(seq, rec_ord, sks[setting.n-1], setting, channels, nil)
        returns[setting.n-1] <- num
        returns[setting.n-1] <- den
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            num, den := MinPolyWorker(seq, rec_ord, sks[i], setting, nil, channels[i])
            returns[i] <- num
            returns[i] <- den
        }(i)
    }
    for i := setting.n-2; i < setting.n; i += 1 {
        min_poly_num := <-returns[i]
        min_poly_den := <-returns[i]
        min_poly := t_decryptPoly(min_poly_num, min_poly_den, sks, setting)
        t_normalizePoly(min_poly, setting)
        if len(corr) != len(min_poly) {
            t.Errorf("min poly too long, expected %d got %d", len(corr), len(min_poly))
            for j := 0; j < len(min_poly); j += 1 {
                t.Errorf("min poly coeff: %d\n", min_poly[j])
            }
        } else {
            for j := 0; j < len(corr); j += 1 {
                if min_poly[j].Cmp(corr[j]) != 0 {
                    t.Errorf("wrong values in minpoly, expected %d got %d", corr[j], min_poly[j])
                }
            }
        }
    }
}

func t_normalizePoly(poly []*big.Int, setting Setting) {
    inv := new(big.Int)
    inv.ModInverse(poly[len(poly)-1], setting.cs.N())
    for i := 0; i < len(poly); i += 1 {
        val := new(big.Int)
        val.Mul(inv, poly[i])
        poly[i].Set(val).Mod(val, setting.cs.N())
    }
}

func TestMatrixMultiplicationWorker(t *testing.T) {
    A, _ := gm.NewMatrixFromInt(3, 3, []int{1, 2, 3, 4, 5, 6, 7, 8, 9})
    B, _ := gm.NewMatrixFromInt(3, 3, []int{1, 2, 1, 2, 1, 2, 1, 2, 1})
    AB_corr, _ := A.Multiply(B)
    var setting Setting
    setting.n = 4
    pk, djsks, _ := NewDJCryptosystem(setting.n)
    sks := ConvertDJSKSlice(djsks)
    setting.cs = pk
    A, _ = EncryptMatrix(A, setting)
    B, _ = EncryptMatrix(B, setting)

    channels := create_chans(setting.n-1)
    return_channel := make(chan gm.Matrix)

    go func() {
        return_channel <- CentralMatrixMultiplicationWorker(A, B, sks[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            return_channel <- OuterMatrixMultiplicationWorker(A, B, sks[i], setting, channels[i])
        }(i)
    }

    for i := 0; i < setting.n; i += 1 {
        AB := <-return_channel
        CompareEnc(AB, AB_corr, sks, setting, t)
    }
}

func TestSingularityTestWorker(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sks, err := NewDJCryptosystem(4)
    if err != nil {t.Error(err)}
    setting.cs = pk

    t.Run("singular matrix", func(t *testing.T) {
        sing, err := gm.NewMatrixFromInt(4, 4, []int{1, 2, 3, 5,
                                                4, 5, 6, 9,
                                                2, 4, 6, 10,
                                                7, 11, 15, 24})
        if err != nil {t.Error(err)}
        sing, err = EncryptMatrix(sing, setting)
        if err != nil {t.Error(err)}
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go func() {
            return_channel <- CentralSingularityTestWorker(sing, sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                return_channel <- OuterSingularityTestWorker(sing, sks[i], setting, channels[i])
            }(i)
        }

        for i := 0; i < setting.n; i += 1 {
            if !(<-return_channel) {
                t.Error("should be singular")
            }
        }
    })

    t.Run("non-singular matrix", func(t *testing.T) {
        non_sing, err := gm.NewMatrixFromInt(4, 4, []int{1, 1, 0, 0,
                                                    2, 0, 1, 2,
                                                    0, 0, 1, 1,
                                                    1, 0, 1, 1})
        if err != nil {t.Error(err)}
        non_sing, err = EncryptMatrix(non_sing, setting)
        if err != nil {t.Error(err)}
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go func () {
            return_channel <- CentralSingularityTestWorker(non_sing, sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                return_channel <- OuterSingularityTestWorker(non_sing, sks[i], setting, channels[i])
            }(i)
        }

        for i := 0; i < setting.n; i += 1 {
            if <-return_channel {
                t.Error("should not be singular")
            }
        }
    })
}

func TestCardinalityTestWorker(t *testing.T) {
    t.Run("below threshold", func (t *testing.T) {
        var setting Setting
        setting.n = 4
        pk, sks, err := NewDJCryptosystem(setting.n)
        if err != nil {t.Error(err)}
        setting.cs = pk
        setting.T = 8
        setting.m = 4
        all_items := make([][]uint64, setting.n)
        all_items[0] = []uint64{1,2,5,6}
        all_items[1] = []uint64{1,2,10,11}
        all_items[2] = []uint64{1,2,15,16}
        all_items[3] = []uint64{1,2,18,19}
        
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go func() {
            return_channel <- CentralCardinalityTestWorker(all_items[setting.n-1], sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                return_channel <- OuterCardinalityTestWorker(all_items[i], sks[i], setting, channels[i])
            }(i)
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
        pk, sks, err := NewDJCryptosystem(setting.n)
        if err != nil {t.Error(err)}
        setting.cs = pk
        setting.T = 7
        setting.m = 6
        all_items := make([][]uint64, setting.n)
        all_items[0] = []uint64{1,2,3,4,5,6}
        all_items[1] = []uint64{1,2,3,4,10,11}
        all_items[2] = []uint64{1,2,3,4,15,16}
        all_items[3] = []uint64{1,2,3,4,20,21}
        
        channels := create_chans(setting.n-1)
        return_channel := make(chan bool)

        go func() {
            return_channel <- CentralCardinalityTestWorker(all_items[setting.n-1], sks[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                return_channel <- OuterCardinalityTestWorker(all_items[i], sks[i], setting, channels[i])
            }(i)
        }

        for i := 0; i < setting.n; i += 1 {
            if <-return_channel {
                t.Error("cardinality test is true despite above threshold")
            }
        }
    })
}

func TestIntersectionPoly(t *testing.T) {
    items := [][]uint64{[]uint64{1,3,4,5},
                       []uint64{1,3,6,7},
                       []uint64{1,3,8,9},
                       []uint64{1,3,10,11}}
    var setting Setting
    setting.n = 4
    pk, sks, err := NewDJCryptosystem(setting.n)
    if err != nil {t.Error(err)}
    setting.cs = pk
    setting.T = 8
    roots := make([]gm.Matrix, 4)
    for i := range items {
        roots[i] = PolyFromRoots(items[i], setting.cs.N())
    }
    channels := create_chans(setting.n)
    ret := make(chan gm.Matrix)
    go func() {
        vs, _ := CentralIntersectionPolyWorker(roots[setting.n-1], sks[setting.n-1], setting, channels)
        ret <- vs
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            vs, _ := OuterIntersectionPolyWorker(roots[i], sks[i], setting, channels[i])
            ret <- vs
        }(i)
    }
    for i := 0; i < setting.n; i += 1 {
        v := <-ret
        j := 0
        for ; j < 2; j += 1 {
            v_val, err := decodeBI(v.At(0,j))
            if err != nil {t.Error(err)}
            if v_val.Cmp(big.NewInt(0)) != 0 {
                t.Errorf("root lost at %d", j+1)
            }
        }
        for ; j < v.Cols; j += 1 {
            v_val, err := decodeBI(v.At(0,j))
            if err != nil {t.Error(err)}
            if v_val.Cmp(big.NewInt(0)) == 0 {
                t.Errorf("additional root at %d", j+1)
            }
        }
    }
}

func TestIntersection(t *testing.T) {
    var setting Setting
    setting.n = 4
    items := [][]uint64{
        []uint64{100,102,202,204,206},
        []uint64{100,102,302,304,306},
        []uint64{100,102,402,404,406},
        []uint64{100,102,502,504,506}}
    no_shared := 2
    no_unique := 3
    setting.T = no_unique * setting.n
    pk, sks, err := NewDJCryptosystem(setting.n)
    if err != nil {panic(err)}
    setting.cs = pk
    channels := create_chans(setting.n-1)
    return_channels := make([]chan []uint64, setting.n)
    for i := 0; i < setting.n-1; i += 1 {
        return_channels[i] = make(chan []uint64)
        go func(i int) {
            shared, unique := IntersectionWorker(items[i], sks[i], setting, false, nil, channels[i])
            return_channels[i] <- shared
            return_channels[i] <- unique
        }(i)
    }
    return_channels[setting.n-1] = make(chan []uint64)
    go func() {
        shared, unique := IntersectionWorker(items[setting.n-1], sks[setting.n-1], setting, true, channels, nil)
        return_channels[setting.n-1] <- shared
        return_channels[setting.n-1] <- unique
    }()

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

func TestTPSIdiff(t *testing.T) {
    var setting Setting
    setting.n = 3
    setting.m = 7
    items := [][]uint64{[]uint64{2,4,6,8,10,12,14},
                       []uint64{2,4,6,8,10,16,18},
                       []uint64{2,4,6,8,12,20,22}}
    pk, sks, err := NewDJCryptosystem(setting.n)
    if err != nil {t.Error(err)}
    setting.cs = pk
    t.Run("pass cardinality test", func(t *testing.T) {
        no_unique := 3
        no_shared := 4
        setting.T = 7
        channels := create_chans(setting.n-1)
        returns := make([]chan []uint64, setting.n)
        for i := 0; i < setting.n-1; i += 1 {
            returns[i] = make(chan []uint64)
            go func(i int) {
                sh, uq := TPSIdiffWorker(items[i], sks[i], setting, false, nil, channels[i])
                returns[i] <- sh
                returns[i] <- uq
            }(i)
        }
        returns[setting.n-1] = make(chan []uint64)
        go func() {
            sh, uq := TPSIdiffWorker(items[setting.n-1], sks[setting.n-1], setting, true, channels, nil)
            returns[setting.n-1] <- sh
            returns[setting.n-1] <- uq
        }()
        for i := 0; i < setting.n; i += 1 {
            shared := <-returns[i]
            if shared == nil {
                t.Error("cardinality test failed")
                continue
            }
            unique := <-returns[i]
            if len(shared) != no_shared {
                t.Errorf("wrong number of shared items, expected %d, got %d", no_shared, len(shared))
            }
            if len(unique) != no_unique {
                t.Errorf("wrong number of unique items, expected %d, got %d", no_unique, len(unique))
            }
            for j := 0; j < no_shared; j += 1 {
                if shared[j] != items[i][j] {
                    t.Errorf("unexpected element in shared, expected %d, got %d", items[i][j], shared[j])
                }
            }
            for j := 0; j < no_unique; j += 1 {
                if unique[j] != items[i][j+no_shared] {
                    t.Errorf("unexpected element in unique, expected %d, got %d", items[i][j+no_shared], unique[j])
                }
            }
        }
    })
    t.Run("fail cardinality test", func(t *testing.T) {
        setting.T = 6
        channels := create_chans(setting.n-1)
        returns := make([]chan []uint64, setting.n)
        for i := 0; i < setting.n-1; i += 1 {
            returns[i] = make(chan []uint64)
            go func(i int) {
                sh, uq := TPSIdiffWorker(items[i], sks[i], setting, false, nil, channels[i])
                returns[i] <- sh
                returns[i] <- uq
            }(i)
        }
        returns[setting.n-1] = make(chan []uint64)
        go func() {
            sh, uq := TPSIdiffWorker(items[setting.n-1], sks[setting.n-1], setting, true, channels, nil)
            returns[setting.n-1] <- sh
            returns[setting.n-1] <- uq
        }()
        for i := 0; i < setting.n; i += 1 {
            shared := <-returns[i]
            if shared != nil {
                t.Error("cardinality test passed")
                <-returns[i]
            }
        }
    })
}

func TestEncryptedZeroMatrix(t *testing.T) {
    var setting Setting
    setting.n = 4
    pk, sks, _ := NewDJCryptosystem(setting.n)
    setting.cs = pk
    l := 4
    randomizers := make([]*big.Int, l)
    for i := range randomizers {
        randomizers[i], _ = SampleInt(setting.cs.N())
    }
    m, _ := EncryptedFixedZeroMatrix(1, l, randomizers, setting)
    channels := create_chans(setting.n-1)
    ret := make(chan *big.Int)
    for i := 0; i < m.Cols; i += 1 {
        v, _ := decodeBI(m.At(0, i))
        go func() {
            u := CentralDecryptionWorker(v, sks[setting.n-1], setting, channels)
            ret <- u
        }()
        for j := 0; j < setting.n-1; j += 1 {
            go func(j int) {
                OuterDecryptionWorker(v, sks[j], setting, channels[j])
            }(j)
        }
        if (<-ret).Cmp(big.NewInt(0)) != 0 {
            t.Error("zero matrix != 0")
        }
    }
}
