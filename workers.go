package tpsi

import (
    "math/big"
    "fmt"
    gm "github.com/ontanj/generic-matrix"
)

func CentralASSWorker(a Ciphertext, sk Secret_key, setting AHE_setting, channels []chan interface{}) *big.Int {
    self := setting.Parties()-1

    // step 1: sample d
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}
    
    // receive all_d
    all_d := make([]Ciphertext, setting.Parties())
    all_d[self] = d_enc
    for i := 0; i < self; i += 1 {
        all_d[i] = (<-channels[i]).(Ciphertext)
    }

    // send all_d
    for i := 0; i < self; i += 1 {
        channels[i] <- all_d
    }

    // step 5: mask and decrypt
    e_partial, err := SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // receive e_parts
    e_parts := make([]Partial_decryption, setting.Parties())
    e_parts[self] = e_partial
    for i := 0; i < setting.Parties()-1; i += 1 {
        e_parts[i] = (<-channels[i]).(Partial_decryption)
    }

    e, err := setting.AHE_cryptosystem().CombinePartials(e_parts)
    if err != nil {
        panic(err)
    }

    // step 7: assign share
    a_share := SecretShare(d_plain, e, setting)
    return a_share
}

func OuterASSWorker(a Ciphertext, sk Secret_key, setting AHE_setting, channel chan interface{}) *big.Int {
    
    // step 1: sample d
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}

    channel <- d_enc
    
    // receive all_ds
    all_d := (<-channel).([]Ciphertext)
    
    // step 5: mask and decrypt
    e_partial, err := SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // broadcast e_partial
    channel <- e_partial
    
    // step 7: assign share
    a_share := NegateValue(d_plain, setting)
    return a_share
}

func CentralMultWorker(a, b Ciphertext, sk Secret_key, setting AHE_setting, channels []chan interface{}) Ciphertext {
    self := setting.Parties()-1

    a_share := CentralASSWorker(a, sk, setting, channels)

    // step 2: partial multiplication
    prod, err := setting.AHE_cryptosystem().Scale(b, a_share)
    if err != nil {panic(err)}

    // receive partial_prods
    partial_prods := make([]Ciphertext, setting.Parties())
    partial_prods[self] = prod
    for i := 0; i < self; i += 1 {
        partial_prods[i] = (<-channels[i]).(Ciphertext)
    }

    // send partial_prods
    for i := 0; i < self; i += 1 {
        channels[i] <- partial_prods
    }

    // step 6: sum partials
    sum, err := SumSlice(partial_prods, setting)
    if err != nil {panic(err)}
    
    return sum
}

func OuterMultWorker(a, b Ciphertext, sk Secret_key, setting AHE_setting, channel chan interface{}) Ciphertext {
    
    a_share := OuterASSWorker(a, sk, setting, channel)
    
    // step 2: partial multiplication    
    prod, err := setting.AHE_cryptosystem().Scale(b, a_share)
    if err != nil {panic(err)}

    // broadcast prod
    channel <- prod

    // receive partial_prods
    partial_prods := (<-channel).([]Ciphertext)

    // step 6: sum partials
    sum, err := SumSlice(partial_prods, setting)
    if err != nil {panic(err)}
    
    return sum
}

func CentralDecryptionWorker(cipher Ciphertext, sk Secret_key, setting AHE_setting, channels []chan interface{}) *big.Int {
    self := setting.Parties()-1
    partial, err := sk.PartialDecrypt(cipher)
    if err != nil {panic(err)}

    ds := make([]Partial_decryption, setting.Parties())
    ds[self] = partial

    for i := 0; i < self; i += 1 {
        ds[i] = (<-channels[i]).(Partial_decryption)
    }

    for i := 0; i < self; i += 1 {
        channels[i] <- ds
    }
    
    plain, err := setting.AHE_cryptosystem().CombinePartials(ds)
    if err != nil {panic(err)}
    
    return plain
}

func OuterDecryptionWorker(cipher Ciphertext, sk Secret_key, setting AHE_setting, channel chan interface{}) *big.Int {
    partial, err := sk.PartialDecrypt(cipher)
    if err != nil {panic(err)}

    channel <- partial

    ds := (<-channel).([]Partial_decryption)

    plain, err := setting.AHE_cryptosystem().CombinePartials(ds)
    if err != nil {panic(err)}

    return plain
}

func CentralZeroTestWorker(a Ciphertext, sk Secret_key, setting AHE_setting, channels []chan interface{}) bool {
    self := setting.Parties()-1
    
    plain_mask, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}

    mask, err := setting.AHE_cryptosystem().Encrypt(plain_mask)
    if err != nil {panic(err)}
    
    masks := make([]Ciphertext, setting.Parties())
    masks[self] = mask
    for i := 0; i < self; i += 1 {
        masks[i] = (<-channels[i]).(Ciphertext)
    }

    sum, err := SumSlice(masks, setting)
    if err != nil {panic(err)}
    
    for i := 0; i < self; i += 1 {
        channels[i] <- sum
    }

    pred_enc := CentralMultWorker(a, sum, sk, setting, channels)

    pred := CentralDecryptionWorker(pred_enc, sk, setting, channels)

    return pred.Cmp(big.NewInt(0)) == 0    
}

func OuterZeroTestWorker(a Ciphertext, sk Secret_key, setting AHE_setting, channel chan interface{}) bool {

    plain_mask, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}

    mask, err := setting.AHE_cryptosystem().Encrypt(plain_mask)
    if err != nil {panic(err)}

    channel <- mask

    sum := (<-channel).(Ciphertext)

    pred_enc := OuterMultWorker(a, sum, sk, setting, channel)

    pred := OuterDecryptionWorker(pred_enc, sk, setting, channel)

    return pred.Cmp(big.NewInt(0)) == 0    
}

// returns 4 slices through return_channel:
//  * q numerator
//  * q denominator
//  * r numerator
//  * r denominator (slice of size 1 as all coefficents share denominator)
func PolynomialDivisionWorker(a, b gm.Matrix, a_den, b_den Ciphertext, sk Secret_key, setting AHE_setting, channels []chan interface{}, channel chan interface{}) (gm.Matrix, gm.Matrix, gm.Matrix, Ciphertext) {
    zeroTest := func (val Ciphertext) bool {
        if channels != nil {
            return CentralZeroTestWorker(val, sk, setting, channels)
        } else {
            return OuterZeroTestWorker(val, sk, setting, channel)
        }
    }
    multiply := func (a, b Ciphertext) Ciphertext {
        if channels != nil {
            return CentralMultWorker(a, b, sk, setting, channels)
        } else {
            return OuterMultWorker(a, b, sk, setting, channel)
        }
    }
    space := a.Space
    var la int // degree of dividend
    for la = a.Cols-1; la >= 0; la -= 1 { // find degree of divisor
        zero_t, err := decodeBI(a.At(0,la))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    var lb int // degree of divisor
    for lb = b.Cols-1; lb >= 0; lb -= 1 { // find degree of divisor
        zero_t, err := decodeBI(b.At(0,lb))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    ql := 1+la-lb
    randomizers := exchangeRandomizers(channels, channel, 2*ql, setting.AHE_cryptosystem().N())
    a_num := a
    q_num, err := EncryptedFixedZeroMatrix(1, ql, randomizers[:ql], setting)
    if err != nil {panic(err)}
    q_den, err := EncryptedFixedOneMatrix(1, ql, randomizers[ql:], setting)
    if err != nil {panic(err)}

    for i := la; i >= lb; i -= 1 { // start at highest degree coefficient, go until dividend smaller than divisor
        // skip 0 coefficents
        zero_t, err := decodeBI(a_num.At(0,i))
        if err != nil {panic(err)}
        if zeroTest(zero_t) {
            continue
        }

        pos := i-lb // entry in q at pos

        // q numerator: b_den * a_num
        a_val, err := decodeBI(a_num.At(0, i))
        if err != nil {panic(err)}
        num := multiply(a_val, b_den)
        q_num.Set(0, pos, num)

        // q denominator: b_num * a_den
        b_val, err := decodeBI(b.At(0, lb))
        if err != nil {panic(err)}
        den := multiply(b_val, a_den)
        q_den.Set(0, pos, den)

        // p = q_val * b
        p_num, err := gm.NewMatrix(1, lb, nil, a.Space) // partial result, size is degree of (partial) dividend - 1 = i , skip highest coefficient as it is cancelling
        if err != nil {panic(err)}
        for j := 0; j < lb; j += 1 {
            b_val, err :=decodeBI( b.At(0, j))
            if err != nil {panic(err)}
            val := multiply(num, b_val)
            p_num.Set(0, j, val)
        }
        p_den := multiply(den, b_den)

        // make common denominator for p and a
        r_num, err := gm.NewMatrix(1, i, nil, space)
        if err != nil {panic(err)}
        for i := 0; i < r_num.Cols; i += 1 {
            a_val, err := decodeBI(a_num.At(0, i))
            if err != nil {panic(err)}
            val := multiply(a_val, p_den)
            r_num.Set(0, i, val)
        }
        for i := 0; i < p_num.Cols; i += 1 {
            p_val, err := decodeBI(p_num.At(0, i))
            if err != nil {panic(err)}
            val := multiply(p_val, a_den)
            p_num.Set(0, i, val)
        }
        r_den := multiply(a_den, p_den)

        // subtract r2 = r1 - p
        if channels != nil {
            r_num = divSub(r_num, p_num, setting)
            for _, ch := range channels {
                ch <- r_num
            }
        } else {
            r_num = (<-channel).(gm.Matrix)
        }

        a_num = r_num
        a_den = r_den

    }

    // remove initial zero coefficients
    var lr int
    for lr = a_num.Cols-1; lr >= 0; lr -=1 {
        zero_t, err := decodeBI(a_num.At(0,lr))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    a_num_vals := make([]interface{}, lr+1)
    for i := range a_num_vals {
        a_num_val, err := a_num.At(0, i)
        if err != nil {panic(err)}
        a_num_vals[i] = a_num_val
    }
    a_num, err = gm.NewMatrix(1, lr+1, a_num_vals, space)
    if err != nil {panic(err)}
    return q_num, q_den, a_num, a_den
}

func exchangeRandomizers(channels []chan interface{}, channel chan interface{}, n int, q *big.Int) []*big.Int {
    if channels != nil {
        randomizers, err := SampleSlice(n, q)
        if err != nil {panic(err)}
        for _, ch := range channels {
            ch <- randomizers
        }
        return randomizers
    } else {
        return (<-channel).([]*big.Int)
    }
}

// subtracts encrypted polynomials r - p, where deg(r) >= deg(p)
func divSub(r, p gm.Matrix,setting AHE_setting) gm.Matrix {
    pos_diff := r.Cols-p.Cols
    for i := 0; i < p.Cols; i += 1 {
        p_val, err := decodeBI(p.At(0,i))
        if err != nil {panic(err)}
        neg, err := setting.AHE_cryptosystem().Scale(p_val, big.NewInt(-1))
        if err != nil {panic(err)}
        r_val, err := decodeBI(r.At(0, i+pos_diff))
        if err != nil {panic(err)}
        diff, err := setting.AHE_cryptosystem().Add(r_val, neg)
        if err != nil {panic(err)}
        r.Set(0, i+pos_diff, diff)
    }
    return r
}

func MinPolyWorker(seq gm.Matrix, rec_ord int, sk Secret_key, setting AHE_setting, channels []chan interface{}, channel chan interface{}) (gm.Matrix, gm.Matrix) {

    // create r0
    randomizers := exchangeRandomizers(channels, channel, 8+seq.Cols, setting.AHE_cryptosystem().N())
    ri := 0
    coeff, err := setting.AHE_cryptosystem().EncryptFixed(big.NewInt(1), randomizers[ri])
    ri += 1
    al := seq.Cols + 1
    a, err := EncryptedFixedZeroMatrix(1, al, randomizers[ri:ri+al], setting)
    if err != nil {panic(err)}
    ri += al
    a.Set(0, seq.Cols, coeff)

    a_den, err := setting.AHE_cryptosystem().EncryptFixed(big.NewInt(1), randomizers[ri])
    if err != nil {panic(err)}
    ri += 1

    // create r1
    b := seq
    b_den, err := setting.AHE_cryptosystem().EncryptFixed(big.NewInt(1), randomizers[ri])
    if err != nil {panic(err)}
    ri += 1
    
    // create t0, t1
    t0_num, err := EncryptedFixedZeroMatrix(1, 1, randomizers[ri:ri+1], setting)
    if err != nil {panic(err)}
    ri += 1
    t0_den, err := EncryptedFixedOneMatrix(1, 1, randomizers[ri:ri+1], setting)
    if err != nil {panic(err)}
    ri += 1
    t1_num, err := EncryptedFixedOneMatrix(1, 1, randomizers[ri:ri+1], setting)
    if err != nil {panic(err)}
    ri += 1
    t1_den, err := EncryptedFixedOneMatrix(1, 1, randomizers[ri:ri+1], setting)
    if err != nil {panic(err)}
    ri += 1
    
    var t2_num gm.Matrix
    var t2_den gm.Matrix

    for {
        q_num, q_den, r_num, r_den := PolynomialDivisionWorker(a, b, a_den, b_den, sk, setting, channels, channel)
        t2_num, t2_den, err = nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den, sk, setting, channels, channel)
        if err != nil {panic(err)}
        if r_num.Cols <= rec_ord {
            break
        }
        a = b
        a_den = b_den
        b = r_num
        b_den = r_den
        t0_num = t1_num
        t0_den = t1_den
        t1_num = t2_num
        t1_den = t2_den
    }
    return t2_num, t2_den
}

func nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}, channel chan interface{}) (t2_num, t2_den gm.Matrix, err error) {
    p_num, p_den, err := PolyMult(t1_num, t1_den, q_num, q_den, sk, setting, channels, channel)
    if err != nil {return}
    t2_num, t2_den, err = PolySub(t0_num, t0_den, p_num, p_den, sk, setting, channels, channel)
    return
}

func PolySub(a_num, a_den, b_num, b_den gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}, channel chan interface{}) (diff_num, diff_den gm.Matrix, err error) {
    if a_num.Cols != a_den.Cols || b_num.Cols != b_den.Cols {
        panic("mismatched length of denominator")
    }
    var diff_l int
    if a_num.Cols > b_num.Cols {
        diff_l = a_num.Cols
    } else {
        diff_l = b_num.Cols
    }
    diff_num, err = gm.NewMatrix(1, diff_l, nil, a_num.Space)
    if err != nil {return}
    diff_den, err = gm.NewMatrix(1, diff_l, nil, a_num.Space)
    if err != nil {return}
    multiply := func (a, b Ciphertext) Ciphertext {
        if channels != nil {
            return CentralMultWorker(a, b, sk, setting, channels)
        } else {
            return OuterMultWorker(a, b, sk, setting, channel)
        }
    }
    scale := func (a Ciphertext, factor *big.Int) Ciphertext {
        if channels != nil {
            val, err := setting.AHE_cryptosystem().Scale(a, factor)
            if err != nil {panic(err)}
            for _, ch := range channels {
                ch <- val
            }
            return val
        } else {
            return (<-channel).(Ciphertext)
        }
    }
    var num Ciphertext
    for i := 0; i < diff_l; i += 1 {
        if i >= b_num.Cols { // todo: not covered by test
            var a_val interface{}
            a_val, err = a_num.At(0, i)
            if err != nil {return}
            diff_num.Set(0, i, a_val)
            a_val, err = a_den.At(0, i)
            if err != nil {return}
            diff_den.Set(0, i, a_val)
        } else if i >= a_num.Cols {
            var b_val *big.Int
            b_val, err = decodeBI(b_num.At(0, i))
            if err != nil {return}
            num = scale(b_val, big.NewInt(-1))
            diff_num.Set(0, i, num)
            b_val, err = decodeBI(b_den.At(0, i))
            if err != nil {return}
            diff_den.Set(0, i, b_val)
        } else {
            var a_num_val *big.Int
            a_num_val, err = decodeBI(a_num.At(0, i))
            if err != nil {return}
            var b_den_val *big.Int
            b_den_val, err = decodeBI(b_den.At(0, i))
            if err != nil {return}
            long_a_num := multiply(a_num_val, b_den_val)
            var b_num_val *big.Int
            b_num_val, err = decodeBI(b_num.At(0, i))
            if err != nil {return}
            var a_den_val *big.Int
            a_den_val, err = decodeBI(a_den.At(0, i))
            if err != nil {return}
            long_b_num := multiply(b_num_val, a_den_val)
            neg := scale(long_b_num, big.NewInt(-1))
            num, err = setting.AHE_cryptosystem().Add(long_a_num, neg)
            if err != nil {return}
            diff_num.Set(0, i, num)
            den := multiply(a_den_val, b_den_val)
            diff_den.Set(0, i, den)
        }
    }
    return
}

func PolyMult(a_num, a_den, b_num, b_den gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}, channel chan interface{}) (prod_num, prod_den gm.Matrix, err error) {
    prod_len := a_num.Cols+b_num.Cols-1
    randomizers := exchangeRandomizers(channels, channel, prod_len*2, setting.AHE_cryptosystem().N())
    prod_num, err = EncryptedFixedZeroMatrix(1, prod_len, randomizers[:prod_len], setting)
    if err != nil {return}
    prod_den, err = EncryptedFixedOneMatrix(1, prod_num.Cols, randomizers[prod_len:], setting)
    if err != nil {return}
    multiply := func (a, b Ciphertext) Ciphertext {
        if channels != nil {
            return CentralMultWorker(a, b, sk, setting, channels)
        } else {
            return OuterMultWorker(a, b, sk, setting, channel)
        }
    }
    for i := 0; i < a_num.Cols; i += 1 {
        for j := 0; j < b_num.Cols; j += 1 {
            var a_num_val *big.Int
            a_num_val, err = decodeBI(a_num.At(0,i))
            if err != nil {return}
            var b_num_val *big.Int
            b_num_val, err = decodeBI(b_num.At(0,j))
            if err != nil {return}
            num := multiply(a_num_val, b_num_val)
            var current_num *big.Int
            current_num, err = decodeBI(prod_num.At(0, i+j))
            if err != nil {return}
            
            var a_den_val *big.Int
            a_den_val, err = decodeBI(a_den.At(0,i))
            if err != nil {return}
            var b_den_val *big.Int
            b_den_val, err = decodeBI(b_den.At(0,j))
            if err != nil {return}
            den := multiply(a_den_val, b_den_val)
            var current_den *big.Int
            current_den, err = decodeBI(prod_den.At(0, i+j))
            if err != nil {return}
            
            long_num := multiply(num, current_den)
            long_current_num := multiply(current_num, den)
            var new_num Ciphertext
            new_num, err = setting.AHE_cryptosystem().Add(long_num, long_current_num)
            if err != nil {return}
            prod_num.Set(0, i+j, new_num)
            
            new_den := multiply(den, current_den)
            prod_den.Set(0, i+j, new_den)
        }
    }
    return
}

func EncryptedFixedZeroMatrix(rows, cols int, randomizers []*big.Int, setting AHE_setting) (m gm.Matrix, err error) {
    var val Ciphertext
    vals := make([]interface{}, rows*cols)
    for i := range vals {
        val, err = setting.AHE_cryptosystem().EncryptFixed(big.NewInt(0), randomizers[i])
        if err != nil {return}
        vals[i] = val
    }
    return gm.NewMatrix(rows, cols, vals, setting.AHE_cryptosystem().EvaluationSpace())
}

func EncryptedFixedOneMatrix(rows, cols int, randomizers []*big.Int, setting AHE_setting) (m gm.Matrix, err error) {
    var val Ciphertext
    vals := make([]interface{}, rows*cols)
    for i := range vals {
        val, err = setting.AHE_cryptosystem().EncryptFixed(big.NewInt(1), randomizers[i])
        if err != nil {return}
        vals[i] = val
    }
    return gm.NewMatrix(rows, cols, vals, setting.AHE_cryptosystem().EvaluationSpace())
}

func CentralMatrixMultiplicationWorker(a, b gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}) gm.Matrix {
    if a.Cols != b.Rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.Rows, a.Cols, b.Rows, b.Cols))
    }
    self := setting.Parties()-1
    
    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    RAs_crypt := make([]gm.Matrix, setting.Parties())
    RBs_crypt := make([]gm.Matrix, setting.Parties())
    RAs_crypt[self] = RAi_crypt
    RBs_crypt[self] = RBi_crypt
    for i := 0; i < self; i += 1 {
        RAs_crypt[i] = (<-channels[i]).(gm.Matrix)
        RBs_crypt[i] = (<-channels[i]).(gm.Matrix)
    }

    // step 2
    RA, MA, MB, err := GetMulMatrices(a, b, RAs_crypt, RBs_crypt, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- RA
        channels[i] <- MA
        channels[i] <- MB
    }

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    cts := make([]gm.Matrix, setting.Parties())
    MA_parts := make([]gm.Matrix, setting.Parties())
    MB_parts := make([]gm.Matrix, setting.Parties())
    cts[self] = cti
    MA_parts[self] = MA_part
    MB_parts[self] = MB_part
    for i := 0; i < self; i += 1 {
        cts[i] = (<-channels[i]).(gm.Matrix)
        MA_parts[i] = (<-channels[i]).(gm.Matrix)
        MB_parts[i] = (<-channels[i]).(gm.Matrix)
    }

    // step 4
    AB, err := CombineMatrixMultiplication(MA, MB, MA_parts, MB_parts, cts, setting)
    for i := 0; i < self; i += 1 {
        channels[i] <- AB
    }

    return AB

}

func OuterMatrixMultiplicationWorker(a, b gm.Matrix, sk Secret_key, setting AHE_setting, channel chan interface{}) gm.Matrix {
    if a.Cols != b.Rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.Rows, a.Cols, b.Rows, b.Cols))
    }

    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    channel <- RAi_crypt
    channel <- RBi_crypt

    // step 2
    RA := (<-channel).(gm.Matrix)
    MA := (<-channel).(gm.Matrix)
    MB := (<-channel).(gm.Matrix)

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    channel <- cti
    channel <- MA_part
    channel <- MB_part

    // step 4
    AB := (<-channel).(gm.Matrix)

    return AB
}

// outputs true through return_channel if m is singular
func CentralSingularityTestWorker(m gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}) bool {
    self := setting.Parties()-1
    // step b
    v, err := SampleVVector(m, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    // step c
    its := NbrMMultInstances(m)
    mats := make([]gm.Matrix, its+1)
    mats[0] = m
    for i := 0; i < its; i += 1 {
        mats[i+1] = CentralMatrixMultiplicationWorker(mats[i], mats[i], sk, setting, channels)
    }

    //step d
    semi_seq := v
    for _, mat := range mats {
        new_semi_seq := CentralMatrixMultiplicationWorker(mat, semi_seq, sk, setting, channels)
        semi_seq, err = new_semi_seq.Concatenate(semi_seq)
        if err != nil {panic(err)}
    }

    // step e
    seq, err := HSeq(semi_seq, m.Cols, setting)
    if err != nil {panic(err)}

    // distribute seq instead of decrypted secret sharing
    for i := 0; i < self; i += 1 {
        channels[i] <- seq
    }

    // step i
    rec_ord := m.Cols
    min_poly, _ := MinPolyWorker(seq, rec_ord, sk, setting, channels, nil)
    
    zero_t, err := decodeBI(min_poly.At(0,0))
    if err != nil {panic(err)}
    return CentralZeroTestWorker(zero_t, sk, setting, channels)
}

// outputs true through return_channel if m is singular
func OuterSingularityTestWorker(m gm.Matrix, sk Secret_key, setting AHE_setting, channel chan interface{}) bool {
    // step b
    v := (<-channel).(gm.Matrix)

    // step c
    its := NbrMMultInstances(m)
    mats := make([]gm.Matrix, its+1)
    mats[0] = m
    for i := 0; i < its; i += 1 {
        mats[i+1] = OuterMatrixMultiplicationWorker(mats[i], mats[i], sk, setting, channel)
    }

    //step d
    semi_seq := v
    var err error
    for i := range mats {
        new_semi_seq := OuterMatrixMultiplicationWorker(mats[i], semi_seq, sk, setting, channel)
        semi_seq, err = new_semi_seq.Concatenate(semi_seq)
        if err != nil {panic(err)}
    }

    seq := (<-channel).(gm.Matrix)

    // step i
    rec_ord := m.Cols
    min_poly, _ := MinPolyWorker(seq, rec_ord, sk, setting, nil, channel)

    zero_t, err := decodeBI(min_poly.At(0,0))
    if err != nil {panic(err)}
    return OuterZeroTestWorker(zero_t, sk, setting, channel)
}


// returns true if number of elements not shared by all is <= setting.Threshold()
func CentralCardinalityTestWorker(items []*big.Int, sk Secret_key, setting AHE_setting, channels []chan interface{}) bool {
    self := setting.Parties()-1
    u, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- u
    }
    H, err := CPComputeHankelMatrix(items, u, setting.AHE_cryptosystem().N(), setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        Hi := (<-channels[i]).(gm.Matrix)
        H, err = H.Subtract(Hi)
        if err != nil {panic(err)}
    }
    for i := 0; i < self; i += 1 {
        channels[i] <- H
    }
    
    return CentralSingularityTestWorker(H, sk, setting, channels)
}

// returns true if number of elements not shared by all is <= setting.Threshold()
func OuterCardinalityTestWorker(items []*big.Int, sk Secret_key, setting AHE_setting, channel chan interface{}) bool {
    u := (<-channel).(*big.Int)
    H1, err := ComputeHankelMatrix(items, u, setting)
    if err != nil {panic(err)}
    channel <- H1
    H := (<-channel).(gm.Matrix)

    return OuterSingularityTestWorker(H, sk, setting, channel)
}

// step 3 of TPSI-diff
func CentralIntersectionPolyWorker(root_poly gm.Matrix, sk Secret_key, setting AHE_setting, channels []chan interface{}) (gm.Matrix, gm.Matrix) {
    sample_max := setting.Threshold() * 3 + 4
    self := setting.Parties()-1
    
    // step a
    root_poly = RootMask(root_poly, setting)
    
    // step b
    R_values_enc, R_tilde_values, p_values := EvalIntPolys(root_poly, sample_max, setting)
    all_R_values := make([]gm.Matrix, setting.Parties())
    all_R_values[self] = R_values_enc
    for i := 0; i < self; i += 1 {
        all_R_values[i] = (<-channels[i]).(gm.Matrix)
    }

    // step c
    var party_values gm.Matrix
    var err error
    for i := 0; i < setting.Parties(); i += 1 {
        party_slice := make([]interface{}, sample_max)
        for j := 0; j < sample_max; j += 1 {
            party_slice[j] = new(big.Int).SetInt64(0)
        }
        party_values, err = gm.NewMatrix(1, sample_max, party_slice, gm.Bigint{})
        if err != nil {panic(err)}
        party_values, err = EncryptMatrix(party_values, setting)
        if err != nil {panic(err)}
        for j, vals := range all_R_values {
            if i != j {
                party_values, err = party_values.Add(vals)
                if err != nil {panic(err)}
            }
        }
        if i != self {
            channels[i] <- party_values
        }
    }

    // step d
    v := MaskRootPoly(p_values, party_values, R_tilde_values, sample_max, setting)

    // step e
    for i := 0; i < self; i += 1 {
        v, err = v.Add((<-channels[i]).(gm.Matrix))
        if err != nil {panic(err)}
    }
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    // step f
    partials := make([]gm.Matrix, setting.Parties())
    pm, err := PartialDecryptMatrix(v, sk)
    if err != nil {panic(err)}
    partials[self] = pm
    for i := 0; i < self; i += 1 {
        partials[i] = (<-channels[i]).(gm.Matrix)
    }

    // step g
    v, err = CombineMatrixShares(partials, v, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    return v, p_values
}

// step 3 of TPSI-diff
func OuterIntersectionPolyWorker(root_poly gm.Matrix, sk Secret_key, setting AHE_setting, channel chan interface{}) (gm.Matrix, gm.Matrix) {
    sample_max := setting.Threshold() * 3 + 4
    
    // step a
    root_poly = RootMask(root_poly, setting)
    
    // step b
    R_values_enc, R_tilde_values, p_values := EvalIntPolys(root_poly, sample_max, setting)
    channel <- R_values_enc

    // step c
    party_values := (<-channel).(gm.Matrix)

    // step d
    v := MaskRootPoly(p_values, party_values, R_tilde_values, sample_max, setting)
    channel <- v
    
    // step e
    v = (<-channel).(gm.Matrix)
    
    // step f
    pm, err := PartialDecryptMatrix(v, sk)
    if err != nil {panic(err)}
    channel <- pm

    // step g
    v = (<-channel).(gm.Matrix)
    return v, p_values
}

// returns two slices, shared elements & unique elements
func IntersectionWorker(items []*big.Int, sk Secret_key, setting AHE_setting, central bool, channels []chan interface{}, channel chan interface{}) ([]*big.Int, []*big.Int) {
    root_poly := PolyFromRoots(items, setting.AHE_cryptosystem().N())
    var vs gm.Matrix
    var ps gm.Matrix
    if central {
        vs, ps = CentralIntersectionPolyWorker(root_poly, sk, setting, channels)
    } else {
        vs, ps = OuterIntersectionPolyWorker(root_poly, sk, setting, channel)
    }
    
    p := Interpolation(vs, ps, setting)
    shared := make([]*big.Int, 0, len(items))
    unique := make([]*big.Int, 0, len(items))
    for _, item := range items {
        if IsRoot(p, item, setting.AHE_cryptosystem().N()) {
            unique = append(unique, item)
        } else {
            shared = append(shared, item)
        }
    }

    return shared, unique
}

// returns two slices: shared elements & unique elements if cardinality test passes, otherwise nil, nil
func TPSIdiffWorker(items []*big.Int, sk Secret_key, setting AHE_setting, central bool, channels []chan interface{}, channel chan interface{}) ([]*big.Int, []*big.Int) {
    var pred bool
    if central {
        pred = CentralCardinalityTestWorker(items, sk, setting, channels)
    } else {
        pred = OuterCardinalityTestWorker(items, sk, setting, channel)
    }

    // exit if cardinality test doesn't pass
    if pred {
        return IntersectionWorker(items, sk, setting, central, channels, channel)
    } else {
        return nil, nil
    }
}