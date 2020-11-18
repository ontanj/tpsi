package tpsi

import (
    "math/big"
    "github.com/niclabs/tcpaillier"
    "fmt"
)

func CentralASSWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- *big.Int) {
    self := setting.n-1

    // step 1: sample d
    var d_plain *big.Int
    var d_enc *big.Int
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}
    
    // recieve all_d
    var all_d []*big.Int
    all_d = make([]*big.Int, setting.n)
    all_d[self] = d_enc
    for i := 0; i < self; i += 1 {
        all_d[i] = (<-channels[i]).(*big.Int)
    }

    // send all_d
    for i := 0; i < self; i += 1 {
        channels[i] <- all_d
    }

    // step 5: mask and decrypt
    var e_partial *tcpaillier.DecryptionShare
    e_partial, err = SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // recieve e_parts
    e_parts := make([]*tcpaillier.DecryptionShare, setting.n)
    e_parts[self] = e_partial
    for i := 0; i < setting.n-1; i += 1 {
        e_parts[i] = (<-channels[i]).(*tcpaillier.DecryptionShare)
    }

    e, err := CombineShares(e_parts, setting)
    if err != nil {
        panic(err)
    }

    // step 7: assign share
    a_share := SecretShare(d_plain, e, setting)
    return_channel <- a_share
}

func OuterASSWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- *big.Int) {
    
    // step 1: sample d
    var d_plain *big.Int
    var d_enc *big.Int
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}

    channel <- d_enc
    
    // recieve all_d
    var all_d []*big.Int
    all_d = (<-channel).([]*big.Int)
    
    // step 5: mask and decrypt
    var e_partial *tcpaillier.DecryptionShare
    e_partial, err = SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // broadcast e_partial
    channel <- e_partial
    
    // step 7: assign share
    a_share := NegateValue(d_plain, setting)
    return_channel <- a_share
}

func CentralMultWorker(a, b *big.Int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- *big.Int) {
    self := setting.n-1

    ass_channel := make(chan *big.Int)
    go CentralASSWorker(a, sk, setting, channels, ass_channel)
    a_share := <-ass_channel

    // step 2: partial multiplication    
    prod, err := MultiplyEncrypted(b, a_share, setting)
    if err != nil {panic(err)}

    // recieve partial_prods
    partial_prods := make([]*big.Int, setting.n)
    partial_prods[self] = prod
    for i := 0; i < self; i += 1 {
        partial_prods[i] = (<-channels[i]).(*big.Int)
    }

    // send partial_prods
    for i := 0; i < self; i += 1 {
        channels[i] <- partial_prods
    }

    // step 6: sum partials
    sum, err := SumMultiplication(partial_prods, setting)
    if err != nil {panic(err)}
    
    return_channel <- sum
}

func OuterMultWorker(a, b *big.Int, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- *big.Int) {
    
    ass_channel := make(chan *big.Int)
    go OuterASSWorker(a, sk, setting, channel, ass_channel)
    a_share := <-ass_channel
    
    // step 2: partial multiplication    
    prod, err := MultiplyEncrypted(b, a_share, setting)
    if err != nil {panic(err)}

    // broadcast prod
    channel <- prod

    // recieve partial_prods
    partial_prods := (<-channel).([]*big.Int)

    // step 6: sum partials
    sum, err := SumMultiplication(partial_prods, setting)
    if err != nil {panic(err)}
    
    return_channel <- sum
}

func CentralZeroTestWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- bool) {
                        //    mask_channel <-chan *big.Int,
                        //    masks_channel chan<- []*big.Int,
                        //    dec_channel <-chan *tcpaillier.DecryptionShare,
                        //    shares_channel chan<- []*tcpaillier.DecryptionShare,
                        //    return_channel chan<- bool) {
    self := setting.n-1
    var err error
    masks := make([]*big.Int, setting.n)
    mask, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    mask, err = EncryptValue(mask, setting)
    if err != nil {panic(err)}
    
    masks[self] = mask
    for i := 0; i < self; i += 1 {
        masks[i] = (<-channels[i]).(*big.Int)
    }
    
    for i := 0; i < self; i += 1 {
        channels[i] <- masks
    }

    sum, err := setting.pk.Add(masks...)
    if err != nil {panic(err)}

    ret := make(chan *big.Int)

    go CentralMultWorker(a, sum, sk, setting, channels, ret)

    pred := <-ret

    go CentralDecryptionWorker(pred, sk, setting, channels, ret)

    pred = <-ret

    return_channel <- pred.Cmp(big.NewInt(0)) == 0    
}

func OuterZeroTestWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- bool) {

    mask, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}

    mask, err = EncryptValue(mask, setting)
    if err != nil {panic(err)}

    channel <- mask

    masks := (<-channel).([]*big.Int)

    sum, err := setting.pk.Add(masks...)
    if err != nil {panic(err)}

    ret := make(chan *big.Int)

    go OuterMultWorker(a, sum, sk, setting, channel, ret)

    pred := <-ret

    go OuterDecryptionWorker(pred, sk, setting, channel, ret)

    pred = <-ret

    return_channel <- pred.Cmp(big.NewInt(0)) == 0    
}

func CentralDecryptionWorker(cipher *big.Int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- *big.Int) {
    self := setting.n-1
    partial, err := PartialDecryptValue(cipher, sk)
    if err != nil {panic(err)}

    ds := make([]*tcpaillier.DecryptionShare, setting.n)
    ds[self] = partial

    for i := 0; i < self; i += 1 {
        ds[i] = (<-channels[i]).(*tcpaillier.DecryptionShare)
    }

    for i := 0; i < self; i += 1 {
        channels[i] <- ds
    }

    plain, err := CombineShares(ds, setting)
    if err != nil {panic(err)}

    return_channel <- plain.Mod(plain, setting.pk.N)
}

func OuterDecryptionWorker(cipher *big.Int, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- *big.Int) {
    partial, err := PartialDecryptValue(cipher, sk)
    if err != nil {panic(err)}

    channel <- partial

    ds := (<-channel).([]*tcpaillier.DecryptionShare)

    plain, err := CombineShares(ds, setting)
    if err != nil {panic(err)}

    return_channel <- plain.Mod(plain, setting.pk.N)
}

// returns 4 slices through return_channel:
//  * q numerator
//  * q denominator
//  * r numerator
//  * r denominator (slice of size 1 as all coefficents share denominator)
func PolynomialDivisionWorker(a, b BigMatrix, a_den, b_den *big.Int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, channel chan interface{}, return_channel chan<- BigMatrix) {
    zeroTest := func (val *big.Int) bool {
        zt_channel := make(chan bool)
        if channels != nil {
            go CentralZeroTestWorker(val, sk, setting, channels, zt_channel)
        } else {
            go OuterZeroTestWorker(val, sk, setting, channel, zt_channel)
        }
        return <-zt_channel
    }
    multiply := func (a, b *big.Int) *big.Int {
        mul_channel := make(chan *big.Int)
        if channels != nil {
            go CentralMultWorker(a, b, sk, setting, channels, mul_channel)
        } else {
            go OuterMultWorker(a, b, sk, setting, channel, mul_channel)
        }
        return <-mul_channel
    }
    var la int // degree of dividend
    for la = a.cols-1; la >= 0; la -= 1 { // find degree of divisor
        if !zeroTest(a.At(0,la)) {
            break
        }
    }
    var lb int // degree of divisor
    for lb = b.cols-1; lb >= 0; lb -= 1 { // find degree of divisor
        if !zeroTest(b.At(0,lb)) {
            break
        }
    }
    a_num := a
    q_num, err := EncryptedFixedZeroMatrix(1, 1+la-lb, setting)
    if err != nil {panic(err)}
    q_den, err := EncryptedFixedOneMatrix(1, 1+la-lb, setting)
    if err != nil {panic(err)}

    for i := la; i >= lb; i -= 1 { // start at highest degree coefficient, go until dividend smaller than divisor
        // skip 0 coefficents
        if zeroTest(a_num.At(0,i)) {
            continue
        }

        pos := i-lb // entry in q at pos

        // q numerator: b_den * a_num
        num := multiply(a_num.At(0, i), b_den)
        q_num.Set(0, pos, num)

        // q denominator: b_num * a_den
        den := multiply(b.At(0, lb), a_den)
        q_den.Set(0, pos, den)

        // p = q_val * b
        p_num := NewBigMatrix(1, lb, nil) // partial result, size is degree of (partial) dividend - 1 = i , skip highest coefficient as it is cancelling
        for j := 0; j < lb; j += 1 {
            val := multiply(num, b.At(0, j))
            p_num.Set(0, j, val)
        }
        p_den := multiply(den, b_den)

        // make common denominator for p and a
        r_num := NewBigMatrix(1, i, nil)
        for i := 0; i < r_num.cols; i += 1 {
            val := multiply(a_num.At(0, i), p_den)
            r_num.Set(0, i, val)
        }
        for i := 0; i < p_num.cols; i += 1 {
            val := multiply(p_num.At(0, i), a_den)
            p_num.Set(0, i, val)
        }
        r_den := multiply(a_den, p_den)

        // subtract r2 = r1 - p
        r_num = divSub(r_num, p_num, setting)

        a_num = r_num
        a_den = r_den

    }

    // remove initial zero coefficients
    var lr int
    for lr = a_num.cols-1; lr >= 0; lr -=1 {
        if !zeroTest(a_num.At(0,lr)) {
            break
        }
    }
    a_num = NewBigMatrix(1, lr+1, a_num.values[0:lr+1])
    return_channel <- q_num
    return_channel <- q_den
    return_channel <- a_num
    return_channel <- NewBigMatrix(1, 1, []*big.Int{a_den})
}

func divSub(r, p BigMatrix, setting Setting) BigMatrix {
    pos_diff := r.cols-p.cols
    for i := 0; i < p.cols; i += 1 {
        neg, err := setting.pk.MultiplyFixed(p.At(0,i), big.NewInt(-1), big.NewInt(1))
        if err != nil {panic(err)}
        diff, err := setting.pk.Add(r.At(0, i+pos_diff), neg)
        if err != nil {panic(err)}
        r.Set(0, i+pos_diff, diff)
    }
    return r
}

func MinPolyWorker(seq BigMatrix, rec_ord int, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, channel chan interface{}, return_channel chan<- BigMatrix) {
    // create r0
    coeff, err := setting.pk.EncryptFixed(big.NewInt(1), big.NewInt(1))
    a, err := EncryptedFixedZeroMatrix(1, seq.cols+1, setting)
    if err != nil {panic(err)}
    a.Set(0, seq.cols, coeff)

    a_den, err := setting.pk.EncryptFixed(big.NewInt(1), big.NewInt(1))
    if err != nil {panic(err)}

    // create r1
    b := seq
    b_den, err := setting.pk.EncryptFixed(big.NewInt(1), big.NewInt(1))
    if err != nil {panic(err)}

    pol_div := make(chan BigMatrix)
    
    // create t0, t1
    t0_num, err := EncryptedFixedZeroMatrix(1, 1, setting)
    if err != nil {panic(err)}
    t0_den, err := EncryptedFixedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    t1_num, err := EncryptedFixedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    t1_den, err := EncryptedFixedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    
    var t2_num BigMatrix
    var t2_den BigMatrix

    for {
        go PolynomialDivisionWorker(a, b, a_den, b_den, sk, setting, channels, channel, pol_div)
        q_num := <-pol_div
        q_den := <-pol_div
        r_num := <-pol_div
        r_den := <-pol_div
        t2_num, t2_den, err = nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den, sk, setting, channels, channel)
        if err != nil {panic(err)}
        if r_num.cols <= rec_ord {
            break
        }
        a = b
        a_den = b_den
        b = r_num
        b_den = r_den.At(0,0)
        t0_num = t1_num
        t0_den = t1_den
        t1_num = t2_num
        t1_den = t2_den
    }
    return_channel <- t2_num
    return_channel <- t2_den
}

func nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, channel chan interface{}) (t2_num, t2_den BigMatrix, err error) {
    p_num, p_den, err := PolyMult(t1_num, t1_den, q_num, q_den, sk, setting, channels, channel)
    if err != nil {return}
    t2_num, t2_den, err = PolySub(t0_num, t0_den, p_num, p_den, sk, setting, channels, channel)
    return
}

func PolySub(a_num, a_den, b_num, b_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, channel chan interface{}) (diff_num, diff_den BigMatrix, err error) {
    if a_num.cols != a_den.cols || b_num.cols != b_den.cols {
        panic("mismatched length of denominator")
    }
    var diff_l int
    if a_num.cols > b_num.cols {
        diff_l = a_num.cols
    } else {
        diff_l = b_num.cols
    }
    diff_num = NewBigMatrix(1, diff_l, nil)
    diff_den = NewBigMatrix(1, diff_l, nil)
    multiply := func (a, b *big.Int) *big.Int {
        return_channel := make(chan *big.Int)
        if channels != nil {
            go CentralMultWorker(a, b, sk, setting, channels, return_channel)
        } else {
            go OuterMultWorker(a, b, sk, setting, channel, return_channel)
        }
        return <-return_channel
    }
    var num *big.Int
    var neg *big.Int
    for i := 0; i < diff_l; i += 1 {
        if i >= b_num.cols {
            diff_num.Set(0, i, a_num.At(0, i))
            diff_den.Set(0, i, a_den.At(0, i))
        } else if i >= a_num.cols {
            num, err = setting.pk.MultiplyFixed(b_num.At(0, i), big.NewInt(-1), big.NewInt(1))
            if err != nil {return}
            diff_num.Set(0, i, num)
            diff_den.Set(0, i, b_den.At(0, i))
        } else {
            long_a_num := multiply(a_num.At(0, i), b_den.At(0, i))
            long_b_num := multiply(b_num.At(0, i), a_den.At(0, i))
            neg, err = setting.pk.MultiplyFixed(long_b_num, big.NewInt(-1), big.NewInt(1))
            if err != nil {return}
            num, err = setting.pk.Add(long_a_num, neg)
            if err != nil {return}
            diff_num.Set(0, i, num)
            den := multiply(a_den.At(0, i), b_den.At(0, i))
            diff_den.Set(0, i, den)
        }
    }
    return
}

func PolyMult(a_num, a_den, b_num, b_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, channel chan interface{}) (prod_num, prod_den BigMatrix, err error) {
    prod_num, err = EncryptedFixedZeroMatrix(1, a_num.cols+b_num.cols-1, setting)
    if err != nil {return}
    prod_den, err = EncryptedFixedOneMatrix(1, prod_num.cols, setting)
    if err != nil {return}
    multiply := func (a, b *big.Int) *big.Int {
        return_channel := make(chan *big.Int)
        if channels != nil {
            go CentralMultWorker(a, b, sk, setting, channels, return_channel)
        } else {
            go OuterMultWorker(a, b, sk, setting, channel, return_channel)
        }
        return <-return_channel
    }
    var new_num *big.Int
    for i := 0; i < a_num.cols; i += 1 {
        for j := 0; j < b_num.cols; j += 1 {
            num := multiply(a_num.At(0,i), b_num.At(0,j))
            current_num := prod_num.At(0, i+j)
            
            den := multiply(a_den.At(0,i), b_den.At(0,j))
            current_den := prod_den.At(0, i+j)
            
            long_num := multiply(num, current_den)
            long_current_num := multiply(current_num, den)
            new_num, err = setting.pk.Add(long_num, long_current_num)
            if err != nil {return}
            prod_num.Set(0, i+j, new_num)
            
            new_den := multiply(den, current_den)
            prod_den.Set(0, i+j, new_den)
        }
    }
    return
}

func EncryptedFixedZeroMatrix(rows, cols int, setting Setting) (m BigMatrix, err error) {
    var val *big.Int
    m = NewBigMatrix(rows, cols, nil)
    for i := range m.values {
        val, err = setting.pk.EncryptFixed(big.NewInt(0), big.NewInt(1))
        m.values[i] = val
        if err != nil {return}
    }
    return
}

func EncryptedFixedOneMatrix(rows, cols int, setting Setting) (m BigMatrix, err error) {
    var val *big.Int
    m = NewBigMatrix(rows, cols, nil)
    for i := range m.values {
        val, err = setting.pk.EncryptFixed(big.NewInt(1), big.NewInt(1))
        m.values[i] = val
        if err != nil {return}
    }
    return
}

func CentralMatrixMultiplicationWorker(a, b BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- BigMatrix) {
    if a.cols != b.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.rows, a.cols, b.rows, b.cols))
    }
    self := setting.n-1
    
    // step 1
    RAs_crypt := make([]BigMatrix, setting.n)
    RBs_crypt := make([]BigMatrix, setting.n)
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    RAs_crypt[self] = RAi_crypt
    RBs_crypt[self] = RBi_crypt
    for i := 0; i < self; i += 1 {
        RAs_crypt[i] = (<-channels[i]).(BigMatrix)
        RBs_crypt[i] = (<-channels[i]).(BigMatrix)
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
    cts := make([]BigMatrix, setting.n)
    MA_parts := make([]PartialMatrix, setting.n)
    MB_parts := make([]PartialMatrix, setting.n)
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    cts[self] = cti
    MA_parts[self] = MA_part
    MB_parts[self] = MB_part
    for i := 0; i < self; i += 1 {
        cts[i] = (<-channels[i]).(BigMatrix)
        MA_parts[i] = (<-channels[i]).(PartialMatrix)
        MB_parts[i] = (<-channels[i]).(PartialMatrix)
    }

    // step 4
    AB, err := CombineMatrixMultiplication(MA_parts, MB_parts, cts, setting)
    for i := 0; i < self; i += 1 {
        channels[i] <- AB
    }

    return_channel <- AB

}

func OuterMatrixMultiplicationWorker(a, b BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- BigMatrix) {
    if a.cols != b.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.rows, a.cols, b.rows, b.cols))
    }

    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    channel <- RAi_crypt
    channel <- RBi_crypt

    // step 2
    RA := (<-channel).(BigMatrix)
    MA := (<-channel).(BigMatrix)
    MB := (<-channel).(BigMatrix)

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    channel <- cti
    channel <- MA_part
    channel <- MB_part

    // step 4
    AB := (<-channel).(BigMatrix)

    return_channel <- AB
}

// outputs true through return_channel if m is singular
func CentralSingularityTestWorker(m BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan bool) {
    self := setting.n-1
    // step b
    v, err := SampleVVector(m, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    // step c
    its := NbrMMultInstances(m)
    mats := make([]BigMatrix, its+1)
    mats[0] = m
    ret := make(chan BigMatrix)
    for i := 0; i < its; i += 1 {
        go CentralMatrixMultiplicationWorker(mats[i], mats[i], sk, setting, channels, ret)
        mats[i+1] = <-ret
    }

    //step d
    semi_seq := v
    for _, mat := range mats {
        go CentralMatrixMultiplicationWorker(mat, semi_seq, sk, setting, channels, ret)
        new_semi_seq := <-ret
        semi_seq = ConcatenateMatrices(new_semi_seq, semi_seq)
    }

    // step e
    seq, err := HSeq(semi_seq, m.cols, setting)
    if err != nil {panic(err)}

    // distribute seq instead of decrypted secret sharing
    for i := 0; i < self; i += 1 {
        channels[i] <- seq
    }

    // step i
    rec_ord := m.cols
    go MinPolyWorker(seq, rec_ord, sk, setting, channels, nil, ret)
    min_poly := <-ret
    <-ret

    go CentralZeroTestWorker(min_poly.At(0,0), sk, setting, channels, return_channel)
}

// outputs true through return_channel if m is singular
func OuterSingularityTestWorker(m BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan bool) {
    // step b
    v := (<-channel).(BigMatrix)

    // step c
    its := NbrMMultInstances(m)
    mats := make([]BigMatrix, its+1)
    mats[0] = m
    mm_ret := make(chan BigMatrix)
    for i := 0; i < its; i += 1 {
        go OuterMatrixMultiplicationWorker(mats[i], mats[i], sk, setting, channel, mm_ret)
        mats[i+1] = <-mm_ret
    }

    //step d
    semi_seq := v
    for i := range mats {
        go OuterMatrixMultiplicationWorker(mats[i], semi_seq, sk, setting, channel, mm_ret)
        new_semi_seq := <-mm_ret
        semi_seq = ConcatenateMatrices(new_semi_seq, semi_seq)
    }

    seq := (<-channel).(BigMatrix)

    // step i
    rec_ord := m.cols
    go MinPolyWorker(seq, rec_ord, sk, setting, nil, channel, mm_ret)
    min_poly := <-mm_ret
    <-mm_ret

    go OuterZeroTestWorker(min_poly.At(0,0), sk, setting, channel, return_channel)

}

func CentralCardinalityTestWorker(items []int64, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan bool) {
    self := setting.n-1
    u, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- u
    }
    H, err := CPComputeHankelMatrix(items, u, setting.pk.N, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        Hi := (<-channels[i]).(BigMatrix)
        H, err = MatEncSub(H, Hi, setting.pk)
        if err != nil {panic(err)}
    }
    for i := 0; i < self; i += 1 {
        channels[i] <- H
    }
    
    go CentralSingularityTestWorker(H, sk, setting, channels, return_channel)

}

func OuterCardinalityTestWorker(items []int64, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan bool) {
    u := (<-channel).(*big.Int)
    H1, err := ComputeHankelMatrix(items, u, setting)
    if err != nil {panic(err)}
    channel <- H1
    H := (<-channel).(BigMatrix)

    go OuterSingularityTestWorker(H, sk, setting, channel, return_channel)

}

// step 3 of TPSI-diff
func CentralIntersectionPolyWorker(root_poly BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channels []chan interface{}, return_channel chan<- BigMatrix) {

    sample_max := setting.T * 3 + 4
    self := setting.n-1
    
    // step a
    r, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    random_root := NewBigMatrix(1, 2, []*big.Int{r, big.NewInt(1)})
    root_poly = MultPoly(root_poly, random_root)
    p_values := NewBigMatrix(1, sample_max, nil)

    // step b
    R, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_tilde, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_values := NewBigMatrix(1, sample_max, nil)
    R_tilde_values := NewBigMatrix(1, sample_max, nil)
    for i := 0; i < sample_max; i += 1 {
        x := int64(i*2+1)
        R_values.Set(0, i, EvalPoly(R, x, setting.pk.N))
        R_tilde_values.Set(0, i, EvalPoly(R_tilde, x, setting.pk.N))
        p_values.Set(0, i, EvalPoly(root_poly, x, setting.pk.N))
    }

    R_values_enc, err := EncryptMatrix(R_values, setting)
    if err != nil {panic(err)}
    all_R_values := make([]BigMatrix, setting.n)
    all_R_values[self] = R_values_enc
    for i := 0; i < self; i += 1 {
        all_R_values[i] = (<-channels[i]).(BigMatrix)
    }

    // step c
    var party_values BigMatrix
    for i := 0; i < setting.n; i += 1 {
        party_values = NewBigMatrix(1, sample_max, nil)
        party_values, err = EncryptMatrix(party_values, setting)
        if err != nil {panic(err)}
        for j, vals := range all_R_values {
            if i != j {
                party_values, err = MatEncAdd(party_values, vals, setting.pk)
                if err != nil {panic(err)}
            }
        }
        if i != self {
            channels[i] <- party_values
        }
    }

    // step d
    v := NewBigMatrix(1, sample_max, nil)
    R_tilde_values_enc, err := EncryptMatrix(R_tilde_values, setting)
    if err != nil {panic(err)}
    all_masks, err := MatEncAdd(party_values, R_tilde_values_enc, setting.pk)
    if err != nil {panic(err)}
    for i := 0; i < sample_max; i += 1 {
        val, _, err := setting.pk.Multiply(all_masks.At(0,i), p_values.At(0,i))
        if err != nil {panic(err)}
        v.Set(0, i, val)
    }

    // step e
    for i := 0; i < self; i += 1 {
        v, err = MatEncAdd(v, (<-channels[i]).(BigMatrix), setting.pk)
        if err != nil {panic(err)}
    }
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    // step f
    partials := make([]PartialMatrix, setting.n)
    pm, err := PartialDecryptMatrix(v, sk)
    if err != nil {panic(err)}
    partials[self] = pm
    for i := 0; i < self; i += 1 {
        partials[i] = (<-channels[i]).(PartialMatrix)
    }

    // step g
    v, err = CombineMatrixShares(partials, setting)
    if err != nil {panic(err)}
    for i := 0; i < self; i += 1 {
        channels[i] <- v
    }

    return_channel <- v
}

// step 3 of TPSI-diff
func OuterIntersectionPolyWorker(root_poly BigMatrix, sk *tcpaillier.KeyShare, setting Setting, channel chan interface{}, return_channel chan<- BigMatrix) {
    sample_max := setting.T * 3 + 4
    
    // step a
    r, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    random_root := NewBigMatrix(1, 2, []*big.Int{r, big.NewInt(1)})
    root_poly = MultPoly(root_poly, random_root)
    p_values := NewBigMatrix(1, sample_max, nil)

    // step b
    R, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_tilde, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_values := NewBigMatrix(1, sample_max, nil)
    R_tilde_values := NewBigMatrix(1, sample_max, nil)
    for i := 0; i < sample_max; i += 1 {
        x := int64(2*i+1)
        R_values.Set(0, i, EvalPoly(R, x, setting.pk.N))
        R_tilde_values.Set(0, i, EvalPoly(R_tilde, x, setting.pk.N))
        p_values.Set(0, i, EvalPoly(root_poly, x, setting.pk.N))
    }
    
    R_values_enc, err := EncryptMatrix(R_values, setting)
    if err != nil {panic(err)}
    channel <- R_values_enc

    // step c
    party_values := (<-channel).(BigMatrix)

    // step d
    v := NewBigMatrix(1, sample_max, nil)
    R_tilde_values_enc, err := EncryptMatrix(R_tilde_values, setting)
    if err != nil {panic(err)}
    all_masks, err := MatEncAdd(party_values, R_tilde_values_enc, setting.pk)
    if err != nil {panic(err)}
    for i := 0; i < sample_max; i += 1 {
        val, _, err := setting.pk.Multiply(all_masks.At(0,i), p_values.At(0,i))
        if err != nil {panic(err)}
        v.Set(0, i, val)
    }
    channel <- v
    
    // step e
    v = (<-channel).(BigMatrix)
    
    // step f
    pm, err := PartialDecryptMatrix(v, sk)
    if err != nil {panic(err)}
    channel <- pm

    // step g
    return_channel <- (<-channel).(BigMatrix)
}

// returns two slices, shared elements & unique elements
func IntersectionWorker(items []int64, sk *tcpaillier.KeyShare, setting Setting, central bool, channels []chan interface{}, channel chan interface{}, return_channel chan []int64) {
    root_poly := PolyFromRoots(items, setting.pk.N)
    ret := make(chan BigMatrix)
    if central {
        go CentralIntersectionPolyWorker(root_poly, sk, setting, channels, ret)
    } else {
        go OuterIntersectionPolyWorker(root_poly, sk, setting, channel, ret)
    }
    vs := <-ret
    ps := NewBigMatrix(1, setting.T * 3 + 4, nil)
    for i := 0; i < ps.cols; i += 1 {
        ps.Set(0, i, EvalPoly(root_poly, int64(2*i+1), setting.pk.N))
    }
    
    p := Intersection(vs, ps, setting)
    shared := make([]int64, 0, len(items))
    unique := make([]int64, 0, len(items))
    for _, item := range items {
        if IsRoot(p, item, setting.pk.N) {
            unique = append(unique, item)
        } else {
            shared = append(shared, item)
        }
    }

    return_channel <- shared
    return_channel <- unique

}

// returns tow slices, shared elements & unique elements if cardinality test passes, otherwise a single nil
func TPSIdiffWorker(items []int64, sk *tcpaillier.KeyShare, setting Setting, central bool, channels []chan interface{}, channel chan interface{}, return_channel chan []int64) {
    ret := make(chan bool)
    if central {
        go CentralCardinalityTestWorker(items, sk, setting, channels, ret)
    } else {
        go OuterCardinalityTestWorker(items, sk, setting, channel, ret)
    }

    // exit if cardinality test doesn't pass
    if !<-ret {
        return_channel <- nil
    } else {
        go IntersectionWorker(items, sk, setting, central, channels, channel, return_channel)
    }
}