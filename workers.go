package tpsi

import (
    "math/big"
    "github.com/niclabs/tcpaillier"
    "fmt"
)

func CentralASSWorkerFunctionality(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                                   mask_channel <-chan *big.Int,
                                   masks_channel chan<- []*big.Int,
                                   dec_channel <-chan *tcpaillier.DecryptionShare) *big.Int {
    // step 1: sample d
    var d_plain *big.Int
    var d_enc *big.Int
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}
    
    // recieve all_d
    var all_d []*big.Int
    all_d = make([]*big.Int, setting.n)
    all_d[0] = d_enc
    for i := 1; i < setting.n; i += 1 {
        all_d[i] = <-mask_channel
    }

    // send all_d
    for i := 1; i < setting.n; i += 1 {
        masks_channel <- all_d
    }

    // step 5: mask and decrypt
    var e_partial *tcpaillier.DecryptionShare
    e_partial, err = SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // recieve e_parts
    e_parts := make([]*tcpaillier.DecryptionShare, setting.n)
    e_parts[0] = e_partial
    for i := 1; i < setting.n; i += 1 {
        e_parts[i] = <-dec_channel
    }

    e, err := CombineShares(e_parts, setting)
    if err != nil {
        panic(err)
    }

    // step 7: assign share
    a_share := SecretShare(d_plain, e, setting)
    return a_share
}

func CentralASSWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                      mask_channel <-chan *big.Int,
                      masks_channel chan<- []*big.Int,
                      dec_channel <-chan *tcpaillier.DecryptionShare,
                      return_channel chan<- *big.Int) {
    
    return_channel <- CentralASSWorkerFunctionality(a, sk, setting, mask_channel, masks_channel, dec_channel)
}

func ASSWorkerFunctionality(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                            mask_channel chan<- *big.Int,
                            masks_channel <-chan []*big.Int,
                            dec_channel chan<- *tcpaillier.DecryptionShare) *big.Int {
    
    // step 1: sample d
    var d_plain *big.Int
    var d_enc *big.Int
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}

    mask_channel <- d_enc
    
    // recieve all_d
    var all_d []*big.Int
    all_d = <-masks_channel
    
    // step 5: mask and decrypt
    var e_partial *tcpaillier.DecryptionShare
    e_partial, err = SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // broadcast e_partial
    dec_channel <- e_partial
    
    // step 7: assign share
    a_share := NegateValue(d_plain, setting)
    return a_share
}

func ASSWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
               mask_channel chan<- *big.Int,
               masks_channel <-chan []*big.Int,
               dec_channel chan<- *tcpaillier.DecryptionShare,
               return_channel chan<- *big.Int) {
    return_channel <- ASSWorkerFunctionality(a, sk, setting, mask_channel, masks_channel, dec_channel)
}

func CentralMultWorker(a, b *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                       mask_channel <-chan *big.Int,
                       masks_channel chan<- []*big.Int,
                       dec_channel <-chan *tcpaillier.DecryptionShare,
                       return_channel chan<- *big.Int) {
    
    a_share := CentralASSWorkerFunctionality(a, sk, setting, mask_channel, masks_channel, dec_channel)

    // step 2: partial multiplication    
    prod, err := MultiplyEncrypted(b, a_share, setting)
    if err != nil {panic(err)}

    // recieve partial_prods
    partial_prods := make([]*big.Int, setting.n)
    partial_prods[0] = prod
    for i := 1; i < setting.n; i += 1 {
        partial_prods[i] = <-mask_channel
    }

    // send partial_prods
    for i := 1; i < setting.n; i += 1 {
        masks_channel <- partial_prods
    }

    // step 6: sum partials
    sum, err := SumMultiplication(partial_prods, setting)
    if err != nil {panic(err)}
    
    return_channel <- sum
}

func MultWorker(a, b *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                mask_channel chan<- *big.Int,
                masks_channel <-chan []*big.Int,
                dec_channel chan<- *tcpaillier.DecryptionShare,
                return_channel chan<- *big.Int) {
    
    a_share := ASSWorkerFunctionality(a, sk, setting, mask_channel, masks_channel, dec_channel)
    
    // step 2: partial multiplication    
    prod, err := MultiplyEncrypted(b, a_share, setting)
    if err != nil {panic(err)}

    // broadcast prod
    mask_channel <- prod

    // recieve partial_prods
    partial_prods := <-masks_channel

    // step 6: sum partials
    sum, err := SumMultiplication(partial_prods, setting)
    if err != nil {panic(err)}
    
    return_channel <- sum
}

func CentralZeroTestWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                           mask_channel <-chan *big.Int,
                           masks_channel chan<- []*big.Int,
                           dec_channel <-chan *tcpaillier.DecryptionShare,
                           shares_channel chan<- []*tcpaillier.DecryptionShare,
                           return_channel chan<- bool) {
    var err error
    masks := make([]*big.Int, setting.n)
    mask, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    mask, err = EncryptValue(mask, setting)
    if err != nil {panic(err)}
    
    masks[0] = mask
    for i := 1; i < setting.n; i += 1 {
        masks[i] = <-mask_channel
    }
    
    for i := 1; i < setting.n; i += 1 {
        masks_channel <- masks
    }

    sum, err := setting.pk.Add(masks...)
    if err != nil {panic(err)}

    local_ret_channel := make(chan *big.Int)

    go CentralMultWorker(a, sum, sk, setting, mask_channel, masks_channel, dec_channel, local_ret_channel)

    pred := <-local_ret_channel

    go CentralDecryptionWorker(pred, sk, setting, dec_channel, shares_channel, local_ret_channel)

    pred = <-local_ret_channel

    return_channel <- pred.Cmp(big.NewInt(0)) == 0    
}

func ZeroTestWorker(a *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                    mask_channel chan<- *big.Int,
                    //mask_sum_channel <-chan *big.Int,
                    masks_channel <-chan []*big.Int,
                    dec_channel chan<- *tcpaillier.DecryptionShare,
                    shares_channel <-chan []*tcpaillier.DecryptionShare,
                    return_channel chan<- bool) {

    mask, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}

    mask, err = EncryptValue(mask, setting)
    if err != nil {panic(err)}

    mask_channel <- mask

    masks := <-masks_channel

    sum, err := setting.pk.Add(masks...)
    if err != nil {panic(err)}

    local_ret_channel := make(chan *big.Int)

    go MultWorker(a, sum, sk, setting, mask_channel, masks_channel, dec_channel, local_ret_channel)

    pred := <-local_ret_channel

    go DecryptionWorker(pred, sk, setting, dec_channel, shares_channel, local_ret_channel)

    pred = <-local_ret_channel

    return_channel <- pred.Cmp(big.NewInt(0)) == 0    
}

func CentralDecryptionWorker(cipher *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                             dec_channel <-chan *tcpaillier.DecryptionShare,
                             shares_channel chan<- []*tcpaillier.DecryptionShare,
                             return_channel chan<- *big.Int) {
    partial, err := PartialDecryptValue(cipher, sk)
    if err != nil {panic(err)}

    ds := make([]*tcpaillier.DecryptionShare, setting.n)
    ds[0] = partial

    for i := 1; i < setting.n; i += 1 {
        ds[i] = <-dec_channel
    }

    for i := 1; i < setting.n; i += 1 {
        shares_channel <- ds
    }

    plain, err := CombineShares(ds, setting)
    if err != nil {panic(err)}

    return_channel <- plain.Mod(plain, setting.pk.N)
}

func DecryptionWorker(cipher *big.Int, sk *tcpaillier.KeyShare, setting Setting,
                      dec_channel chan<- *tcpaillier.DecryptionShare,
                      shares_channel <-chan []*tcpaillier.DecryptionShare,
                      return_channel chan<- *big.Int) {
    partial, err := PartialDecryptValue(cipher, sk)
    if err != nil {panic(err)}

    dec_channel <- partial

    ds := <-shares_channel

    plain, err := CombineShares(ds, setting)
    if err != nil {panic(err)}

    return_channel <- plain.Mod(plain, setting.pk.N)
}

// returns 4 slices through return_channel:
//  * q numerator
//  * q denominator
//  * r numerator
//  * r denominator (slice of size 1 as all coefficents share denominator)
func PolynomialDivisionWorker(a, b BigMatrix, a_den, b_den *big.Int, sk *tcpaillier.KeyShare, setting Setting, central bool,
                                mask_channel chan *big.Int,
                                masks_channel chan []*big.Int,
                                dec_channel chan *tcpaillier.DecryptionShare,
                                shares_channel chan []*tcpaillier.DecryptionShare,
                                mult_channel chan *big.Int,
                                sub_channel chan BigMatrix,
                                return_channel chan BigMatrix) {
    zeroTest := func (val *big.Int) bool {
        zt_channel := make(chan bool)
        if central {
            go CentralZeroTestWorker(val, sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        } else {
            go ZeroTestWorker(val, sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        }
        return <-zt_channel
    }
    multiply := func (a, b *big.Int) *big.Int {
        mul_channel := make(chan *big.Int)
        if central {
            go CentralMultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
        } else {
            go MultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
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
    q_num := make([]*big.Int, 1+la-lb)
    q_den := make([]*big.Int, 1+la-lb)

    for i := la; i >= lb; i -= 1 { // start at highest degree coefficient, go until dividend smaller than divisor
        // skip 0 coefficents
        if zeroTest(a_num.At(0,i)) {
            continue
        }

        pos := i-lb // entry in q at pos

        // q numerator: b_den * a_num
        num := multiply(a_num.At(0, i), b_den)
        q_num[pos] = num

        // q denominator: b_num * a_den
        den := multiply(b.At(0, lb), a_den)
        q_den[pos] = den

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

    return_channel <- NewBigMatrix(1, len(q_num), q_num)
    return_channel <- NewBigMatrix(1, len(q_den), q_den)
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

func MinPolyWorker(seq BigMatrix, rec_ord int, sk *tcpaillier.KeyShare, setting Setting, central bool,
                    mask_channel chan *big.Int,
                    masks_channel chan []*big.Int,
                    dec_channel chan *tcpaillier.DecryptionShare,
                    shares_channel chan []*tcpaillier.DecryptionShare,
                    mult_channel chan *big.Int,
                    sub_channel chan BigMatrix,
                    return_channel chan BigMatrix) {
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
        go PolynomialDivisionWorker(a, b, a_den, b_den, sk, setting, central, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, pol_div)
        q_num := <- pol_div
        q_den := <- pol_div
        r_num := <- pol_div
        r_den := <- pol_div
        t2_num, t2_den, err = nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den, sk, setting, central, mask_channel, masks_channel, dec_channel)
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

func nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, central bool,
            mask_channel chan *big.Int,
            masks_channel chan []*big.Int,
            dec_channel chan *tcpaillier.DecryptionShare) (t2_num, t2_den BigMatrix, err error) {
    p_num, p_den, err := PolyMult(t1_num, t1_den, q_num, q_den, sk, setting, central, mask_channel, masks_channel, dec_channel)
    if err != nil {return}
    t2_num, t2_den, err = PolySub(t0_num, t0_den, p_num, p_den, sk, setting, central, mask_channel, masks_channel, dec_channel)
    return
}

func PolySub(a_num, a_den, b_num, b_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, central bool,
                mask_channel chan *big.Int,
                masks_channel chan []*big.Int,
                dec_channel chan *tcpaillier.DecryptionShare) (diff_num, diff_den BigMatrix, err error) {
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
        if central {
            go CentralMultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, return_channel)
        } else {
            go MultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, return_channel)
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

func PolyMult(a_num, a_den, b_num, b_den BigMatrix, sk *tcpaillier.KeyShare, setting Setting, central bool,
                mask_channel chan *big.Int,
                masks_channel chan []*big.Int,
                dec_channel chan *tcpaillier.DecryptionShare) (prod_num, prod_den BigMatrix, err error) {
    prod_num, err = EncryptedFixedZeroMatrix(1, a_num.cols+b_num.cols-1, setting)
    if err != nil {return}
    prod_den, err = EncryptedFixedOneMatrix(1, prod_num.cols, setting)
    if err != nil {return}
    multiply := func (a, b *big.Int) *big.Int {
        return_channel := make(chan *big.Int)
        if central {
            go CentralMultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, return_channel)
        } else {
            go MultWorker(a, b, sk, setting, mask_channel, masks_channel, dec_channel, return_channel)
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

func CentralMatrixMultiplicationWorker(a, b BigMatrix, sk *tcpaillier.KeyShare, setting Setting,
                                    mats_channels []chan BigMatrix,
                                    dec_channels []chan PartialMatrix,
                                    return_channel chan<- BigMatrix) {
    if a.cols != b.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.rows, a.cols, b.rows, b.cols))
    }
    
    // step 1
    RAs_crypt := make([]BigMatrix, setting.n)
    RBs_crypt := make([]BigMatrix, setting.n)
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    RAs_crypt[0] = RAi_crypt
    RBs_crypt[0] = RBi_crypt
    for i := 1; i < setting.n; i += 1 {
        RAs_crypt[i] = <-mats_channels[i-1]
        RBs_crypt[i] = <-mats_channels[i-1]
    }

    // step 2
    RA, MA, MB, err := GetMulMatrices(a, b, RAs_crypt, RBs_crypt, setting)
    if err != nil {panic(err)}
    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] <- RA
        mats_channels[i] <- MA
        mats_channels[i] <- MB
    }

    // step 3
    cts := make([]BigMatrix, setting.n)
    MA_parts := make([]PartialMatrix, setting.n)
    MB_parts := make([]PartialMatrix, setting.n)
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    cts[0] = cti
    MA_parts[0] = MA_part
    MB_parts[0] = MB_part
    for i := 1; i < setting.n; i += 1 {
        cts[i] = <-mats_channels[i-1]
        MA_parts[i] = <-dec_channels[i-1]
        MB_parts[i] = <-dec_channels[i-1]
    }

    // step 4
    AB, err := CombineMatrixMultiplication(MA_parts, MB_parts, cts, setting)
    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] <- AB
    }

    return_channel <- AB

}

func MatrixMultiplicationWorker(a, b BigMatrix, sk *tcpaillier.KeyShare, setting Setting,
                                mat_channel chan BigMatrix,
                                dec_channel chan<- PartialMatrix,
                                return_channel chan<- BigMatrix) {
    if a.cols != b.rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.rows, a.cols, b.rows, b.cols))
    }

    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    mat_channel <- RAi_crypt
    mat_channel <- RBi_crypt

    // step 2
    RA := <- mat_channel
    MA := <- mat_channel
    MB := <- mat_channel

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    mat_channel <- cti
    dec_channel <- MA_part
    dec_channel <- MB_part

    // step 4
    AB := <-mat_channel

    return_channel <- AB
}

func CentralSingularityTestWorker(m BigMatrix, sk *tcpaillier.KeyShare, setting Setting,
                                mats_channels []chan BigMatrix,
                                pm_channels []chan PartialMatrix,
                                mask_channel chan *big.Int,
                                masks_channel chan []*big.Int,
                                dec_channel chan *tcpaillier.DecryptionShare,
                                shares_channel chan []*tcpaillier.DecryptionShare,
                                mult_channel chan *big.Int,
                                sub_channel chan BigMatrix,
                                return_channel chan bool) {
    // step b
    v, err := SampleVVector(m, setting)
    if err != nil {panic(err)}
    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] <- v
    }

    // step c
    its := NbrMMultInstances(m)
    mats := make([]BigMatrix, its+1)
    mats[0] = m
    ret := make(chan BigMatrix)
    for i := 0; i < its; i += 1 {
        go CentralMatrixMultiplicationWorker(mats[i], mats[i], sk, setting, mats_channels, pm_channels, ret)
        mats[i+1] = <-ret
    }

    //step d
    semi_seq := v
    for _, mat := range mats {
        go CentralMatrixMultiplicationWorker(mat, semi_seq, sk, setting, mats_channels, pm_channels, ret)
        new_semi_seq := <-ret
        semi_seq = ConcatenateMatrices(new_semi_seq, semi_seq)
    }

    // step e
    seq, err := HSeq(semi_seq, m.cols, setting)
    if err != nil {panic(err)}

    // distribute seq instead of decrypted secret sharing
    for i := 0; i < setting.n-1; i += 1 {
        mats_channels[i] <- seq
    }

    // step i
    rec_ord := m.cols
    go MinPolyWorker(seq, rec_ord, sk, setting, true, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, ret)
    min_poly := <-ret
    <-ret

    retu := make(chan bool)
    go CentralZeroTestWorker(min_poly.At(0,0), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, retu)

    return_channel <- <-retu
}

func SingularityTestWorker(m BigMatrix, sk *tcpaillier.KeyShare, setting Setting,
                            mats_channel chan BigMatrix,
                            pm_channel chan PartialMatrix,
                            mask_channel chan *big.Int,
                            masks_channel chan []*big.Int,
                            dec_channel chan *tcpaillier.DecryptionShare,
                            shares_channel chan []*tcpaillier.DecryptionShare,
                            mult_channel chan *big.Int,
                            sub_channel chan BigMatrix,
                            return_channel chan bool) {
    // step b
    v := <-mats_channel

    // step c
    its := NbrMMultInstances(m)
    mats := make([]BigMatrix, its+1)
    mats[0] = m
    mm_ret := make(chan BigMatrix)
    for i := 0; i < its; i += 1 {
        go MatrixMultiplicationWorker(mats[i], mats[i], sk, setting, mats_channel, pm_channel, mm_ret)
        mats[i+1] = <-mm_ret
    }

    //step d
    semi_seq := v
    for i := range mats {
        go MatrixMultiplicationWorker(mats[i], semi_seq, sk, setting, mats_channel, pm_channel, mm_ret)
        new_semi_seq := <-mm_ret
        semi_seq = ConcatenateMatrices(new_semi_seq, semi_seq)
    }

    seq := <-mats_channel

    // step i
    rec_ord := m.cols
    go MinPolyWorker(seq, rec_ord, sk, setting, false, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, mm_ret)
    min_poly := <-mm_ret
    <-mm_ret

    retu := make(chan bool)
    go ZeroTestWorker(min_poly.At(0,0), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, retu)

    return_channel <- <-retu
}