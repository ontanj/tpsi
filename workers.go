package tpsi

import (
    "math/big"
    "github.com/niclabs/tcpaillier"
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
    
    zt_channel := make(chan bool)
    var la int // degree of dividend
    for la = a.cols-1; la >= 0; la -= 1 { // find degree of divisor
        if central {
            go CentralZeroTestWorker(a.At(0,la), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        } else {
            go ZeroTestWorker(a.At(0,la), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        }
        if !(<-zt_channel) {
            break
        }
    }
    var lb int // degree of divisor
    for lb = b.cols-1; lb >= 0; lb -= 1 { // find degree of divisor
        if central {
            go CentralZeroTestWorker(b.At(0,lb), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        } else {
            go ZeroTestWorker(b.At(0,lb), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        }
        if !(<-zt_channel) {
            break
        }
    }
    a_num := a
    q_num := make([]*big.Int, 1+la-lb)
    q_den := make([]*big.Int, 1+la-lb)
    mul_channel := make(chan *big.Int)

    for i := la; i >= lb; i -= 1 { // start at highest degree coefficient, go until dividend smaller than divisor
        if central { // skip 0 coefficents
            go CentralZeroTestWorker(a_num.At(0, i), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        } else {
            go ZeroTestWorker(a_num.At(0, i), sk, setting, mask_channel, masks_channel, dec_channel, shares_channel, zt_channel)
        }
        if <-zt_channel {
            continue
        }

        pos := i-lb // entry in q at pos

        // q numerator: b_den * a_num
        if central {
            go CentralMultWorker(a_num.At(0, i), b_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
        } else {
            go MultWorker(a_num.At(0, i), b_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
        }
        num := <-mul_channel
        q_num[pos] = num

        // q denominator: b_num * a_den
        if central {
            go CentralMultWorker(b.At(0, lb), a_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
        } else {
            go MultWorker(b.At(0, lb), a_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
        }
        den := <-mul_channel
        q_den[pos] = den

        // p = q_val * b
        p_num := NewBigMatrix(1, lb, nil) // partial result, size is degree of (partial) dividend - 1 = i , skip highest coefficient as it is cancelling
        for j := 0; j < lb; j += 1 {
            if central {
                go CentralMultWorker(num, b.At(0, j), sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            } else {
                go MultWorker(num, b.At(0, j), sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            }
            val := <-mul_channel
            p_num.Set(0, j, val)
        }
        p_den := den

        // make common denominator for p and a
        r_num := NewBigMatrix(1, i, nil)
        for i := 0; i < r_num.cols; i += 1 {
            if central {
                go CentralMultWorker(a_num.At(0, i), p_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            } else {
                go MultWorker(a_num.At(0, i), p_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            }
            val := <-mul_channel
            r_num.Set(0, i, val)
        }
        for i := 0; i < p_num.cols; i += 1 {
            if central {
                go CentralMultWorker(p_num.At(0, i), a_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            } else {
                go MultWorker(p_num.At(0, i), a_den, sk, setting, mask_channel, masks_channel, dec_channel, mul_channel)
            }
            val := <-mul_channel
            p_num.Set(0, i, val)
        }
        ret := make(chan *big.Int)
        if central {
            go CentralMultWorker(a_den, p_den, sk, setting, mask_channel, masks_channel, dec_channel, ret)
        } else {
            go MultWorker(a_den, p_den, sk, setting, mask_channel, masks_channel, dec_channel, ret)
        }
        r_den := <-ret

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
