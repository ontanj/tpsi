package tpsi

import (
    "github.com/ldsec/lattigo/bfv"
    "github.com/ldsec/lattigo/dbfv"
    "github.com/ldsec/lattigo/ring"
    "math/big"
)

type fhe_setting struct {
    params *bfv.Parameters
    pk *bfv.PublicKey
    rlk *bfv.EvaluationKey
    tpk *bfv.PublicKey
    tsk *bfv.SecretKey
    crs *ring.Poly
    crp []*ring.Poly
    n int
    T int
}

func CentralKeyGenerator(setting fhe_setting, channels []chan interface{}) (*bfv.PublicKey, *bfv.SecretKey, *bfv.EvaluationKey) {
    // generate secret key
    sk := bfv.NewKeyGenerator(setting.params).GenSecretKey()


    // generate public key
    ckg := dbfv.NewCKGProtocol(setting.params)
    ckgShare := ckg.AllocateShares()
    ckg.GenShare(sk.Get(), setting.crs, ckgShare)

    ckgCombined := ckg.AllocateShares()
    ckg.AggregateShares(ckgShare, ckgCombined, ckgCombined) // aggregate all shares to ckgCombined
    for _, ch := range channels {
        ckg.AggregateShares((<-ch).(dbfv.CKGShare), ckgCombined, ckgCombined) // aggregate all shares to ckgCombined
    }
    pk := bfv.NewPublicKey(setting.params)
    ckg.GenPublicKey(ckgCombined, setting.crs, pk) // generate public key

    // distribute public key
    for _, ch := range channels {
        ch <- pk
    }

    // generate relinearization key
    rkg := dbfv.NewEkgProtocol(setting.params)
    contextKeys, _ := ring.NewContextWithParams(1<<setting.params.LogN, append(setting.params.Qi, setting.params.Pi...))
    rlkEphemSk := contextKeys.SampleTernaryMontgomeryNTTNew(1.0 / 3)
    rkgShareOne, rkgShareTwo, rkgShareThree := rkg.AllocateShares()

    rkg.GenShareRoundOne(rlkEphemSk, sk.Get(), setting.crp, rkgShareOne)  //TODO

    rkgCombined1, rkgCombined2, rkgCombined3 := rkg.AllocateShares()
    rkg.AggregateShareRoundOne(rkgShareOne, rkgCombined1, rkgCombined1)
    for _, ch := range channels {
        rkg.AggregateShareRoundOne((<-ch).(dbfv.RKGShareRoundOne), rkgCombined1, rkgCombined1)
    }
    for _, ch := range channels {
        ch <- rkgCombined1
    }
    
    rkg.GenShareRoundTwo(rkgCombined1, sk.Get(), setting.crp, rkgShareTwo)
    
    rkg.AggregateShareRoundTwo(rkgShareTwo, rkgCombined2, rkgCombined2)
    for _, ch := range channels {
        rkg.AggregateShareRoundTwo((<-ch).(dbfv.RKGShareRoundTwo), rkgCombined2, rkgCombined2)
    }
    for _, ch := range channels {
        ch <- rkgCombined2
    }
    
    rkg.GenShareRoundThree(rkgCombined2, rlkEphemSk, sk.Get(), rkgShareThree)
    
    rkg.AggregateShareRoundThree(rkgShareThree, rkgCombined3, rkgCombined3)
    for _, ch := range channels {
        rkg.AggregateShareRoundThree((<-ch).(dbfv.RKGShareRoundThree), rkgCombined3, rkgCombined3)
    }
    
    rlk := bfv.NewRelinKey(setting.params, 1)
    rkg.GenRelinearizationKey(rkgCombined2, rkgCombined3, rlk)
    for _, ch := range channels {
        ch <- rlk
    }
    
    return pk, sk, rlk
}

func OuterKeyGenerator(setting fhe_setting, channel chan interface{}) (*bfv.PublicKey, *bfv.SecretKey, *bfv.EvaluationKey) {

    // generate secret key
    sk := bfv.NewKeyGenerator(setting.params).GenSecretKey()

    // generate public key
    ckg := dbfv.NewCKGProtocol(setting.params)
    ckgShare := ckg.AllocateShares()
    ckg.GenShare(sk.Get(), setting.crs, ckgShare)
    channel <- ckgShare
    pk := (<-channel).(*bfv.PublicKey)

    // generate relinearization key
    rkg := dbfv.NewEkgProtocol(setting.params)
    contextKeys, _ := ring.NewContextWithParams(1<<setting.params.LogN, append(setting.params.Qi, setting.params.Pi...))
    rlkEphemSk := contextKeys.SampleTernaryMontgomeryNTTNew(1.0 / 3)
    rkgShareOne, rkgShareTwo, rkgShareThree := rkg.AllocateShares()

    rkg.GenShareRoundOne(rlkEphemSk, sk.Get(), setting.crp, rkgShareOne)

    channel <- rkgShareOne
    rkgCombined1 := (<-channel).(dbfv.RKGShareRoundOne)

    rkg.GenShareRoundTwo(rkgCombined1, sk.Get(), setting.crp, rkgShareTwo)

    channel <- rkgShareTwo
    rkgCombined2 := (<-channel).(dbfv.RKGShareRoundTwo)
    
    rkg.GenShareRoundThree(rkgCombined2, rlkEphemSk, sk.Get(), rkgShareThree)

    channel <- rkgShareThree
    rlk := (<-channel).(*bfv.EvaluationKey)

    return pk, sk, rlk
}

func CentralDecryptor(enc *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) []uint64 {
    pcks := dbfv.NewPCKSProtocol(setting.params, 3.19)
    pcksShare := pcks.AllocateShares()
    pcks.GenShare(sk.Get(), setting.tpk, enc, pcksShare)
    
    pcksCombined := pcks.AllocateShares()
    pcks.AggregateShares(pcksShare, pcksCombined, pcksCombined)
    for _, ch := range channels {
        pcks.AggregateShares((<-ch).(dbfv.PCKSShare), pcksCombined, pcksCombined)
    }

    encOut := bfv.NewCiphertext(setting.params, 1)
    pcks.KeySwitch(pcksCombined, enc, encOut)

    decryptor := bfv.NewDecryptor(setting.params, setting.tsk)
    ptres := bfv.NewPlaintext(setting.params)
    decryptor.Decrypt(encOut, ptres)
    encoder := bfv.NewEncoder(setting.params)
    dec := encoder.DecodeUint(ptres)
    
    for _, ch := range channels {
        ch <- dec
    }

    return dec

}

func OuterDecryptor(enc *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) []uint64 {
    pcks := dbfv.NewPCKSProtocol(setting.params, 3.19)
    pcksShare := pcks.AllocateShares()
    pcks.GenShare(sk.Get(), setting.tpk, enc, pcksShare)

    channel <- pcksShare

    dec := (<-channel).([]uint64)

    return dec
}

func GenCRP(params *bfv.Parameters) (*ring.Poly, []*ring.Poly) {
    contextKeys, _ := ring.NewContextWithParams(1<<params.LogN, append(params.Qi, params.Pi...))
    crsGen := ring.NewCRPGenerator([]byte{'o', 'n', 't', 'a', 'n', 'j'}, contextKeys)
    crs := crsGen.ClockNew()
    crp := make([]*ring.Poly, params.Beta())
    for i := uint64(0); i < params.Beta(); i++ {
        crp[i] = crsGen.ClockNew()
    }
    return crs, crp
}

func CentralInverseWorker(a *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) *bfv.Ciphertext {
    return CentralInverseWorkerWithFactor(a, 1, sk, setting, channels)
}

func CentralInverseWorkerWithFactor(a *bfv.Ciphertext, factor uint64, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) *bfv.Ciphertext {
    big_mask, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    int_mask := big_mask.Uint64()
    mask := Encrypt(int_mask, setting)
    
    evaluator := bfv.NewEvaluator(setting.params)
    for _, ch := range channels {
        store := evaluator.MulNew(mask, (<-ch).(*bfv.Ciphertext))
        mask = evaluator.RelinearizeNew(store, setting.rlk)
    }

    store := evaluator.MulNew(mask, a)
    ab_enc := evaluator.RelinearizeNew(store, setting.rlk)

    for _, ch := range channels {
        ch <- ab_enc
    }

    ab := CentralDecryptor(ab_enc, sk, setting, channels)

    ab_big := new(big.Int).SetUint64(ab[0]*factor)
    ab_big.ModInverse(ab_big, new(big.Int).SetUint64(setting.params.T))
    ab_inv := ab_big.Uint64()

    ab_inv_enc := Encrypt(ab_inv, setting)
    
    store = evaluator.MulNew(ab_inv_enc, mask)
    a_inv := evaluator.RelinearizeNew(store, setting.rlk)

    for _, ch := range channels {
        ch <- a_inv
    }

    return a_inv
}

func OuterInverseWorker(sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) *bfv.Ciphertext {
    big_mask, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    mask := big_mask.Uint64()

    cipher := Encrypt(mask, setting)

    channel <- cipher
    
    ab_enc := (<-channel).(*bfv.Ciphertext)

    OuterDecryptor(ab_enc, sk, setting, channel)

    a_inv := (<-channel).(*bfv.Ciphertext)

    return a_inv
}

func Encrypt(val uint64, setting fhe_setting) *bfv.Ciphertext {
    encoder := bfv.NewEncoder(setting.params)
    pt := bfv.NewPlaintext(setting.params)
    encoder.EncodeUint([]uint64{val}, pt)
    
    encryptor := bfv.NewEncryptorFromPk(setting.params, setting.pk)
    enc := bfv.NewCiphertext(setting.params, 1)
    encryptor.Encrypt(pt, enc)

    return enc
}

func CentralFHEZeroTestWorker(a *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) bool {
    self := setting.n-1
    
    mask_big, err := SampleInt(new(big.Int).SetUint64(setting.params.T-1))
    if err != nil {panic(err)}
    mask_plain := mask_big.Uint64() + 1

    sum := Encrypt(mask_plain, setting)
    
    evaluator := bfv.NewEvaluator(setting.params)
    for i := 0; i < self; i += 1 {
        evaluator.Add(sum, (<-channels[i]).(*bfv.Ciphertext), sum)
    }

    store := bfv.NewCiphertext(setting.params, 2)
    evaluator.Mul(sum, a, store)
    evaluator.Relinearize(store, setting.rlk, sum)

    for _, ch := range channels {
        ch <- sum
    }
    
    pred := CentralDecryptor(sum, sk, setting, channels)

    return pred[0] == 0
}

func OuterFHEZeroTestWorker(sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) bool {

    mask_big, err := SampleInt(new(big.Int).SetUint64(setting.params.T-1))
    if err != nil {panic(err)}
    mask_plain := mask_big.Uint64() + 1

    mask := Encrypt(mask_plain, setting)

    channel <- mask

    masked := (<-channel).(*bfv.Ciphertext)

    pred := OuterDecryptor(masked, sk, setting, channel)

    return pred[0] == 0    
}

func CentralRefresh(cipher *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) *bfv.Ciphertext {
    rpf := dbfv.NewRefreshProtocol(setting.params)
    share := rpf.AllocateShares()
    rpf.GenShares(sk.Get(), cipher, setting.crs, share)

    for _, ch := range channels {
        rpf.Aggregate(share, (<-ch).(dbfv.RefreshShare), share)
    }
    
    newCipher := bfv.NewCiphertext(setting.params, 1)
    rpf.Finalize(cipher, setting.crs, share, newCipher)

    for _, ch := range channels {
        ch <- newCipher
    }

    return newCipher
}


func OuterRefresh(cipher *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) *bfv.Ciphertext {
    rpf := dbfv.NewRefreshProtocol(setting.params)
    share := rpf.AllocateShares()
    rpf.GenShares(sk.Get(), cipher, setting.crs, share)

    channel <- share
    
    newCipher := (<-channel).(*bfv.Ciphertext)
    
    return newCipher
}

func CentralFHEInterpolation(q []*bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}) []*bfv.Ciphertext {
    sample_max := 2*setting.T + 3

    relations := make([][]*bfv.Ciphertext, sample_max)
    zero := Encrypt(0, setting)

    evaluator := bfv.NewEvaluator(setting.params)
    coeff_pos := 0
    for ; coeff_pos < sample_max; coeff_pos += 1 {
        eq := make([]*bfv.Ciphertext, sample_max + 1)
        
        x := uint64(2*coeff_pos+1)
        x_pow := uint64(1)
        
        // populate rel_row with full equation
        j := 0
        for ; j < setting.T + 2; j += 1 {
            eq[j] = Encrypt(x_pow, setting)
            x_pow *= x
        }
        x_pow = 1
        for ; j < sample_max + 1; j += 1 {
            store := evaluator.MulNew(q[coeff_pos], Encrypt(setting.params.T-x_pow, setting))
            eq[j] = evaluator.RelinearizeNew(store, setting.rlk)
            x_pow = x_pow*x % setting.params.T
        }

        // substitue previous coefficents
        for prev_coeff := 0; prev_coeff < coeff_pos; prev_coeff += 1 {
            coeff := eq[prev_coeff]
            for i := prev_coeff + 1; i < sample_max + 1; i += 1 {
                store := evaluator.MulNew(relations[prev_coeff][i], coeff)
                evaluator.Relinearize(store, setting.rlk, store)
                if prev_coeff % 5 == 0 {
                    for _, ch := range channels {
                        ch <- store
                    }
                    store = CentralRefresh(store, sk, setting, channels)
                }
                evaluator.Add(store, eq[i], eq[i])
            }
            eq[prev_coeff] = Encrypt(0, setting)
        }
        
        // if we get 0 = 0, we have all relations needed
        if CentralFHEZeroTestWorker(eq[coeff_pos], sk, setting, channels) {
            break
        }
        
        // collect current coefficient
        rel_row := make([]*bfv.Ciphertext, sample_max + 1)
        coeff_inv := CentralInverseWorkerWithFactor(eq[coeff_pos], setting.params.T-1, sk, setting, channels)
        rem_coeff := 0
        for ; rem_coeff < coeff_pos + 1; rem_coeff += 1 {
            rel_row[rem_coeff] = zero
        }
        for ; rem_coeff < sample_max + 1; rem_coeff += 1 {
            store := evaluator.MulNew(eq[rem_coeff], coeff_inv)
            rel := evaluator.RelinearizeNew(store, setting.rlk)
            for _, ch := range channels {
                ch <- rel
            }
            rel_row[rem_coeff] = CentralRefresh(rel, sk, setting, channels)
        }

        relations[coeff_pos] = rel_row
    }

    interpolated_coeffs := make([]*bfv.Ciphertext, sample_max + 1)
    interpolated_coeffs[coeff_pos] = Encrypt(1, setting)
    
    // solve all coefficients from relations
    for solving_coeff := coeff_pos - 1; solving_coeff >= 0; solving_coeff -= 1 {
        coeff := Encrypt(0, setting)
        for known_coeff := solving_coeff + 1; known_coeff <= coeff_pos; known_coeff += 1 {
            store := evaluator.MulNew(relations[solving_coeff][known_coeff], interpolated_coeffs[known_coeff])
            evaluator.Relinearize(store, setting.rlk, store)
            evaluator.Add(coeff, store, coeff)
        }
        for _, ch := range channels {
            ch <- coeff
        }
        coeff = CentralRefresh(coeff, sk, setting, channels)
        interpolated_coeffs[solving_coeff] = coeff
    }

    return interpolated_coeffs[:coeff_pos+1]
}

func OuterFHEInterpolation(sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) {
    sample_max := 2*setting.T + 3
    coeff_pos := 0
    for ; coeff_pos < sample_max; coeff_pos += 1 {
        for prev_coeff := 0; prev_coeff < coeff_pos; prev_coeff += 1 {
            for i := prev_coeff + 1; i < sample_max + 1; i += 1 {
                if prev_coeff % 5 == 0 {
                    OuterRefresh((<-channel).(*bfv.Ciphertext), sk, setting, channel)
                }
            }
        }
        if OuterFHEZeroTestWorker(sk, setting, channel) {
            break
        }
        OuterInverseWorker(sk, setting, channel)
        for rem_coeff := coeff_pos + 1 ; rem_coeff < sample_max + 1; rem_coeff += 1 {
            OuterRefresh((<-channel).(*bfv.Ciphertext), sk, setting, channel)
        }
    }
    for solving_coeff := coeff_pos - 1; solving_coeff >= 0; solving_coeff -= 1 {
        OuterRefresh((<-channel).(*bfv.Ciphertext), sk, setting, channel)
    }
}

func invert(val, mod uint64) uint64 {
    return new(big.Int).ModInverse(new(big.Int).SetUint64(val), new(big.Int).SetUint64(mod)).Uint64()
}

// returns true if cardinality test passes
func CentralFHECardinalityTestWorker(items []uint64, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}, channel chan interface{}) bool {

    // step 2
    s, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    z := s.Uint64()
    for _, ch := range channels {
        ch <- z
    }

    // step 3
    // add mask to polynomial
    mod := new(big.Int).SetUint64(setting.params.T)
    big_rand, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    rand := big_rand.Uint64()
    p := PolyFromRoots(append(items, rand), mod)
    
    // evaluate root polynomial
    plain_evals := make([]uint64, 2*setting.T+3)
    evals := make([]*bfv.Ciphertext, 2*setting.T+3)
    var point uint64
    for i := range evals {
        point = uint64(i * 2 + 1)
        plain_evals[i] = EvalPoly(p, point, mod).Uint64()
        evals[i] = Encrypt(plain_evals[i], setting)
    }
    eval := EvalPoly(p, z, mod)
    z_eval := Encrypt(eval.Uint64(), setting)

    // collect outer parties evaluations
    evaluator := bfv.NewEvaluator(setting.params)
    all_evals := make([][]*bfv.Ciphertext, setting.n-1)
    z_evals := Encrypt(0, setting)
    for i, ch := range channels {
        all_evals[i] = (<-ch).([]*bfv.Ciphertext)
        evaluator.Add(z_evals, (<-ch).(*bfv.Ciphertext), z_evals)
    }
    
    // step 4
    // evaluate rational polynomial
    evals_sum := make([]*bfv.Ciphertext, 2*setting.T+3)
    for i := range evals_sum {
        sum := bfv.NewCiphertext(setting.params, 1)
        for _, eval := range all_evals {
            evaluator.Add(sum, eval[i], sum)
        }
        inv := invert(plain_evals[i], setting.params.T)
        inv_enc := Encrypt(inv, setting)
        store := evaluator.MulNew(inv_enc, sum)
        evals_sum[i] = evaluator.RelinearizeNew(store, setting.rlk)
    }
    
    // interpolate
    interpol := CentralFHEInterpolation(evals_sum, sk, setting, channels)
    num := interpol[:setting.T+2]
    den := interpol[setting.T+2:]

    num_eval := FHEEvaluate(z, num, setting)
    den_eval := FHEEvaluate(z, den, setting)

    // compare interpolation with expected result
    den_inv := CentralInverseWorkerWithFactor(den_eval, setting.params.T-1, sk, setting, channels)
    store := evaluator.MulNew(num_eval, den_inv)
    int_eval := evaluator.RelinearizeNew(store, setting.rlk)
    
    z_den_inv := CentralInverseWorker(z_eval, sk, setting, channels)
    evaluator.Mul(z_evals, z_den_inv, store)
    exp_eval := evaluator.RelinearizeNew(store, setting.rlk)
    
    pred := evaluator.AddNew(int_eval, exp_eval)

    for _, ch := range channels {
        ch <- pred
    }
    pred = CentralRefresh(pred, sk, setting, channels)
    return CentralFHEZeroTestWorker(pred, sk, setting, channels)
}

// returns true if cardinality test passes
func OuterFHECardinalityTestWorker(items []uint64, sk *bfv.SecretKey, setting fhe_setting, channels []chan interface{}, channel chan interface{}) bool {

    // step 2
    z := (<-channel).(uint64)

    // step 3
    mod := new(big.Int).SetUint64(setting.params.T)
    big_rand, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    rand := big_rand.Uint64()
    p := PolyFromRoots(append(items, rand), mod)
    plain_evals := make([]uint64, 2*setting.T+3)
    evals := make([]*bfv.Ciphertext, 2*setting.T+3)
    var point uint64
    for i := range evals {
        point = uint64(i * 2 + 1)
        plain_evals[i] = EvalPoly(p, point, mod).Uint64()
        evals[i] = Encrypt(plain_evals[i], setting)
    }
    eval := EvalPoly(p, z, mod)
    z_eval := Encrypt(eval.Uint64(), setting)
    channel <- evals
    channel <- z_eval
    
    // step 4
    OuterFHEInterpolation(sk, setting, channel)
    OuterInverseWorker(sk, setting, channel)
    OuterInverseWorker(sk, setting, channel)
    OuterRefresh((<-channel).(*bfv.Ciphertext), sk, setting, channel)
    return OuterFHEZeroTestWorker(sk, setting, channel)
       
}

func FHEEvaluate(x uint64, poly []*bfv.Ciphertext, setting fhe_setting) *bfv.Ciphertext {
    sum := poly[0]
    x_raised := x
    evaluator := bfv.NewEvaluator(setting.params)
    for i := 1; i < len(poly); i += 1 {
        x_enc := Encrypt(x_raised, setting)
        store := evaluator.MulNew(x_enc, poly[i])
        prod := evaluator.RelinearizeNew(store, setting.rlk)
        sum = evaluator.AddNew(sum, prod)
        x_raised *= x
    }
    return sum
}