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

// func Encrypt(input []uint64, params *bfv.Parameters, pk *bfv.PublicKey) *bfv.Ciphertext {
    
//     encInput := bfv.NewCiphertext(params, 1)
//     encryptor.Encrypt(pt, encInput)
//     return encInput
// }

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
    big_mask, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    mask := big_mask.Uint64()

    encoder := bfv.NewEncoder(setting.params)
    encryptor := bfv.NewEncryptorFromPk(setting.params, setting.pk)
    evaluator := bfv.NewEvaluator(setting.params)

    mask_pt := bfv.NewPlaintext(setting.params)
    encoder.EncodeUint([]uint64{mask}, mask_pt)

    mask_enc := bfv.NewCiphertext(setting.params, 1)
    store := bfv.NewCiphertext(setting.params, 2)
    ab_enc := bfv.NewCiphertext(setting.params, 1)
    encryptor.Encrypt(mask_pt, mask_enc)
    
    all_masks := make([]*bfv.Ciphertext, setting.n)
    all_masks[setting.n-1] = mask_enc

    evaluator.Mul(a, mask_enc, store)
    evaluator.Relinearize(store, setting.rlk, ab_enc)

    for i, ch := range channels {
        mask := (<-ch).(*bfv.Ciphertext)
        all_masks[i] = mask
        evaluator.Mul(ab_enc, mask, store)
        evaluator.Relinearize(store, setting.rlk, ab_enc)
    }

    for _, ch := range channels {
        ch <- ab_enc
    }

    ab := CentralDecryptor(ab_enc, sk, setting, channels)

    ab_big := new(big.Int).SetUint64(ab[0])
    ab_big.ModInverse(ab_big, new(big.Int).SetUint64(setting.params.T))
    ab_inv := ab_big.Uint64()
    
    inv_pt := bfv.NewPlaintext(setting.params)
    encoder.EncodeUint([]uint64{ab_inv}, inv_pt)
    inv_enc := bfv.NewCiphertext(setting.params, 1)
    encryptor.Encrypt(inv_pt, inv_enc)
    
    for _, mask := range all_masks {
        evaluator.Mul(inv_enc, mask, store)
        evaluator.Relinearize(store, setting.rlk, inv_enc)
    }

    for _, ch := range channels {
        ch <- inv_enc
    }

    return inv_enc

}

func OuterInverseWorker(a *bfv.Ciphertext, sk *bfv.SecretKey, setting fhe_setting, channel chan interface{}) *bfv.Ciphertext {
    big_mask, err := SampleInt(new(big.Int).SetUint64(setting.params.T))
    if err != nil {panic(err)}
    mask := big_mask.Uint64()

    encoder := bfv.NewEncoder(setting.params)
    pt := bfv.NewPlaintext(setting.params)
    encoder.EncodeUint([]uint64{mask}, pt)
    encryptor := bfv.NewEncryptorFromPk(setting.params, setting.pk)
    cipher := bfv.NewCiphertext(setting.params, 1)
    encryptor.Encrypt(pt, cipher)

    channel <- cipher

    ab_enc := (<-channel).(*bfv.Ciphertext)
    OuterDecryptor(ab_enc, sk, setting, channel)

    a_inv := (<-channel).(*bfv.Ciphertext)

    return a_inv

}