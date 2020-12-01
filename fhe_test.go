package tpsi

import (
    "testing"
    "github.com/ldsec/lattigo/bfv"
    "math/big"
)

func TestEncryptDecrypt(t *testing.T) {
	var setting fhe_setting
    params := bfv.DefaultParams[bfv.PN14QP438]
	params.T = 65537
	setting.params = params
    val := make([]uint64, 1)
    val[0] = 5
    n := 4
    channels := create_chans(n-1)
    return_channels := create_chans(n)
	crs, crp := GenCRP(params)
	setting.crs = crs
	setting.crp = crp
    encoder := bfv.NewEncoder(params)
    pt := bfv.NewPlaintext(params)
    encoder.EncodeUint(val, pt)
    
    go func() {
        pk, sk, _ := CentralKeyGenerator(setting, channels)
        return_channels[n-1] <- pk
        return_channels[n-1] <- sk
    }()
        for i := 0; i < n-1; i += 1 {
        go func(i int) {
            pk, sk, _ := OuterKeyGenerator(setting, channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
        }(i)
    }
    sk := make([]*bfv.SecretKey, n)
    var pk *bfv.PublicKey
    for i, ch := range return_channels {
        pk = (<-ch).(*bfv.PublicKey)
        sk[i] = (<-ch).(*bfv.SecretKey)
    }
    
    encryptor := bfv.NewEncryptorFromPk(params, pk)
    enc := bfv.NewCiphertext(params, 1)
    encryptor.Encrypt(pt, enc)

    ret := make(chan []uint64)
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
	setting.tsk = tsk
	setting.tpk = tpk
    go func() {
        ret <- CentralDecryptor(enc, sk[n-1], setting, channels)
    }()
    for i := 0; i < n-1; i += 1 {
        go func(i int) {
            ret <- OuterDecryptor(enc, sk[i], setting, channels[i])
        }(i)
    }
    dec := <-ret
    
    if dec[0] != val[0] {
        t.Errorf("wrong value after decryption, got %d", dec)
    }
}

func TestEvaluation(t *testing.T) {
    params := bfv.DefaultParams[bfv.PN14QP438]
	params.T = 65537
	var setting fhe_setting
	setting.params = params
    val1 := make([]uint64, 1)
    val1[0] = 5
    val2 := make([]uint64, 1)
    val2[0] = 6
    n := 4
    channels := create_chans(n-1)
    return_channels := create_chans(n)
	crs, crp := GenCRP(params)
	setting.crs = crs
	setting.crp = crp
    encoder := bfv.NewEncoder(params)
    pt1 := bfv.NewPlaintext(params)
    encoder.EncodeUint(val1, pt1)
    pt2 := bfv.NewPlaintext(params)
    encoder.EncodeUint(val2, pt2)
    
    go func() {
        pk, sk, rlk := CentralKeyGenerator(setting, channels)
        return_channels[n-1] <- pk
        return_channels[n-1] <- sk
        return_channels[n-1] <- rlk
    }()
        for i := 0; i < n-1; i += 1 {
        go func(i int) {
            pk, sk, rlk := OuterKeyGenerator(setting, channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
            return_channels[i] <- rlk
        }(i)
    }
    sk := make([]*bfv.SecretKey, n)
    var pk *bfv.PublicKey
    var rlk *bfv.EvaluationKey
    for i, ch := range return_channels {
        pk = (<-ch).(*bfv.PublicKey)
        sk[i] = (<-ch).(*bfv.SecretKey)
        rlk = (<-ch).(*bfv.EvaluationKey)
    }
    
    encryptor := bfv.NewEncryptorFromPk(params, pk)
    enc1 := bfv.NewCiphertext(params, 1)
    encryptor.Encrypt(pt1, enc1)
    enc2 := bfv.NewCiphertext(params, 1)
    encryptor.Encrypt(pt2, enc2)
    res := bfv.NewCiphertext(params, 2)

    evaluator := bfv.NewEvaluator(params)
    evaluator.Mul(enc1, enc2, res)
    evaluator.Relinearize(res, rlk, res)

    ret := make(chan []uint64)
	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
	setting.tsk = tsk
	setting.tpk = tpk
    go func() {
        dec := CentralDecryptor(res, sk[n-1], setting, channels)
        ret <- dec
    }()
    for i := 0; i < n-1; i += 1 {
        go func(i int) {
			dec := OuterDecryptor(res, sk[i], setting, channels[i])
            ret <- dec
        }(i)
    }
    dec := <-ret
    
    if dec[0] != 30 {
        t.Errorf("wrong value after decryption, got %d", dec[0])
    }
}

func TestInverse(t *testing.T) {
    var setting fhe_setting
    params := bfv.DefaultParams[bfv.PN14QP438]
    params.T = 65537
    setting.params = params
    val := make([]uint64, 1)
    s, _ := SampleInt(new(big.Int).SetUint64(setting.params.T))
    val[0] = s.Uint64()
    setting.n = 4
    channels := create_chans(setting.n-1)
    return_channels := create_chans(setting.n)
    crs, crp := GenCRP(params)
    setting.crs = crs
    setting.crp = crp
    encoder := bfv.NewEncoder(params)
    pt := bfv.NewPlaintext(params)
    encoder.EncodeUint(val, pt)
    
    go func() {
        pk, sk, rlk := CentralKeyGenerator(setting, channels)
        return_channels[setting.n-1] <- pk
        return_channels[setting.n-1] <- sk
        return_channels[setting.n-1] <- rlk
    }()
        for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            pk, sk, rlk := OuterKeyGenerator(setting, channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
            return_channels[i] <- rlk
        }(i)
    }
    sk := make([]*bfv.SecretKey, setting.n)
    var pk *bfv.PublicKey
    for i, ch := range return_channels {
        pk = (<-ch).(*bfv.PublicKey)
        sk[i] = (<-ch).(*bfv.SecretKey)
        setting.rlk = (<-ch).(*bfv.EvaluationKey)
    }
    setting.pk = pk
    
    encryptor := bfv.NewEncryptorFromPk(params, pk)
    enc := bfv.NewCiphertext(params, 1)
    encryptor.Encrypt(pt, enc)

    ret := make(chan []uint64)
    tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
    setting.tsk = tsk
    setting.tpk = tpk

    go func() {
        return_channels[0] <- CentralInverseWorker(enc, sk[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            OuterInverseWorker(enc, sk[i], setting, channels[i])
        }(i)
    }

    enc_inv := (<-return_channels[0]).(*bfv.Ciphertext)

    go func() {
        ret <- CentralDecryptor(enc_inv, sk[setting.n-1], setting, channels)
    }()
    for i := 0; i < setting.n-1; i += 1 {
        go func(i int) {
            OuterDecryptor(enc_inv, sk[i], setting, channels[i])
        }(i)
    }
    dec := <-ret
    
    if dec[0] * val[0] % setting.params.T != 1 {
        t.Errorf("not an inverse, got %d", dec[0])
    }
}
