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
    n := 4
    channels := create_chans(n-1)
    return_channels := create_chans(n)
    crs, crp := GenCRP(params)
    setting.crs = crs
    setting.crp = crp
    
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
    setting.pk = pk
    
    enc := Encrypt(5, setting)

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
    
    if dec[0] != 5 {
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
    setting, sk, channels := SetupTest()
    
    t.Run("no factor", func(t *testing.T) {
        enc := Encrypt(2,setting)

        ret_inv := make(chan *bfv.Ciphertext)
        ret_dec := make(chan []uint64)
        
        go func() {
            ret_inv <- CentralInverseWorker(enc, sk[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                OuterInverseWorker(sk[i], setting, channels[i])
            }(i)
        }

        enc_inv := <-ret_inv

        go func() {
            ret_dec <- CentralDecryptor(enc_inv, sk[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                OuterDecryptor(enc_inv, sk[i], setting, channels[i])
            }(i)
        }
        dec := <-ret_dec
        
        if dec[0] * 2 % setting.params.T != 1 {
            t.Errorf("not an inverse, got %d", dec[0])
        }
    })

    t.Run("-1 factor", func(t *testing.T) {
        enc := Encrypt(3, setting)
        channels := create_chans(setting.n-1)
        ret_inv := make(chan *bfv.Ciphertext)
        ret_dec := make(chan []uint64)

        go func() {
            ret_inv <- CentralInverseWorkerWithFactor(enc, setting.params.T-1, sk[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                OuterInverseWorker(sk[i], setting, channels[i])
            }(i)
        }
        enc_inv := <-ret_inv

        go func() {
            ret_dec <- CentralDecryptor(enc_inv, sk[setting.n-1], setting, channels)
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                OuterDecryptor(enc_inv, sk[i], setting, channels[i])
            }(i)
        }
        dec := <-ret_dec

        if dec[0] * (setting.params.T-3) % setting.params.T != 1 {
            t.Errorf("not an inverse, got %d", dec[0])
        }
    })
}

func TestFHEZeroTest(t *testing.T) {
    var setting fhe_setting
    params := bfv.DefaultParams[bfv.PN14QP438]
    params.T = 65537
    setting.params = params
    setting.n = 4
    channels := create_chans(setting.n-1)
    return_channels := create_chans(setting.n)
    crs, crp := GenCRP(params)
    setting.crs = crs
    setting.crp = crp
    
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

    tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
    setting.tsk = tsk
    setting.tpk = tpk

    t.Run("not zero", func(t *testing.T) {
        val := Encrypt(98, setting)

        go func() {
            pred := CentralFHEZeroTestWorker(val, sk[setting.n-1], setting, channels)
            return_channels[setting.n-1] <- pred
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                pred := OuterFHEZeroTestWorker(sk[i], setting, channels[i])
                return_channels[i] <- pred
            }(i)
        }

        for _, ch := range return_channels {
            if (<-ch).(bool) {
                t.Error("zero test error")
            }
        }
    })

    t.Run("is zero", func(t *testing.T) {
        val := Encrypt(0, setting)
            
        channels := create_chans(setting.n-1)
        return_channels := create_chans(setting.n)

        go func() {
            pred := CentralFHEZeroTestWorker(val, sk[setting.n-1], setting, channels)
            return_channels[setting.n-1] <- pred
        }()
        for i := 0; i < setting.n-1; i += 1 {
            go func(i int) {
                pred := OuterFHEZeroTestWorker(sk[i], setting, channels[i])
                return_channels[i] <- pred
            }(i)
        }

        for _, ch := range return_channels {
            if !(<-ch).(bool) {
                t.Error("zero test error")
            }
        }
    })
}

func SetupTest() (fhe_setting, []*bfv.SecretKey, []chan interface{}) {
    return SetupTestN(4)
}

func SetupTestN(n int) (fhe_setting, []*bfv.SecretKey, []chan interface{}) {
    var setting fhe_setting
    params := bfv.DefaultParams[bfv.PN14QP438]
    params.T = 65537
    setting.params = params
    setting.n = n
    channels := create_chans(setting.n-1)
    return_channels := create_chans(setting.n)
    crs, crp := GenCRP(params)
    setting.crs = crs
    setting.crp = crp
    
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

    tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()
    setting.tsk = tsk
    setting.tpk = tpk

    return setting, sk, channels
}

func TestFHEInterpolation(t *testing.T) {
    t.Run("at threshold", func(t *testing.T) {
        setting, sk, channels := SetupTest()
        setting.T = 1
        mod := new(big.Int).SetUint64(setting.params.T)
        num := PolyFromRoots([]uint64{2,6}, mod)
        den := PolyFromRoots([]uint64{4,8}, mod)
        q := make([]*bfv.Ciphertext, setting.T*2+3)
        sol := []uint64{12,setting.params.T-8,1,32,setting.params.T-12,1}
        for i := range q {
            num_eval := EvalPoly(num, uint64(2*i+1), mod)
            den_eval := EvalPoly(den, uint64(2*i+1), mod)
            den_inv := new(big.Int).ModInverse(den_eval, mod)
            a := new(big.Int)
            q_p := a.Mul(num_eval, den_inv).Mod(a, mod).Uint64()
            q[i] = Encrypt(q_p, setting)
        }
        ret := make(chan []*bfv.Ciphertext)

        go func() {
            den := CentralFHEInterpolation(q, sk[setting.n-1], setting, channels)
            ret <- den
        }()
        for i := range channels {
            go func(i int) {
                OuterFHEInterpolation(sk[i], setting, channels[i])
            }(i)
        }

        int_den := <-ret
        if len(int_den) != len(sol) {
            t.Errorf("wrong length, expected %d, got %d", den.cols, len(int_den))
        }
        rets := create_chans(setting.n)
        for index := range int_den {
            go func(index int) {
                rets[setting.n-1] <- CentralDecryptor(int_den[index], sk[setting.n-1], setting, channels)
            }(index)
            for party := range channels {
                go func(index, party int) {
                    rets[party] <- OuterDecryptor(int_den[index], sk[party], setting, channels[party])
                }(index, party)
            }
            for p, ch := range rets {
                dec := (<-ch).([]uint64)
                if dec[0] != sol[index] {
                    t.Errorf("wrong number for party %d at index %d, expected %d got %d", p, index, sol[index], dec[0])
                }
            }
        }
    })
    t.Run("below threshold", func(t *testing.T) {
        setting, sk, channels := SetupTest()
        setting.T = 3
        mod := new(big.Int).SetUint64(setting.params.T)
        num := PolyFromRoots([]uint64{2,6}, mod)
        den := PolyFromRoots([]uint64{4,8}, mod)
        q := make([]*bfv.Ciphertext, setting.T*2+3)
        sol := []uint64{12,setting.params.T-8,1,0,0,32,setting.params.T-12,1}
        for i := range q {
            num_eval := EvalPoly(num, uint64(2*i+1), mod)
            den_eval := EvalPoly(den, uint64(2*i+1), mod)
            den_inv := new(big.Int).ModInverse(den_eval, mod)
            a := new(big.Int)
            q_p := a.Mul(num_eval, den_inv).Mod(a, mod).Uint64()
            q[i] = Encrypt(q_p, setting)
        }
        ret := make(chan []*bfv.Ciphertext)

        go func() {
            den := CentralFHEInterpolation(q, sk[setting.n-1], setting, channels)
            ret <- den
        }()
        for i := range channels {
            go func(i int) {
                OuterFHEInterpolation(sk[i], setting, channels[i])
            }(i)
        }

        int_den := <-ret
        if len(int_den) != len(sol) {
            t.Errorf("wrong length, expected %d, got %d", den.cols, len(int_den))
        }
        rets := create_chans(setting.n)
        for index := range int_den {
            go func(index int) {
                rets[setting.n-1] <- CentralDecryptor(int_den[index], sk[setting.n-1], setting, channels)
            }(index)
            for party := range channels {
                go func(index, party int) {
                    rets[party] <- OuterDecryptor(int_den[index], sk[party], setting, channels[party])
                }(index, party)
            }
            for p, ch := range rets {
                dec := (<-ch).([]uint64)
                if dec[0] != sol[index] {
                    t.Errorf("wrong number for party %d at index %d, expected %d got %d", p, index, sol[index], dec[0])
                }
            }
        }
    })
}

func TestFHECardinalityTest(t *testing.T) {
    setting, sk, channels := SetupTest()
    t.Run("passing cardinality test", func(t *testing.T) {
        setting.T = 3
        ret := make(chan bool)
        items := [][]uint64{[]uint64{2,4,6,8,10},
                            []uint64{2,4,6,12,14},
                            []uint64{2,4,6,16,18},
                            []uint64{2,4,6,20,22}}
        go func() {
            ret <- CentralFHECardinalityTestWorker(items[setting.n-1], sk[setting.n-1], setting, channels, nil)
        }()
        for i := range channels {
            go func(i int) {
                ret <- OuterFHECardinalityTestWorker(items[i], sk[i], setting, nil, channels[i])
            }(i)
        }
        for _ = range items {
            if !<-ret {
                t.Error("cardinality test failed")
            }
        }
    })

    t.Run("failing cardinality test", func(t *testing.T) {
        setting.T = 2
        ret := make(chan bool)
        items := [][]uint64{[]uint64{2,4,6,8,10,24},
                            []uint64{2,4,6,12,14,26},
                            []uint64{2,4,6,16,18,28},
                            []uint64{2,4,6,20,22,30}}
        go func() {
            ret <- CentralFHECardinalityTestWorker(items[setting.n-1], sk[setting.n-1], setting, channels, nil)
        }()
        for i := range channels {
            go func(i int) {
                ret <- OuterFHECardinalityTestWorker(items[i], sk[i], setting, nil, channels[i])
            }(i)
        }
        for _ = range items {
            if <-ret {
                t.Error("cardinality test passed")
            }
        }
    })
}