package tpsi

import (
    "testing"
    "math/big"
)

func TestEncryptDecrypt(t *testing.T) {
    n := 4
    channels := create_chans(n-1)
    return_channels := create_chans(n)
    
    go func() {
        pk, sk := CentralBFVEncryptionGenerator(channels)
        return_channels[n-1] <- pk
        return_channels[n-1] <- sk
    }()
        for i := 0; i < n-1; i += 1 {
        go func(i int) {
            pk, sk := OuterBFVEncryptionGenerator(channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
        }(i)
    }
    sk := make([]Secret_key, n)
    setts := make([]FHESetting, n)
    for i, ch := range return_channels[:n-1] {
        setts[i].cs = (<-ch).(BFV_encryption)
        setts[i].n = n
        sk[i] = (<-ch).(Secret_key)
        setts[i].channel = channels[i]
    }
    setts[n-1].cs = (<-return_channels[n-1]).(BFV_encryption)
    setts[n-1].n = n
    sk[n-1] = (<-return_channels[n-1]).(Secret_key)
    setts[n-1].channels = channels
    
    enc, err := setts[0].cs.Encrypt(big.NewInt(5))
    if err != nil {panic(err)}

    ret := make(chan *big.Int)
    go func() {
        ret <- CentralDecryptionWorker(enc, sk[n-1], setts[n-1])
    }()
    for i := 0; i < n-1; i += 1 {
        go func(i int) {
            ret <- OuterDecryptionWorker(enc, sk[i], setts[i])
        }(i)
    }
    
    for i := 0; i < setts[0].n; i += 1 {
        dec := <-ret
        if dec.Cmp(big.NewInt(5)) != 0 {
            t.Errorf("wrong value after decryption, got %d", dec)
        }
    }
}

func TestEvaluation(t *testing.T) {
    val1 := big.NewInt(5)
    val2 := big.NewInt(6)
    n := 4
    channels := create_chans(n-1)
    return_channels := create_chans(n)

    go func() {
        pk, sk := CentralBFVEncryptionGenerator(channels)
        return_channels[n-1] <- pk
        return_channels[n-1] <- sk
    }()
        for i := 0; i < n-1; i += 1 {
        go func(i int) {
            pk, sk := OuterBFVEncryptionGenerator(channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
        }(i)
    }
    sk := make([]Secret_key, n)
    setts := make([]FHESetting, n)
    for i, ch := range return_channels[:n-1] {
        setts[i].cs = (<-ch).(BFV_encryption)
        setts[i].n = n
        sk[i] = (<-ch).(Secret_key)
        setts[i].channel = channels[i]
    }
    setts[n-1].cs = (<-return_channels[n-1]).(BFV_encryption)
    setts[n-1].n = n
    sk[n-1] = (<-return_channels[n-1]).(Secret_key)
    setts[n-1].channels = channels
    
    enc1, err := setts[0].cs.Encrypt(val1)
    if err != nil {t.Error(err)}
    enc2, err := setts[0].cs.Encrypt(val2)
    if err != nil {t.Error(err)}
    
    for j := 0; j < 10; j += 1 {

        go func() {
            enc2, err = setts[n-1].cs.Multiply(enc1, enc2)
            if err != nil {t.Error(err)}
            return_channels[n-1] <- enc2
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                enc2, err = setts[i].cs.Multiply(enc1, enc2)
                if err != nil {t.Error(err)}
            }(i)
        }

        enc2 := (<-return_channels[n-1]).(Ciphertext)

        go func() {
            dec := CentralDecryptionWorker(enc2, sk[n-1], setts[n-1])
            return_channels[n-1] <- dec
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                dec := OuterDecryptionWorker(enc2, sk[i], setts[i])
                return_channels[i] <- dec
            }(i)
        }

        val2.Mul(val2, val1).Mod(val2, setts[0].FHE_cryptosystem().N())
        for _, ch := range return_channels {
            dec := (<-ch).(*big.Int)

            if dec.Cmp(val2) != 0 {
                t.Errorf("wrong value after %d multiplications, got %d expected %d", j+1, dec, val2)
            }
        }
    }
}

func SetupTest() ([]FHESetting, []Secret_key) {
    return SetupTestN(4)
}

func SetupTestN(n int) ([]FHESetting, []Secret_key) {
    settings := make([]FHESetting, n)
    channels := create_chans(n-1)
    return_channels := create_chans(n)
    
    go func() {
        pk, sk := CentralBFVEncryptionGenerator(channels)
        return_channels[n-1] <- pk
        return_channels[n-1] <- sk
    }()
        for i := 0; i < n-1; i += 1 {
        go func(i int) {
            pk, sk := OuterBFVEncryptionGenerator(channels[i])
            return_channels[i] <- pk
            return_channels[i] <- sk
        }(i)
    }
    sk := make([]Secret_key, n)
    for i, ch := range return_channels[:n-1] {
        settings[i].cs = (<-ch).(BFV_encryption)
        sk[i] = (<-ch).(Secret_key)
        settings[i].n = n
        settings[i].channel = channels[i]
    }
    settings[n-1].cs = (<-return_channels[n-1]).(BFV_encryption)
    sk[n-1] = (<-return_channels[n-1]).(Secret_key)
    settings[n-1].n = n
    settings[n-1].channels = channels

    return settings, sk
}

func TestInverse(t *testing.T) {
    settings, sk := SetupTest()
    n := settings[0].Parties()
    
    t.Run("no factor", func(t *testing.T) {
        enc, err := settings[0].cs.Encrypt(big.NewInt(2))
        if err != nil {t.Error(err)}

        ret_inv := make(chan Ciphertext)
        ret_dec := make(chan *big.Int)
        
        go func() {
            ret_inv <- CentralInverseWorker(enc, sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                OuterInverseWorker(enc, sk[i], settings[i])
            }(i)
        }

        enc_inv := <-ret_inv

        go func() {
            ret_dec <- CentralDecryptionWorker(enc_inv, sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                OuterDecryptionWorker(enc_inv, sk[i], settings[i])
            }(i)
        }
        dec := <-ret_dec
        
        if dec.Mul(dec, big.NewInt(2)).Mod(dec, settings[0].cs.N()).Cmp(big.NewInt(1)) != 0 {
            t.Errorf("not an inverse, got %d", dec)
        }
    })

    t.Run("-1 factor", func(t *testing.T) {
        plain := big.NewInt(3)
        enc, err := settings[0].cs.Encrypt(plain)
        if err != nil {t.Error(err)}
        ret_inv := make(chan Ciphertext)
        ret_dec := make(chan *big.Int)
        minus_one := new(big.Int).Sub(settings[0].cs.N(), big.NewInt(1))
        go func() {
            ret_inv <- CentralInverseWorkerWithFactor(enc, minus_one, sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                OuterInverseWorkerWithFactor(enc, minus_one, sk[i], settings[i])
            }(i)
        }
        enc_inv := <-ret_inv

        go func() {
            ret_dec <- CentralDecryptionWorker(enc_inv, sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                OuterDecryptionWorker(enc_inv, sk[i], settings[i])
            }(i)
        }
        dec := <-ret_dec

        if dec.Mul(dec, plain).Mul(dec, minus_one).Mod(dec, settings[0].cs.N()).Cmp(big.NewInt(1)) != 0 {
            t.Errorf("not an inverse, got %d", dec)
        }
    })
}

func TestFHEZeroTest(t *testing.T) {
    settings, sk := SetupTest()
    n := settings[0].Parties()
    
    t.Run("not zero", func(t *testing.T) {
        return_channels := create_chans(n)
        val, err := settings[0].cs.Encrypt(big.NewInt(98))
        if err != nil {t.Error(err)}

        go func() {
            pred := CentralZeroTestWorker(val, sk[n-1], settings[n-1])
            return_channels[n-1] <- pred
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                pred := OuterZeroTestWorker(val, sk[i], settings[i])
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
        val, err := settings[0].cs.Encrypt(big.NewInt(0))
        if err != nil {t.Error(err)}
            
        return_channels := create_chans(n)

        go func() {
            pred := CentralZeroTestWorker(val, sk[n-1], settings[n-1])
            return_channels[n-1] <- pred
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                pred := OuterZeroTestWorker(val, sk[i], settings[i])
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

func TestFHEInterpolation(t *testing.T) {
    t.Run("at threshold", func(t *testing.T) {
        settings, sk := SetupTest()
        n := settings[0].Parties()
        for i := range settings {
            settings[i].T = 1
        }
        mod := settings[0].cs.N()
        int_mod := mod.Int64()
        num := PolyFromRoots(bigIntSlice([]int64{2,6}), mod)
        den := PolyFromRoots(bigIntSlice([]int64{4,8}), mod)
        q := make([]Ciphertext, settings[0].T*2+3)
        sol := bigIntSlice([]int64{12,int_mod-8,1,32,int_mod-12,1})
        var err error
        for i := range q {
            num_eval := EvalPoly(num, big.NewInt(int64(2*i+1)), mod)
            den_eval := EvalPoly(den, big.NewInt(int64(2*i+1)), mod)
            den_inv := new(big.Int).ModInverse(den_eval, mod)
            a := new(big.Int)
            q_p := a.Mul(num_eval, den_inv)
            q[i], err = settings[0].cs.Encrypt(q_p)
            if err != nil {t.Error(err)}
        }
        ret := make(chan []Ciphertext, n)

        for i := 0; i < n; i += 1 {
            go func(i int) {
                ret <- FHEInterpolation(q, sk[i], settings[i])
            }(i)
        }

        int_den := <-ret
        if len(int_den) != len(sol) {
            t.Errorf("wrong length, expected %d, got %d", den.Cols, len(int_den))
        }
        rets := create_chans(n)
        for index := range int_den {
            go func(index int) {
                rets[n-1] <- CentralDecryptionWorker(int_den[index], sk[n-1], settings[n-1])
            }(index)
            for party := 0; party < n-1; party += 1 {
                go func(index, party int) {
                    rets[party] <- OuterDecryptionWorker(int_den[index], sk[party], settings[party])
                }(index, party)
            }
            for p, ch := range rets {
                dec := (<-ch).(*big.Int)
                if dec.Cmp(sol[index]) != 0 {
                    t.Errorf("wrong number for party %d at index %d, expected %d got %d", p, index, sol[index], dec)
                }
            }
        }
    })
    t.Run("below threshold", func(t *testing.T) {
        settings, sk := SetupTest()
        n := settings[0].Parties()
        for i := range settings {
            settings[i].T = 3
        }
        mod := settings[0].cs.N()
        int_mod := mod.Int64()
        num := PolyFromRoots(bigIntSlice([]int64{2,6}), mod)
        den := PolyFromRoots(bigIntSlice([]int64{4,8}), mod)
        q := make([]Ciphertext, settings[0].T*2+3)
        sol := bigIntSlice([]int64{12,int_mod-8,1,0,0,32,int_mod-12,1})
        var err error
        for i := range q {
            num_eval := EvalPoly(num, big.NewInt(int64(2*i+1)), mod)
            den_eval := EvalPoly(den, big.NewInt(int64(2*i+1)), mod)
            den_inv := new(big.Int).ModInverse(den_eval, mod)
            a := new(big.Int)
            q_p := a.Mul(num_eval, den_inv)
            q[i], err = settings[0].cs.Encrypt(q_p)
            if err != nil {t.Error(err)}
        }
        ret := make(chan []Ciphertext, n)

        for i := 0; i < n; i += 1 {
            go func(i int) {
                ret <- FHEInterpolation(q, sk[i], settings[i])
            }(i)
        }

        int_den := <-ret
        if len(int_den) != len(sol) {
            t.Errorf("wrong length, expected %d, got %d", den.Cols, len(int_den))
        }
        rets := create_chans(n)
        for index := range int_den {
            go func(index int) {
                rets[n-1] <- CentralDecryptionWorker(int_den[index], sk[n-1], settings[n-1])
            }(index)
            for party := 0; party < n-1; party += 1 {
                go func(index, party int) {
                    rets[party] <- OuterDecryptionWorker(int_den[index], sk[party], settings[party])
                }(index, party)
            }
            for p, ch := range rets {
                dec := (<-ch).(*big.Int)
                if dec.Cmp(sol[index]) != 0 {
                    t.Errorf("wrong number for party %d at index %d, expected %d got %d", p, index, sol[index], dec)
                }
            }
        }
    })
}
                        
func TestFHECardinalityTest(t *testing.T) {
    settings, sk := SetupTestN(4)
    n := settings[0].Parties()
    t.Run("passing cardinality test", func(t *testing.T) {
        for i := range settings {
            settings[i].T = 4
        }
        ret := make(chan bool)
        items := [][]*big.Int{bigIntSlice([]int64{2,4,6,8,12,16,26}),
                              bigIntSlice([]int64{2,4,6,12,16,20,22}),
                              bigIntSlice([]int64{2,4,6,16,20,22,24}),
                              bigIntSlice([]int64{2,4,6,20,22,24,26})}
        go func() {
            ret <- CentralFHECardinalityTestWorker(items[n-1], sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                ret <- OuterFHECardinalityTestWorker(items[i], sk[i], settings[i])
            }(i)
        }
        for _ = range items {
            if !<-ret {
                t.Error("cardinality test failed")
            }
        }
    })

    t.Run("failing cardinality test", func(t *testing.T) {
        for i := range settings {
            settings[i].T = 4
        }
        ret := make(chan bool)
        items := [][]*big.Int{bigIntSlice([]int64{2,4,6,8,12,16,26,28}),
                              bigIntSlice([]int64{2,4,6,12,16,20,22,24}),
                              bigIntSlice([]int64{2,4,6,16,20,22,24,26}),
                              bigIntSlice([]int64{2,4,6,20,22,24,26,28})}
        go func() {
            ret <- CentralFHECardinalityTestWorker(items[n-1], sk[n-1], settings[n-1])
        }()
        for i := 0; i < n-1; i += 1 {
            go func(i int) {
                ret <- OuterFHECardinalityTestWorker(items[i], sk[i], settings[i])
            }(i)
        }
        for _ = range items {
            if <-ret {
                t.Error("cardinality test passed")
            }
        }
    })
}

func TestTPSIint(t *testing.T) {
    items := [][]*big.Int{bigIntSlice([]int64{2,4,6,8,10,12,14}),
                          bigIntSlice([]int64{2,4,6,8,10,16,18}),
                          bigIntSlice([]int64{2,4,6,8,12,20,22})}
    n := 3
    t.Run("pass cardinality test", func(t *testing.T) {
        settings, sks := SetupTestN(n)
        no_unique := 3
        no_shared := 4
        for i := range settings {
            settings[i].T = 3
        }
        returns := make([]chan []*big.Int, n)
        for i := 0; i < n-1; i += 1 {
            returns[i] = make(chan []*big.Int)
            go func(i int) {
                sh, uq := TPSIintWorker(items[i], sks[i], settings[i])
                returns[i] <- sh
                returns[i] <- uq
            }(i)
        }
        returns[n-1] = make(chan []*big.Int)
        go func() {
            sh, uq := TPSIintWorker(items[n-1], sks[n-1], settings[n-1])
            returns[n-1] <- sh
            returns[n-1] <- uq
        }()
        for i := 0; i < n; i += 1 {
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
        settings, sks := SetupTestN(n)
        for i := range settings {
            settings[i].T = 2
        }
        returns := make([]chan []*big.Int, n)
        for i := 0; i < n-1; i += 1 {
            returns[i] = make(chan []*big.Int)
            go func(i int) {
                sh, uq := TPSIintWorker(items[i], sks[i], settings[i])
                returns[i] <- sh
                returns[i] <- uq
            }(i)
        }
        returns[n-1] = make(chan []*big.Int)
        go func() {
            sh, uq := TPSIintWorker(items[n-1], sks[n-1], settings[n-1])
            returns[n-1] <- sh
            returns[n-1] <- uq
        }()
        for i := 0; i < n; i += 1 {
            shared := <-returns[i]
            if shared != nil {
                t.Error("cardinality test passed")
                <-returns[i]
            }
        }
    })
}
