package tpsi

import (
    "testing"
    "math/big"
    "github.com/niclabs/tcpaillier"
)

func TestASSWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(20), setting)
    if err != nil {t.Error(err)}

    go CentralASSWorker(a, sks[0], setting, mask_channel, masks_channel, dec_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go ASSWorker(a, sks[i], setting, mask_channel, masks_channel, dec_channel, return_channel)
    }

    sum := big.NewInt(0)
    for i := 0; i < setting.n; i += 1 {
        val := <-return_channel
        sum.Add(sum, val)
        sum.Mod(sum, setting.pk.N)
    }
    if sum.Cmp(big.NewInt(20)) != 0 {
        t.Error("shares don't add up")
    }
}

func TestMultWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, 4)
    if err != nil {t.Error(err)}
    setting.pk = pk
    
    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)
    a, err := EncryptValue(big.NewInt(3), setting)
    if err != nil {t.Error(err)}
    b, err := EncryptValue(big.NewInt(4), setting)
    if err != nil {t.Error(err)}

    go CentralMultWorker(a, b, sks[0], setting, mask_channel, masks_channel, dec_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go MultWorker(a, b, sks[i], setting, mask_channel, masks_channel, dec_channel, return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        prod_enc := <-return_channel
        // verify
        parts := make([]*tcpaillier.DecryptionShare, setting.n)
        for i, sk := range sks {
            part, err := PartialDecryptValue(prod_enc, sk)
            if err != nil {t.Error(err)}
            parts[i] = part
        }
        prod, err := CombineShares(parts, setting)
        prod.Mod(prod, setting.pk.N)
        if err != nil {t.Error(err)}
        if prod.Cmp(big.NewInt(12)) != 0 {
            t.Error("multiplication error")
        }
    }
}

func TestZeroTestWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    return_channel := make(chan bool)

    t.Run("test 0", func (t *testing.T) {
        cipher, err := EncryptValue(big.NewInt(0), setting)
        if err != nil {panic(err)}

        go CentralZeroTestWorker(cipher, sks[0], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
        for i := 1; i < setting.n; i += 1 {
            go ZeroTestWorker(cipher, sks[i], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
        }

        for i := 0; i < setting.n; i += 1 {
            if !(<-return_channel) {
                t.Error("zero test fail for 0")
            }
        }
    })

    t.Run("test non-0", func (t *testing.T) {
        cipher, err := EncryptValue(big.NewInt(131), setting)
        if err != nil {panic(err)}

        go CentralZeroTestWorker(cipher, sks[0], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
        for i := 1; i < setting.n; i += 1 {
            go ZeroTestWorker(cipher, sks[i], setting, mask_channel, masks_channel, dec_channel, shares_channel, return_channel)
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
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk
    
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    return_channel := make(chan *big.Int)

    cipher, err := EncryptValue(big.NewInt(83), setting)
    if err != nil {panic(err)}

    go CentralDecryptionWorker(cipher, sks[0], setting, dec_channel, shares_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go DecryptionWorker(cipher, sks[i], setting, dec_channel, shares_channel, return_channel)
    }

    for i := 0; i < setting.n; i += 1 {
        if (<-return_channel).Cmp(big.NewInt(83)) != 0 {
            t.Error("decryption error")
        }
    }
}

func t_decrypt(cipher *big.Int, sks []*tcpaillier.KeyShare, setting Setting,
                dec_channel chan *tcpaillier.DecryptionShare, 
                shares_channel chan []*tcpaillier.DecryptionShare) *big.Int {
    return_channel := make(chan *big.Int, 4)
    go CentralDecryptionWorker(cipher, sks[0], setting, dec_channel, shares_channel, return_channel)
    for i := 1; i < setting.n; i += 1 {
        go DecryptionWorker(cipher, sks[i], setting, dec_channel, shares_channel, return_channel)
    }
    val := <-return_channel
    return val
}

func TestPolynomialDivisionWorkers(t *testing.T) {
    var setting Setting
    setting.n = 4
    sks, pk, err := GenerateKeys(512, 1, setting.n)
    if err != nil {panic(err)}
    setting.pk = pk
    divid := NewBigMatrix(1, 5, sliceToBigInt([]int64{3, 6, 5, 2, 0}))
    divis := NewBigMatrix(1, 4, sliceToBigInt([]int64{1, 3, 2, 0}))
    q := sliceToBigInt([]int64{1, 1})
    r := sliceToBigInt([]int64{2, 2})

    divid_enc, err := EncryptMatrix(divid, setting)
    if err != nil {t.Error(err)}
    divid_den, err := EncryptValue(big.NewInt(1), setting)
    if err != nil {t.Error(err)}
    divis_enc, err := EncryptMatrix(divis, setting)
    if err != nil {t.Error(err)}
    divis_den, err := EncryptValue(big.NewInt(1), setting)
    if err != nil {t.Error(err)}

    mask_channel := make(chan *big.Int)
    masks_channel := make(chan []*big.Int)
    dec_channel := make(chan *tcpaillier.DecryptionShare)
    shares_channel := make(chan []*tcpaillier.DecryptionShare)
    mult_channel := make(chan *big.Int)
    sub_channel := make(chan BigMatrix)
    
    validator := func(num BigMatrix, den BigMatrix, corr []*big.Int) {
        dec := make([]*big.Int, num.cols)
        var den_i *big.Int // denominator inverse
        
        // if denominator shared among all coefficients -> decrypt it
        if den.cols == 1 {
            den_i = t_decrypt(den.At(0, 0), sks, setting, dec_channel, shares_channel)
            den_i.ModInverse(den_i, setting.pk.N)
        }
        
        // iterate over coefficients
        for j := 0; j < len(corr); j += 1 {
            // decrypt current denominator if not shared
            if den.cols != 1 {
                den_i = t_decrypt(den.At(0, j), sks, setting, dec_channel, shares_channel)
                den_i.ModInverse(den_i, setting.pk.N)
            }
            dec[j] = t_decrypt(num.At(0, j), sks, setting, dec_channel, shares_channel) // decrypt current numerator
            dec[j].Mul(dec[j], den_i).Mod(dec[j], setting.pk.N) // multiply numerator and denominator inverse
            if dec[j].Cmp(corr[j]) != 0 {
                t.Errorf("error in polynomial division, expected %d got %d", corr[j], dec[j])
            }
        }
        if den.cols > len(corr) {
            t.Error("exceeding coefficients")
        }
    }

    returns := make([]chan BigMatrix, 4)
    returns[0] = make(chan BigMatrix, 4)
    returns[1] = make(chan BigMatrix, 4)
    returns[2] = make(chan BigMatrix, 100) // discard these messages
    returns[3] = make(chan BigMatrix, 100) // discard these messages
    
    go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[0], setting, true, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[0])
    for i := 1; i < setting.n; i += 1 {
        go PolynomialDivisionWorker(divid_enc, divis_enc, divid_den, divis_den, sks[i], setting, false, mask_channel, masks_channel, dec_channel, shares_channel, mult_channel, sub_channel, returns[i])
    }
    
    for i := 0; i < 2; i += 1 {
        select {
        case qn := <-returns[0]:
            validator(qn, <-returns[0], q)
            rn :=  <-returns[0]
            validator(rn, <-returns[0], r)
        case qn := <-returns[1]:
            validator(qn, <-returns[1], q)
            rn := <-returns[1]
            validator(rn, <-returns[1], r)
        }
    }
}
