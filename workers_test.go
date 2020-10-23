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
    setting.q, err = SamplePrime()
    if err != nil {t.Error(err)}
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
        sum.Mod(sum, setting.q)
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
    setting.q, err = SamplePrime()
    if err != nil {t.Error(err)}
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
        prod.Mod(prod, setting.q)
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
    setting.q, err = SamplePrime()
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
    setting.q, err = SamplePrime()
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