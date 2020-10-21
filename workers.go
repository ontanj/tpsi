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