package tpsi

import (
    "github.com/ldsec/lattigo/bfv"
    "github.com/ldsec/lattigo/dbfv"
    "github.com/ldsec/lattigo/ring"
    "math/big"
    gm "github.com/ontanj/generic-matrix"
    "math"
)

// FHE cryptosystem

type BFV_encryption struct {
    params *bfv.Parameters
    crs *ring.Poly
    crp []*ring.Poly
    pk *bfv.PublicKey
    rlk *bfv.EvaluationKey
    tpk *bfv.PublicKey
    tsk *bfv.SecretKey
    sk *bfv.SecretKey
    channels []chan interface{}
    channel chan interface{}
}

func mulMax(a, b BFV_ciphertext) int {
    return int(math.Max(float64(a.mult_counter), float64(b.mult_counter)))
}

func (pk BFV_encryption) Add(a, b Ciphertext) (sum Ciphertext, err error) {
    ac := a.(BFV_ciphertext)
    bc := b.(BFV_ciphertext)
    evaluator := bfv.NewEvaluator(pk.params)
    res := evaluator.AddNew(ac.msg, bc.msg)
    return BFV_ciphertext{msg: res, mult_counter: mulMax(ac, bc)}, nil
}

func (pk BFV_encryption) Scale(cipher Ciphertext, factor *big.Int) (product Ciphertext, err error) {
    val := cipher.(BFV_ciphertext)
    evaluator := bfv.NewEvaluator(pk.params)
    prod := evaluator.MulScalarNew(val.msg, factor.Uint64())
    return BFV_ciphertext{msg: prod, mult_counter: val.mult_counter}, nil
}

func (pk BFV_encryption) Multiply(a, b Ciphertext) (product Ciphertext, err error) {
    mult_limit := 6
    ac := a.(BFV_ciphertext)
    bc := b.(BFV_ciphertext)

    if ac.mult_counter >= mult_limit {
        if pk.channels != nil {
            ac = CentralRefresh(ac, pk)
        } else {
            ac = OuterRefresh(ac, pk)
        }
    }
    if bc.mult_counter >= mult_limit {
        if pk.channels != nil {
            bc = CentralRefresh(bc, pk)
        } else {
            bc = OuterRefresh(bc, pk)
        }
    }

    var prod *bfv.Ciphertext
    if pk.channels != nil {
        evaluator := bfv.NewEvaluator(pk.params)
        prod = evaluator.MulNew(ac.msg, bc.msg)
        evaluator.Relinearize(prod, pk.rlk, prod)
        for _, ch := range pk.channels {
            ch <- prod
        }
    } else {
        prod = (<-pk.channel).(*bfv.Ciphertext)
    }
    return BFV_ciphertext{msg: prod, mult_counter: mulMax(ac, bc) + 1}, nil
}

func (pk BFV_encryption) Encrypt(a *big.Int) (Ciphertext, error) {
    encoder := bfv.NewEncoder(pk.params)
    encryptor := bfv.NewEncryptorFromPk(pk.params, pk.pk)
    pt := bfv.NewPlaintext(pk.params)
    encoder.EncodeUint([]uint64{a.Uint64()}, pt)
    cipher := encryptor.EncryptNew(pt)
    return BFV_ciphertext{msg: cipher, mult_counter: 0}, nil
}

func (pk BFV_encryption) EncryptFixed(plaintext *big.Int, randomizer *big.Int) (Ciphertext, error) {
    panic("EncryptFixed not supported!")
}

func (pk BFV_encryption) CombinePartials(parts []Partial_decryption) (*big.Int, error) {
    pcks := dbfv.NewPCKSProtocol(pk.params, 3.19)
    pcksCombined := pcks.AllocateShares()

    for _, part := range parts {
        pcks.AggregateShares(part.(BFV_partial).part, pcksCombined, pcksCombined)
    }

    enc := parts[0].(BFV_partial).ciphertext
    encOut := bfv.NewCiphertext(pk.params, 1)
    pcks.KeySwitch(pcksCombined, enc.msg, encOut)

    decryptor := bfv.NewDecryptor(pk.params, pk.tsk)
    ptres := bfv.NewPlaintext(pk.params)
    decryptor.Decrypt(encOut, ptres)
    encoder := bfv.NewEncoder(pk.params)
    dec := encoder.DecodeUint(ptres)
    
    return new(big.Int).SetUint64(dec[0]), nil

}

func (pk BFV_encryption) EvaluationSpace() gm.Space {
    return BFV_eval_space{pk}
}

func (pk BFV_encryption) N() *big.Int {
    return new(big.Int).SetUint64(pk.params.T)
}


// secret key

type BFV_secret_key struct {
    sk *bfv.SecretKey
    pk BFV_encryption
}

func (sk BFV_secret_key) PartialDecrypt(ciphertext Ciphertext) (Partial_decryption, error) {
    pcks := dbfv.NewPCKSProtocol(sk.pk.params, 3.19)
    pcksShare := pcks.AllocateShares()
    pcks.GenShare(sk.sk.Get(), sk.pk.tpk, ciphertext.(BFV_ciphertext).msg, pcksShare)
    return BFV_partial{pcksShare, ciphertext.(BFV_ciphertext)}, nil
}

// ciphertext wrapper

type BFV_ciphertext struct {
    msg *bfv.Ciphertext
    mult_counter int
}

type BFV_partial struct {
    part dbfv.PCKSShare
    ciphertext BFV_ciphertext
}


// evaluation space

type BFV_eval_space struct {
    BFV_encryption
}

func (pk BFV_eval_space) Add(a, b interface{}) (interface{}, error) {
    return pk.BFV_encryption.Add(a, b)
}

func (pk BFV_eval_space) Subtract(a, b interface{}) (diff interface{}, err error) {
    neg, _ := pk.BFV_encryption.Scale(b, big.NewInt(-1))
    return pk.Add(a, neg)
}

func (pk BFV_eval_space) Multiply(a, b interface{}) (product interface{}, err error) {
    return pk.BFV_encryption.Multiply(a.(BFV_ciphertext), b.(bfv.Operand))
}

func (pk BFV_eval_space) Scale(ciphertext interface{}, factor interface{}) (product interface{}, err error) {
    return pk.BFV_encryption.Scale(ciphertext, factor.(*big.Int))
}

func (pk BFV_eval_space) Scalarspace() bool {
    return false
}

type BFV_init struct {
    params *bfv.Parameters
    crs *ring.Poly
    crp []*ring.Poly
}

func CentralBFVEncryptionGenerator(channels []chan interface{}) (BFV_encryption, BFV_secret_key) {
    var init BFV_init
    init.params = bfv.DefaultParams[bfv.PN14QP438]
    init.params.T = 65537
    init.crs, init.crp = GenCRP(init.params)
    for _, ch := range channels {
        ch <- init
    }

    pk, sk := CentralKeyGenerator(init, channels)

    pk.tsk, pk.tpk = bfv.NewKeyGenerator(pk.params).GenKeyPair()

    for _, ch := range channels {
        ch <- pk
    }
    
    pk.sk = sk
    pk.channels = channels
    return pk, BFV_secret_key{pk: pk, sk: sk}
}

func OuterBFVEncryptionGenerator(channel chan interface{}) (BFV_encryption, BFV_secret_key) {
    init := (<-channel).(BFV_init)
    _, sk := OuterKeyGenerator(init, channel)
    pk := (<-channel).(BFV_encryption)
    pk.sk = sk
    pk.channel = channel
    return pk, BFV_secret_key{pk: pk, sk: sk}
}

func CentralKeyGenerator(init BFV_init, channels []chan interface{}) (BFV_encryption, *bfv.SecretKey) {
    var pk BFV_encryption
    pk.params = init.params
    pk.crs = init.crs
    pk.crp = init.crp

    // generate secret key
    sk := bfv.NewKeyGenerator(pk.params).GenSecretKey()

    // generate public key
    ckg := dbfv.NewCKGProtocol(pk.params)
    ckgShare := ckg.AllocateShares()
    ckg.GenShare(sk.Get(), pk.crs, ckgShare)

    ckgCombined := ckg.AllocateShares()
    ckg.AggregateShares(ckgShare, ckgCombined, ckgCombined) // aggregate all shares to ckgCombined
    for _, ch := range channels {
        ckg.AggregateShares((<-ch).(dbfv.CKGShare), ckgCombined, ckgCombined) // aggregate all shares to ckgCombined
    }
    pk.pk = bfv.NewPublicKey(pk.params)
    ckg.GenPublicKey(ckgCombined, pk.crs, pk.pk) // generate public key

    // distribute public key
    for _, ch := range channels {
        ch <- pk.pk
    }

    // generate relinearization key
    rkg := dbfv.NewEkgProtocol(pk.params)
    contextKeys, _ := ring.NewContextWithParams(1<<pk.params.LogN, append(pk.params.Qi, pk.params.Pi...))
    rlkEphemSk := contextKeys.SampleTernaryMontgomeryNTTNew(1.0 / 3)
    rkgShareOne, rkgShareTwo, rkgShareThree := rkg.AllocateShares()

    rkg.GenShareRoundOne(rlkEphemSk, sk.Get(), pk.crp, rkgShareOne)  //TODO

    rkgCombined1, rkgCombined2, rkgCombined3 := rkg.AllocateShares()
    rkg.AggregateShareRoundOne(rkgShareOne, rkgCombined1, rkgCombined1)
    for _, ch := range channels {
        rkg.AggregateShareRoundOne((<-ch).(dbfv.RKGShareRoundOne), rkgCombined1, rkgCombined1)
    }
    for _, ch := range channels {
        ch <- rkgCombined1
    }
    
    rkg.GenShareRoundTwo(rkgCombined1, sk.Get(), pk.crp, rkgShareTwo)
    
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
    
    rlk := bfv.NewRelinKey(pk.params, 1)
    rkg.GenRelinearizationKey(rkgCombined2, rkgCombined3, rlk)
    for _, ch := range channels {
        ch <- rlk
    }
    pk.rlk = rlk
    
    return pk, sk
}

func OuterKeyGenerator(init BFV_init, channel chan interface{}) (BFV_encryption, *bfv.SecretKey) {
    var pk BFV_encryption
    pk.params = init.params
    pk.crs = init.crs
    pk.crp = init.crp

    // generate secret key
    sk := bfv.NewKeyGenerator(pk.params).GenSecretKey()

    // generate public key
    ckg := dbfv.NewCKGProtocol(pk.params)
    ckgShare := ckg.AllocateShares()
    ckg.GenShare(sk.Get(), pk.crs, ckgShare)
    channel <- ckgShare
    pk.pk = (<-channel).(*bfv.PublicKey)

    // generate relinearization key
    rkg := dbfv.NewEkgProtocol(pk.params)
    contextKeys, _ := ring.NewContextWithParams(1<<pk.params.LogN, append(pk.params.Qi, pk.params.Pi...))
    rlkEphemSk := contextKeys.SampleTernaryMontgomeryNTTNew(1.0 / 3)
    rkgShareOne, rkgShareTwo, rkgShareThree := rkg.AllocateShares()

    rkg.GenShareRoundOne(rlkEphemSk, sk.Get(), pk.crp, rkgShareOne)

    channel <- rkgShareOne
    rkgCombined1 := (<-channel).(dbfv.RKGShareRoundOne)

    rkg.GenShareRoundTwo(rkgCombined1, sk.Get(), pk.crp, rkgShareTwo)

    channel <- rkgShareTwo
    rkgCombined2 := (<-channel).(dbfv.RKGShareRoundTwo)
    
    rkg.GenShareRoundThree(rkgCombined2, rlkEphemSk, sk.Get(), rkgShareThree)

    channel <- rkgShareThree
    pk.rlk = (<-channel).(*bfv.EvaluationKey)

    return pk, sk
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

func CentralRefresh(cipher BFV_ciphertext, pk BFV_encryption) BFV_ciphertext {
    rpf := dbfv.NewRefreshProtocol(pk.params)
    share := rpf.AllocateShares()
    rpf.GenShares(pk.sk.Get(), cipher.msg, pk.crs, share)

    for _, ch := range pk.channels {
        rpf.Aggregate(share, (<-ch).(dbfv.RefreshShare), share)
    }
    
    newCipher := bfv.NewCiphertext(pk.params, 1)
    rpf.Finalize(cipher.msg, pk.crs, share, newCipher)

    for _, ch := range pk.channels {
        ch <- newCipher
    }

    return BFV_ciphertext{msg: newCipher, mult_counter: 0}
}

func OuterRefresh(cipher BFV_ciphertext, pk BFV_encryption) BFV_ciphertext {
    rpf := dbfv.NewRefreshProtocol(pk.params)
    share := rpf.AllocateShares()
    rpf.GenShares(pk.sk.Get(), cipher.msg, pk.crs, share)

    pk.channel <- share
    
    newCipher := (<-pk.channel).(*bfv.Ciphertext)
    
    return BFV_ciphertext{msg: newCipher, mult_counter: 0}
}