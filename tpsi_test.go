package tpsi

import (
    "testing"
    "math/big"
    gm "github.com/ontanj/generic-matrix"
)

func TestHankelMatrix(t *testing.T) {
    var setting Setting
    items := []uint64{2, 3, 5}
    setting.m = 3
    setting.T = 2
    setting.n = 4
    pk, _, eval_space, err := NewDJCryptosystem(setting.n)
    setting.eval_space = eval_space
    if err != nil {t.Error(err)}
    setting.cs = pk
    q := big.NewInt(11)
    u := big.NewInt(6)
    H := ComputePlainHankelMatrix(items, u, q, setting)
    H_corr := []int64{3,9,4,9,4,6,4,6,8}
    t.Run("check dimensions", func(t *testing.T){
        if H.Rows != setting.T + 1 || H.Cols != setting.T + 1 {
            t.Error("wrong dimensions")
        }
    })
    t.Run("check elements", func(t *testing.T){
        for i := 0; i < 3; i += 1 {
            for j := 0; j < 3; j += 1 {
                h_val, err := decodeBI(H.At(i,j))
                if err != nil {t.Error(err)}
                if h_val.Cmp(new(big.Int).SetInt64(H_corr[i*3 + j])) != 0 {
                    t.Error("incorrect values")
                }
            }
        }
    })
}

func TestEncryptValue(t *testing.T) {
    var setting Setting
    pk, sks, eval_space, err := NewDJCryptosystem(4)
    if err != nil {t.Error(err)}
    setting.eval_space = eval_space
    setting.cs = pk
    plaintext := big.NewInt(32)
    ciphertext, err := setting.cs.Encrypt(plaintext)
    if err != nil {
        t.Errorf("%v", err)
    }
    decryptShares := make([]partial_decryption, 4)
    for i, sk := range sks {
        dks, err := PartialDecryptValue(ciphertext, sk)
        if err != nil {
            t.Errorf("%v", err)
        }
        decryptShares[i] = dks
    }
    dec_plaintext, err := setting.cs.CombinePartials(decryptShares)
    if err != nil {
        t.Errorf("%v", err)
    }
    if plaintext.Cmp(dec_plaintext) != 0 {
        t.Error("decrypted value does not match plaintext")
    }
    if plaintext.Cmp(ciphertext) == 0 {
        t.Error("plaintext didn't encrypt")
    }
}

func TestEncryptMatrix(t *testing.T) {
    var setting Setting
    pk, djsks, eval_space, err := NewDJCryptosystem(4)
    setting.eval_space = eval_space
    sks := ConvertDJSKSlice(djsks)
    setting.cs = pk
    if err != nil {t.Error(err)}
    vals := []int{1,2,3,4,5,6,7,8,9}
    a, err := gm.NewMatrixFromInt(3, 3, vals)
    if err != nil {t.Error(err)}
    a, err = EncryptMatrix(a, setting)
    if err != nil {t.Error(err)}
    b, err := gm.NewMatrixFromInt(3, 3, []int{1,2,3,4,5,6,7,8,9})
    if err != nil {t.Error(err)}
    
    CompareEnc(a, b, sks, setting, t)
}

func TestDecryptMatrix(t *testing.T) {
    var setting Setting
    pk, sks, eval_space, err := NewDJCryptosystem(4)
    setting.eval_space = eval_space
    setting.cs = pk
    if err != nil {t.Error(err)}
    vals := []int{1,2,3,4,5,6,7,8,9}
    a, err := gm.NewMatrixFromInt(3, 3, vals)
    if err != nil {t.Error(err)}
    enc, _ := EncryptMatrix(a, setting)
    partial_decrypts := make([]gm.Matrix, len(sks))
    for i, sk := range sks {
        pd, err := PartialDecryptMatrix(enc, sk)
        if err != nil {
            t.Error(err)
        }
        partial_decrypts[i] = pd
    }
    decrypted, err := CombineMatrixShares(partial_decrypts, setting)
    if err != nil {
        return
    }
    for i := 0; i < 3; i += 1 {
        for j := 0; j < 3; j += 1 {
            dec_val, err := decodeBI(decrypted.At(i, j))
            if err != nil {t.Error(err)}
            a_val, err := decodeBI(a.At(i, j))
            if err != nil {t.Error(err)}
            if dec_val.Cmp(a_val) != 0 {
                t.Error("values differ")
            }
        }
    }

}

// checks if encrypted matrix a is equal to unencrypted matrix b, returns error otherwise
func CompareEnc(enc, plain gm.Matrix, sks []secret_key, setting Setting, t *testing.T) {
    for i := 0; i < enc.Rows; i += 1 {
        for j := 0; j < enc.Cols; j += 1 {
            decryptShares := make([]partial_decryption, len(sks))
            for k, sk := range sks {
                enc_val, err := decodeBI(enc.At(i, j))
                if err != nil {t.Error(err)}
                dks, err := sk.PartialDecrypt(enc_val)
                if err != nil {t.Error(err)}
                decryptShares[k] = dks
            }
            dec_plaintext, err := setting.cs.CombinePartials(decryptShares)
            if err != nil {t.Error(err)}
            plain_val, err := decodeBI(plain.At(i,j))
            if err != nil {t.Error(err)}
            if dec_plaintext.Cmp(plain_val) != 0 {
                t.Errorf("decrypted values is wrong for (%d, %d), expected %d, got %d", i, j, plain_val, dec_plaintext)
            }
        }
    }
}

func TestMMult(t *testing.T) {
    A, err := gm.NewMatrixFromInt(3, 3, []int{1, 2, 3, 4, 5, 6, 7, 8, 9})
    if err != nil {t.Error(err)}
    B, err := gm.NewMatrixFromInt(3, 3, []int{1, 2, 1, 2, 1, 2, 1, 2, 1})
    if err != nil {t.Error(err)}
    AB_corr, err := A.Multiply(B)
    if err != nil {t.Error(err)}
    var setting Setting
    setting.n = 4
    pk, djsks, eval_space, _ := NewDJCryptosystem(setting.n)
    sks := ConvertDJSKSlice(djsks)
    setting.cs = pk
    setting.eval_space = eval_space
    A, _ = EncryptMatrix(A, setting)
    B, _ = EncryptMatrix(B, setting)

    // step1
    RAs_clear := make([]gm.Matrix, setting.n)
    RBs_clear := make([]gm.Matrix, setting.n)
    RAs_crypt := make([]gm.Matrix, setting.n)
    RBs_crypt := make([]gm.Matrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(A, B, setting)
        if err != nil {t.Error(err)}
        RAs_clear[i] = RAi_clear
        RAs_crypt[i] = RAi_crypt
        RBs_clear[i] = RBi_clear
        RBs_crypt[i] = RBi_crypt
    }

    // step 2
    RA, MA, MB, err := GetMulMatrices(A, B, RAs_crypt, RBs_crypt, setting)
    if err != nil {t.Error(err)}

    // step 3
    cts := make([]gm.Matrix, setting.n)
    MA_parts := make([]gm.Matrix, setting.n)
    MB_parts := make([]gm.Matrix, setting.n)
    for i := 0; i < setting.n; i += 1 {
        cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAs_clear[i], RBs_clear[i], setting, sks[i])
        if err != nil {t.Error(err)}
        cts[i] = cti
        MA_parts[i] = MA_part
        MB_parts[i] = MB_part
    }

    // step 4
    AB, err := CombineMatrixMultiplication(MA_parts, MB_parts, cts, setting)
    CompareEnc(AB, AB_corr, sks, setting, t)
}

func TestMPC(t *testing.T) {
    // setup
    a_plain := big.NewInt(13)
    var setting Setting
    setting.n = 4
    pk, sks, eval_space, err := NewDJCryptosystem(setting.n)
    setting.eval_space = eval_space
    if err != nil {
        t.Error(err)
        return
    }
    setting.cs = pk
    a, _ := setting.cs.Encrypt(a_plain)

    // step 1: sample d
    d_plain := make([]*big.Int, setting.n)
    d_enc := make([]*big.Int, setting.n)
    for i := range d_plain {
        plain, enc, err := GetRandomEncrypted(setting)
        if err != nil {t.Error(err)}
        d_plain[i] = plain
        d_enc[i] = enc
    }

    // step 5: mask and decrypt
    e_parts := make([]partial_decryption, setting.n)
    for i := range d_enc {
        e_partial, err := SumMasksDecrypt(a, d_enc, sks[i], setting)
        if err != nil {t.Error(err)}
        e_parts[i] = e_partial
    }
    e, err := setting.cs.CombinePartials(e_parts)
    if err != nil {
        t.Error(err)
    }

    // step 7: assign shares
    as := make([]*big.Int, setting.n)
    as[0] = SecretShare(d_plain[0], e, setting)
    for i := 1; i < setting.n; i += 1 {
        as[i] = NegateValue(d_plain[i], setting)
    }

    t.Run("test ASS", func (t *testing.T) {
        for _, val := range as {
            a_plain.Sub(a_plain, val)
        }
        a_plain.Mod(a_plain, setting.cs.N())
        if a_plain.Cmp(big.NewInt(0)) != 0 {
            t.Error("shares don't add up")
        }
    })

    t.Run("test Mult", func (t *testing.T) {
        b, err := setting.cs.Encrypt(big.NewInt(7))
        if err != nil {t.Error(err)}

        // step 2: partial multiplication
        partial_prods := make([]*big.Int, setting.n)        
        for i, val := range as {
            prod, err := MultiplyEncrypted(b, val, setting)
            if err != nil {t.Error(err)}
            partial_prods[i] = prod
        }

        // step 6: sum partials
        sum, err := SumMultiplication(partial_prods, setting)
        if err != nil {t.Error(err)}
        
        // verify
        parts := make([]partial_decryption, setting.n)
        for i, sk := range sks {
            part, err := PartialDecryptValue(sum, sk)
            if err != nil {t.Error(err)}
            parts[i] = part
        }
        ab, err := setting.cs.CombinePartials(parts)
        ab.Mod(ab, setting.cs.N())
        if err != nil {t.Error(err)}
        if ab.Cmp(big.NewInt(91)) != 0 {
            t.Error("multiplication error")
        }
    })
}

func TestEvalPoly(t *testing.T) {
    p, err := gm.NewMatrixFromInt(1, 3, []int{2,4,3})
    if err != nil {t.Error(err)}
    x := []uint64{0,1,2}
    y := []int64{2,9,0}
    mod := big.NewInt(11)
    for i := 0; i < len(x); i += 1 {
        ev_y := EvalPoly(p, x[i], mod)
        if ev_y.Cmp(new(big.Int).SetInt64(y[i])) != 0 {
            t.Errorf("expected %d, got %d", y[i], ev_y)
        }
    }
}

func TestPolyMult(t *testing.T) {
    a, err := gm.NewMatrixFromInt(1, 3, []int{3,2,1})
    if err != nil {t.Error(err)}
    b, err := gm.NewMatrixFromInt(1, 3, []int{2,4,1})
    if err != nil {t.Error(err)}
    ab_corr := []int64{6,16,13,6,1}
    ab := MultPoly(a, b)
    if ab.Cols != len(ab_corr) {
        t.Errorf("length mismatch: expected %d, got %d", len(ab_corr), ab.Cols)
    }
    for i := 0; i < len(ab_corr); i += 1 {
        ab_val, err := decodeBI(ab.At(0,i))
        if err != nil {t.Error(err)}
        if new(big.Int).SetInt64(ab_corr[i]).Cmp(ab_val) != 0 {
            t.Errorf("error at %d: expected %d, got %d", i, ab_corr[i], ab_val)
        }
    }
}

func TestPolyFromRoots(t *testing.T) {
    roots := []uint64{1, 2}
    poly := []int64{2,8,1}
    mod := big.NewInt(11)
    rpol := PolyFromRoots(roots, mod)
    if len(poly) != rpol.Cols {
        t.Errorf("length mismatch: expected %d, got %d", len(poly), rpol.Cols)
    }
    for i := 0; i < len(poly); i += 1 {
        rpol_val, err := decodeBI(rpol.At(0,i))
        if err != nil {t.Error(err)}
        if new(big.Int).SetInt64(poly[i]).Cmp(rpol_val) != 0 {
            t.Errorf("error at %d: expected %d, got %d", i, poly[i], rpol_val)
        }
    }
}

func TestInterpolation(t *testing.T) {
    vs, err := gm.NewMatrixFromInt(1, 7, []int{19, 6, 7, 12, 4, 5, 7})//, 18, 16, 18}))
    if err != nil {t.Error(err)}
    ps, err := gm.NewMatrixFromInt(1, 7, []int{22, 21, 5, 20, 20, 5, 21})//, 22, 8, 2}))
    if err != nil {t.Error(err)}
    // v_corr := []*big.Int{21,6,12,2,1}
    p_corr := []int64{14,7,1}
    var setting Setting
    pk, _, eval_space, _ := NewDJCryptosystem(4)
    setting.eval_space = eval_space
    pk.PubKey.N = big.NewInt(23)
    setting.cs = pk
    setting.T = 1
    p := Interpolation(vs, ps, setting)
    if len(p_corr) != p.Cols {
        t.Errorf("wrong degree on interpolated polynomial; expected %d, got %d", len(p_corr), p.Cols)
    } else {
        for i, p_coeff := range p_corr {
            p_val, err := decodeBI(p.At(0,i))
            if err != nil {t.Error(err)}
            if new(big.Int).SetInt64(p_coeff).Cmp(p_val) != 0 {
                t.Errorf("expected %d, got %d", p_coeff, p_val)
            }
        }
    }
}
