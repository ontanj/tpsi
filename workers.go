package tpsi

import (
    "math/big"
    "fmt"
    gm "github.com/ontanj/generic-matrix"
)

func toCiphertextSlice(is []interface{}) []Ciphertext {
    cs := make([]Ciphertext, len(is))
    for i, v := range is {
        cs[i] = v.(Ciphertext)
    }
    return cs
}

func toPartialSlice(is []interface{}) []Partial_decryption {
    cs := make([]Partial_decryption, len(is))
    for i, v := range is {
        cs[i] = v.(Partial_decryption)
    }
    return cs
}

func toMatrixSlice(is []interface{}) []gm.Matrix {
    cs := make([]gm.Matrix, len(is))
    for i, v := range is {
        cs[i] = v.(gm.Matrix)
    }
    return cs
}

func toCiphertextSliceSlice(is []interface{}) [][]Ciphertext {
    cs := make([][]Ciphertext, len(is))
    for i, v := range is {
        cs[i] = v.([]Ciphertext)
    }
    return cs
}

func CentralASSWorker(a Ciphertext, sk Secret_key, setting AHE_setting) *big.Int {
    // step 1: sample d
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}
    
    // receive all_d
    all_d := toCiphertextSlice(setting.ReceiveAll())
    all_d = append(all_d, d_enc)

    // send all_d
    setting.Distribute(all_d)

    // step 5: mask and decrypt
    e_partial, err := SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // receive e_parts
    e_parts := toPartialSlice(setting.ReceiveAll())
    e_parts = append(e_parts, e_partial)

    e, err := setting.AHE_cryptosystem().CombinePartials(e_parts)
    if err != nil {
        panic(err)
    }

    // step 7: assign share
    a_share := SecretShare(d_plain, e, setting)
    return a_share
}

func OuterASSWorker(a Ciphertext, sk Secret_key, setting AHE_setting) *big.Int {
    
    // step 1: sample d
    d_plain, d_enc, err := GetRandomEncrypted(setting)
    if err != nil {panic(err)}

    setting.Send(d_enc)
    
    // receive all_ds
    all_d := setting.Receive().([]Ciphertext)
    
    // step 5: mask and decrypt
    e_partial, err := SumMasksDecrypt(a, all_d, sk, setting)
    if err != nil {panic(err)}
    
    // broadcast e_partial
    setting.Send(e_partial)
    
    // step 7: assign share
    a_share := NegateValue(d_plain, setting)
    return a_share
}

func CentralMultWorker(a, b Ciphertext, sk Secret_key, setting AHE_setting) Ciphertext {
    a_share := CentralASSWorker(a, sk, setting)

    // step 2: partial multiplication
    prod, err := setting.AHE_cryptosystem().Scale(b, a_share)
    if err != nil {panic(err)}

    // receive partial_prods
    partial_prods := toCiphertextSlice(setting.ReceiveAll())
    partial_prods = append(partial_prods, prod)

    // send partial_prods
    setting.Distribute(partial_prods)

    // step 6: sum partials
    sum, err := SumSlice(partial_prods, setting)
    if err != nil {panic(err)}
    
    return sum
}

func OuterMultWorker(a, b Ciphertext, sk Secret_key, setting AHE_setting) Ciphertext {
    
    a_share := OuterASSWorker(a, sk, setting)
    
    // step 2: partial multiplication    
    prod, err := setting.AHE_cryptosystem().Scale(b, a_share)
    if err != nil {panic(err)}

    // broadcast prod
    setting.Send(prod)

    // receive partial_prods
    partial_prods := (setting.Receive()).([]Ciphertext)

    // step 6: sum partials
    sum, err := SumSlice(partial_prods, setting)
    if err != nil {panic(err)}
    
    return sum
}

func CentralDecryptionWorker(cipher Ciphertext, sk Secret_key, setting AHE_setting) *big.Int {
    partial, err := sk.PartialDecrypt(cipher)
    if err != nil {panic(err)}

    ds := toPartialSlice(setting.ReceiveAll())
    ds = append(ds, partial)

    setting.Distribute(ds)
    
    plain, err := setting.AHE_cryptosystem().CombinePartials(ds)
    if err != nil {panic(err)}
    
    return plain
}

func OuterDecryptionWorker(cipher Ciphertext, sk Secret_key, setting AHE_setting) *big.Int {
    partial, err := sk.PartialDecrypt(cipher)
    if err != nil {panic(err)}

    setting.Send(partial)

    ds := (setting.Receive()).([]Partial_decryption)

    plain, err := setting.AHE_cryptosystem().CombinePartials(ds)
    if err != nil {panic(err)}

    return plain
}

func CentralZeroTestWorker(a Ciphertext, sk Secret_key, setting AHE_setting) bool {
    plain_mask, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}

    mask, err := setting.AHE_cryptosystem().Encrypt(plain_mask)
    if err != nil {panic(err)}
    
    masks := toCiphertextSlice(setting.ReceiveAll())
    masks = append(masks, mask)

    sum, err := SumSlice(masks, setting)
    if err != nil {panic(err)}
    
    setting.Distribute(sum)

    pred_enc := CentralMultWorker(a, sum, sk, setting)

    pred := CentralDecryptionWorker(pred_enc, sk, setting)

    return pred.Cmp(big.NewInt(0)) == 0    
}

func OuterZeroTestWorker(a Ciphertext, sk Secret_key, setting AHE_setting) bool {

    plain_mask, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}

    mask, err := setting.AHE_cryptosystem().Encrypt(plain_mask)
    if err != nil {panic(err)}

    setting.Send(mask)

    sum := (setting.Receive()).(Ciphertext)

    pred_enc := OuterMultWorker(a, sum, sk, setting)

    pred := OuterDecryptionWorker(pred_enc, sk, setting)

    return pred.Cmp(big.NewInt(0)) == 0    
}

// returns:
//  * q numerator
//  * q denominator
//  * r numerator
//  * r denominator
func PolynomialDivisionWorker(a, b gm.Matrix, a_den, b_den Ciphertext, sk Secret_key, setting AHE_setting) (gm.Matrix, gm.Matrix, gm.Matrix, Ciphertext) {
    zeroTest := func (val Ciphertext) bool {
        if setting.IsCentral() {
            return CentralZeroTestWorker(val, sk, setting)
        } else {
            return OuterZeroTestWorker(val, sk, setting)
        }
    }
    multiply := func (a, b Ciphertext) Ciphertext {
        if setting.IsCentral() {
            return CentralMultWorker(a, b, sk, setting)
        } else {
            return OuterMultWorker(a, b, sk, setting)
        }
    }
    space := a.Space
    var la int // degree of dividend
    for la = a.Cols-1; la >= 0; la -= 1 { // find degree of divisor
        zero_t, err := decodeC(a.At(0,la))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    var lb int // degree of divisor
    for lb = b.Cols-1; lb >= 0; lb -= 1 { // find degree of divisor
        zero_t, err := decodeC(b.At(0,lb))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    ql := 1+la-lb
    a_num := a
    var q_num gm.Matrix
    var err error
    if setting.IsCentral() {
        q_num, err = EncryptedZeroMatrix(1, ql, setting)
        if err != nil {panic(err)}
        setting.Distribute(q_num)
    } else {
        q_num = (setting.Receive()).(gm.Matrix)
    }
    var q_den gm.Matrix
    if setting.IsCentral() {
        q_den, err = EncryptedOneMatrix(1, ql, setting)
        if err != nil {panic(err)}
        setting.Distribute(q_den)
    } else {
        q_den = (setting.Receive()).(gm.Matrix)
    }
    
    for i := la; i >= lb; i -= 1 { // start at highest degree coefficient, go until dividend smaller than divisor
        // skip 0 coefficents
        zero_t, err := decodeC(a_num.At(0,i))
        if err != nil {panic(err)}
        if zeroTest(zero_t) {
            continue
        }

        pos := i-lb // entry in q at pos

        // q numerator: b_den * a_num
        a_val, err := decodeC(a_num.At(0, i))
        if err != nil {panic(err)}
        num := multiply(a_val, b_den)
        q_num.Set(0, pos, num)
    
        // q denominator: b_num * a_den
        b_val, err := decodeC(b.At(0, lb))
        if err != nil {panic(err)}
        den := multiply(b_val, a_den)
        q_den.Set(0, pos, den)

        // p = q_val * b
        p_num, err := gm.NewMatrix(1, lb, nil, a.Space) // partial result, size is degree of (partial) dividend - 1 = i , skip highest coefficient as it is cancelling
        if err != nil {panic(err)}
        for j := 0; j < lb; j += 1 {
            b_val, err := decodeC(b.At(0, j))
            if err != nil {panic(err)}
            val := multiply(num, b_val)
            p_num.Set(0, j, val)
        }
        p_den := multiply(den, b_den)

        // make same denominator for p and a
        r_num, err := gm.NewMatrix(1, i, nil, space)
        if err != nil {panic(err)}
        for i := 0; i < r_num.Cols; i += 1 {
            a_val, err := decodeC(a_num.At(0, i))
            if err != nil {panic(err)}
            val := multiply(a_val, p_den)
            r_num.Set(0, i, val)
        }
        for i := 0; i < p_num.Cols; i += 1 {
            p_val, err := decodeC(p_num.At(0, i))
            if err != nil {panic(err)}
            val := multiply(p_val, a_den)
            p_num.Set(0, i, val)
        }
        r_den := multiply(a_den, p_den)

        // subtract r2 = r1 - p
        if setting.IsCentral() {
            r_num = divSub(r_num, p_num, setting)
            setting.Distribute(r_num)
        } else {
            r_num = (setting.Receive()).(gm.Matrix)
        }

        a_num = r_num
        a_den = r_den

    }

    // remove initial zero coefficients
    var lr int
    for lr = a_num.Cols-1; lr >= 0; lr -=1 {
        zero_t, err := decodeC(a_num.At(0,lr))
        if err != nil {panic(err)}
        if !zeroTest(zero_t) {
            break
        }
    }
    a_num_vals := make([]interface{}, lr+1)
    for i := range a_num_vals {
        a_num_val, err := a_num.At(0, i)
        if err != nil {panic(err)}
        a_num_vals[i] = a_num_val
    }
    a_num, err = gm.NewMatrix(1, lr+1, a_num_vals, space)
    if err != nil {panic(err)}
    return q_num, q_den, a_num, a_den
}

// subtracts encrypted polynomials r - p, where deg(r) >= deg(p)
func divSub(r, p gm.Matrix,setting AHE_setting) gm.Matrix {
    pos_diff := r.Cols-p.Cols
    for i := 0; i < p.Cols; i += 1 {
        p_val, err := decodeC(p.At(0,i))
        if err != nil {panic(err)}
        neg, err := setting.AHE_cryptosystem().Scale(p_val, big.NewInt(-1))
        if err != nil {panic(err)}
        r_val, err := decodeC(r.At(0, i+pos_diff))
        if err != nil {panic(err)}
        diff, err := setting.AHE_cryptosystem().Add(r_val, neg)
        if err != nil {panic(err)}
        r.Set(0, i+pos_diff, diff)
    }
    return r
}

func CentralMinPolyWorker(seq gm.Matrix, rec_ord int, sk Secret_key, setting AHE_setting) (gm.Matrix, gm.Matrix) {

    // create r0
    coeff, err := setting.AHE_cryptosystem().Encrypt(big.NewInt(1))
    if err != nil {panic(err)}
    
    al := seq.Cols + 1
    a, err := EncryptedZeroMatrix(1, al, setting)
    if err != nil {panic(err)}
    a.Set(0, seq.Cols, coeff)
    setting.Distribute(a)

    a_den, err := setting.AHE_cryptosystem().Encrypt(big.NewInt(1))
    if err != nil {panic(err)}
    setting.Distribute(a_den)

    // create r1
    b := seq
    b_den, err := setting.AHE_cryptosystem().Encrypt(big.NewInt(1))
    if err != nil {panic(err)}
    setting.Distribute(b_den)
    
    // create t0, t1
    t0_num, err := EncryptedZeroMatrix(1, 1, setting)
    if err != nil {panic(err)}
    setting.Distribute(t0_num)
    t0_den, err := EncryptedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    setting.Distribute(t0_den)
    t1_num, err := EncryptedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    setting.Distribute(t1_num)
    t1_den, err := EncryptedOneMatrix(1, 1, setting)
    if err != nil {panic(err)}
    setting.Distribute(t1_den)
    
    var t2_num gm.Matrix
    var t2_den gm.Matrix

    for {
        q_num, q_den, r_num, r_den := PolynomialDivisionWorker(a, b, a_den, b_den, sk, setting)
        t2_num, t2_den, err = nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den, sk, setting)
        if err != nil {panic(err)}
        if r_num.Cols <= rec_ord {
            break
        }
        a = b
        a_den = b_den
        b = r_num
        b_den = r_den
        t0_num = t1_num
        t0_den = t1_den
        t1_num = t2_num
        t1_den = t2_den
    }
    return t2_num, t2_den
}

func OuterMinPolyWorker(seq gm.Matrix, rec_ord int, sk Secret_key, setting AHE_setting) (gm.Matrix, gm.Matrix) {

    // create r0
    a := (setting.Receive()).(gm.Matrix)
    a_den := (setting.Receive()).(Ciphertext)

    // create r1
    b := seq
    b_den := (setting.Receive()).(Ciphertext)
    
    // create t0, t1
    t0_num := (setting.Receive()).(gm.Matrix)
    t0_den := (setting.Receive()).(gm.Matrix)
    t1_num := (setting.Receive()).(gm.Matrix)
    t1_den := (setting.Receive()).(gm.Matrix)
    
    var t2_num gm.Matrix
    var t2_den gm.Matrix
    var err error

    for {
        q_num, q_den, r_num, r_den := PolynomialDivisionWorker(a, b, a_den, b_den, sk, setting)
        t2_num, t2_den, err = nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den, sk, setting)
        if err != nil {panic(err)}
        if r_num.Cols <= rec_ord {
            break
        }
        a = b
        a_den = b_den
        b = r_num
        b_den = r_den
        t0_num = t1_num
        t0_den = t1_den
        t1_num = t2_num
        t1_den = t2_den
    }
    return t2_num, t2_den
}

func nextT(t0_num, t0_den, t1_num, t1_den, q_num, q_den gm.Matrix, sk Secret_key, setting AHE_setting) (t2_num, t2_den gm.Matrix, err error) {
    p_num, p_den, err := PolyMult(t1_num, t1_den, q_num, q_den, sk, setting)
    if err != nil {return}
    t2_num, t2_den, err = PolySub(t0_num, t0_den, p_num, p_den, sk, setting)
    return
}

func PolySub(a_num, a_den, b_num, b_den gm.Matrix, sk Secret_key, setting AHE_setting) (diff_num, diff_den gm.Matrix, err error) {
    if a_num.Cols != a_den.Cols || b_num.Cols != b_den.Cols {
        panic("mismatched length of denominator")
    }
    var diff_l int
    if a_num.Cols > b_num.Cols {
        diff_l = a_num.Cols
    } else {
        diff_l = b_num.Cols
    }
    diff_num, err = gm.NewMatrix(1, diff_l, nil, a_num.Space)
    if err != nil {return}
    diff_den, err = gm.NewMatrix(1, diff_l, nil, a_num.Space)
    if err != nil {return}
    multiply := func (a, b Ciphertext) Ciphertext {
        if setting.IsCentral() {
            return CentralMultWorker(a, b, sk, setting)
        } else {
            return OuterMultWorker(a, b, sk, setting)
        }
    }
    scale := func (a Ciphertext, factor *big.Int) Ciphertext {
        if setting.IsCentral() {
            val, err := setting.AHE_cryptosystem().Scale(a, factor)
            if err != nil {panic(err)}
            setting.Distribute(val)
            return val
        } else {
            return (setting.Receive()).(Ciphertext)
        }
    }
    var num Ciphertext
    for i := 0; i < diff_l; i += 1 {
        if i >= b_num.Cols { // todo: not covered by test
            var a_val interface{}
            a_val, err = a_num.At(0, i)
            if err != nil {return}
            diff_num.Set(0, i, a_val)
            a_val, err = a_den.At(0, i)
            if err != nil {return}
            diff_den.Set(0, i, a_val)
        } else if i >= a_num.Cols {
            var b_val Ciphertext
            b_val, err = decodeC(b_num.At(0, i))
            if err != nil {return}
            num = scale(b_val, big.NewInt(-1))
            diff_num.Set(0, i, num)
            b_val, err = decodeC(b_den.At(0, i))
            if err != nil {return}
            diff_den.Set(0, i, b_val)
        } else {
            var a_num_val Ciphertext
            a_num_val, err = decodeC(a_num.At(0, i))
            if err != nil {return}
            var b_den_val Ciphertext
            b_den_val, err = decodeC(b_den.At(0, i))
            if err != nil {return}
            long_a_num := multiply(a_num_val, b_den_val)
            var b_num_val Ciphertext
            b_num_val, err = decodeC(b_num.At(0, i))
            if err != nil {return}
            var a_den_val Ciphertext
            a_den_val, err = decodeC(a_den.At(0, i))
            if err != nil {return}
            long_b_num := multiply(b_num_val, a_den_val)
            neg := scale(long_b_num, big.NewInt(-1))
            num, err = setting.AHE_cryptosystem().Add(long_a_num, neg)
            if err != nil {return}
            diff_num.Set(0, i, num)
            den := multiply(a_den_val, b_den_val)
            diff_den.Set(0, i, den)
        }
    }
    return
}

func PolyMult(a_num, a_den, b_num, b_den gm.Matrix, sk Secret_key, setting AHE_setting) (prod_num, prod_den gm.Matrix, err error) {
    prod_len := a_num.Cols+b_num.Cols-1
    if setting.IsCentral() {
        prod_num, err = EncryptedZeroMatrix(1, prod_len, setting)
        if err != nil {panic(err)}
        setting.Distribute(prod_num)
    } else {
        prod_num = (setting.Receive()).(gm.Matrix)
    }
    if setting.IsCentral() {
        prod_den, err = EncryptedOneMatrix(1, prod_len, setting)
        if err != nil {panic(err)}
        setting.Distribute(prod_den)
    } else {
        prod_den = (setting.Receive()).(gm.Matrix)
    }
    multiply := func (a, b Ciphertext) Ciphertext {
        if setting.IsCentral() {
            return CentralMultWorker(a, b, sk, setting)
        } else {
            return OuterMultWorker(a, b, sk, setting)
        }
    }
    for i := 0; i < a_num.Cols; i += 1 {
        for j := 0; j < b_num.Cols; j += 1 {
            var a_num_val Ciphertext
            a_num_val, err = decodeC(a_num.At(0,i))
            if err != nil {return}
            var b_num_val Ciphertext
            b_num_val, err = decodeC(b_num.At(0,j))
            if err != nil {return}
            num := multiply(a_num_val, b_num_val)
            var current_num Ciphertext
            current_num, err = decodeC(prod_num.At(0, i+j))
            if err != nil {return}
            
            var a_den_val Ciphertext
            a_den_val, err = decodeC(a_den.At(0,i))
            if err != nil {return}
            var b_den_val Ciphertext
            b_den_val, err = decodeC(b_den.At(0,j))
            if err != nil {return}
            den := multiply(a_den_val, b_den_val)
            var current_den Ciphertext
            current_den, err = decodeC(prod_den.At(0, i+j))
            if err != nil {return}
            
            long_num := multiply(num, current_den)
            long_current_num := multiply(current_num, den)
            var new_num Ciphertext
            new_num, err = setting.AHE_cryptosystem().Add(long_num, long_current_num)
            if err != nil {return}
            prod_num.Set(0, i+j, new_num)
            
            new_den := multiply(den, current_den)
            prod_den.Set(0, i+j, new_den)
        }
    }
    return
}

func EncryptedZeroMatrix(rows, cols int, setting AHE_setting) (m gm.Matrix, err error) {
    var val Ciphertext
    vals := make([]interface{}, rows*cols)
    for i := range vals {
        val, err = setting.AHE_cryptosystem().Encrypt(big.NewInt(0))
        if err != nil {return}
        vals[i] = val
    }
    return gm.NewMatrix(rows, cols, vals, setting.AHE_cryptosystem().EvaluationSpace())
}

func EncryptedOneMatrix(rows, cols int, setting AHE_setting) (m gm.Matrix, err error) {
    var val Ciphertext
    vals := make([]interface{}, rows*cols)
    for i := range vals {
        val, err = setting.AHE_cryptosystem().Encrypt(big.NewInt(1))
        if err != nil {return}
        vals[i] = val
    }
    return gm.NewMatrix(rows, cols, vals, setting.AHE_cryptosystem().EvaluationSpace())
}

func CentralMatrixMultiplicationWorker(a, b gm.Matrix, sk Secret_key, setting AHE_setting) gm.Matrix {
    if a.Cols != b.Rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.Rows, a.Cols, b.Rows, b.Cols))
    }
    
    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    RAs_crypt := toMatrixSlice(setting.ReceiveAll())
    RBs_crypt := toMatrixSlice(setting.ReceiveAll())
    RAs_crypt = append(RAs_crypt, RAi_crypt)
    RBs_crypt = append(RBs_crypt, RBi_crypt)
    

    // step 2
    RA, MA, MB, err := GetMulMatrices(a, b, RAs_crypt, RBs_crypt, setting)
    if err != nil {panic(err)}
    setting.Distribute(RA)
    setting.Distribute(MA)
    setting.Distribute(MB)

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    cts := toMatrixSlice(setting.ReceiveAll())
    cts = append(cts, cti)
    MA_parts := toMatrixSlice(setting.ReceiveAll())
    MA_parts = append(MA_parts, MA_part)
    MB_parts := toMatrixSlice(setting.ReceiveAll())
    MB_parts = append(MB_parts, MB_part)

    // step 4
    AB, err := CombineMatrixMultiplication(MA, MB, MA_parts, MB_parts, cts, setting)
    setting.Distribute(AB)

    return AB

}

func OuterMatrixMultiplicationWorker(a, b gm.Matrix, sk Secret_key, setting AHE_setting) gm.Matrix {
    if a.Cols != b.Rows {
        panic(fmt.Errorf("matrices are not compatible: (%d, %d) x (%d, %d)", a.Rows, a.Cols, b.Rows, b.Cols))
    }

    // step 1
    RAi_clear, RAi_crypt, RBi_clear, RBi_crypt, err := SampleRMatrices(a, b, setting)
    if err != nil {panic(err)}
    setting.Send(RAi_crypt)
    setting.Send(RBi_crypt)

    // step 2
    RA := (setting.Receive()).(gm.Matrix)
    MA := (setting.Receive()).(gm.Matrix)
    MB := (setting.Receive()).(gm.Matrix)

    // step 3
    cti, MA_part, MB_part, err := GetCti(MA, MB, RA, RAi_clear, RBi_clear, setting, sk)
    if err != nil {panic(err)}
    setting.Send(cti)
    setting.Send(MA_part)
    setting.Send(MB_part)

    // step 4
    AB := (setting.Receive()).(gm.Matrix)

    return AB
}

// returns true if m is singular
func CentralSingularityTestWorker(m gm.Matrix, sk Secret_key, setting AHE_setting) bool {
    // step b
    v, err := SampleVVector(m, setting)
    if err != nil {panic(err)}
    setting.Distribute(v)

    // step c
    its := NbrMMultInstances(m)
    mats := make([]gm.Matrix, its+1)
    mats[0] = m
    for i := 0; i < its; i += 1 {
        mats[i+1] = CentralMatrixMultiplicationWorker(mats[i], mats[i], sk, setting)
    }

    //step d
    semi_seq := v
    for _, mat := range mats {
        new_semi_seq := CentralMatrixMultiplicationWorker(mat, semi_seq, sk, setting)
        semi_seq, err = new_semi_seq.Concatenate(semi_seq)
        if err != nil {panic(err)}
    }

    // step e
    seq, err := HSeq(semi_seq, m.Cols, setting)
    if err != nil {panic(err)}

    // distribute seq instead of decrypted secret sharing
    setting.Distribute(seq)

    // step i
    rec_ord := m.Cols
    min_poly, _ := CentralMinPolyWorker(seq, rec_ord, sk, setting)
    
    zero_t, err := decodeC(min_poly.At(0,0))
    if err != nil {panic(err)}
    return CentralZeroTestWorker(zero_t, sk, setting)
}

// returns true if m is singular
func OuterSingularityTestWorker(m gm.Matrix, sk Secret_key, setting AHE_setting) bool {
    // step b
    v := (setting.Receive()).(gm.Matrix)

    // step c
    its := NbrMMultInstances(m)
    mats := make([]gm.Matrix, its+1)
    mats[0] = m
    for i := 0; i < its; i += 1 {
        mats[i+1] = OuterMatrixMultiplicationWorker(mats[i], mats[i], sk, setting)
    }

    //step d
    semi_seq := v
    var err error
    for i := range mats {
        new_semi_seq := OuterMatrixMultiplicationWorker(mats[i], semi_seq, sk, setting)
        semi_seq, err = new_semi_seq.Concatenate(semi_seq)
        if err != nil {panic(err)}
    }

    seq := (setting.Receive()).(gm.Matrix)

    // step i
    rec_ord := m.Cols
    min_poly, _ := OuterMinPolyWorker(seq, rec_ord, sk, setting)

    zero_t, err := decodeC(min_poly.At(0,0))
    if err != nil {panic(err)}
    return OuterZeroTestWorker(zero_t, sk, setting)
}

func CentralHankelMatrix(items []*big.Int, sk Secret_key, setting AHE_setting) gm.Matrix {
    u, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}
    setting.Distribute(u)

    H, err := CPComputeHankelMatrix(items, u, setting)
    if err != nil {panic(err)}
    Hi := toMatrixSlice(setting.ReceiveAll())
    for _, Hv := range Hi {
        H, err = H.Subtract(Hv)
        if err != nil {panic(err)}
    }
    setting.Distribute(H)
    return H
}

func OuterHankelMatrix(items []*big.Int, sk Secret_key, setting AHE_setting) gm.Matrix {
    u := (setting.Receive()).(*big.Int)

    H1, err := ComputeHankelMatrix(items, u, setting)
    if err != nil {panic(err)}
    setting.Send(H1)
    H := (setting.Receive()).(gm.Matrix)
    return H
}

// returns true if number of elements not shared by all is <= setting.Threshold()
func CentralCardinalityTestWorker(items []*big.Int, sk Secret_key, setting AHE_setting) bool {
    H := CentralHankelMatrix(items, sk, setting)
    
    return CentralSingularityTestWorker(H, sk, setting)
}

// returns true if number of elements not shared by all is <= setting.Threshold()
func OuterCardinalityTestWorker(items []*big.Int, sk Secret_key, setting AHE_setting) bool {
    H := OuterHankelMatrix(items, sk, setting)

    return OuterSingularityTestWorker(H, sk, setting)
}

// step 3 of TPSI-diff
func CentralIntersectionPolyWorker(root_poly gm.Matrix, sk Secret_key, setting AHE_setting) (gm.Matrix, gm.Matrix) {
    sample_max := setting.Threshold() * 3 + 4
    self := setting.Parties()-1
    
    // step a
    root_poly = RootMask(root_poly, setting)
    
    // step b
    R_values_enc, R_tilde_values, p_values := EvalIntPolys(root_poly, sample_max, setting)
    all_R_values := toMatrixSlice(setting.ReceiveAll())
    all_R_values = append(all_R_values, R_values_enc)

    // step c
    var party_values gm.Matrix
    var err error
    for i := 0; i < setting.Parties(); i += 1 {
        party_slice := make([]interface{}, sample_max)
        for j := 0; j < sample_max; j += 1 {
            party_slice[j] = new(big.Int).SetInt64(0)
        }
        party_values, err = gm.NewMatrix(1, sample_max, party_slice, gm.Bigint{})
        if err != nil {panic(err)}
        party_values, err = EncryptMatrix(party_values, setting)
        if err != nil {panic(err)}
        for j, vals := range all_R_values {
            if i != j {
                party_values, err = party_values.Add(vals)
                if err != nil {panic(err)}
            }
        }
        if i != self {
            setting.SendTo(i, party_values)
        }
    }

    // step d
    v := MaskRootPoly(p_values, party_values, R_tilde_values, sample_max, setting)

    // step e
    vs := setting.ReceiveAll()
    for _, vv := range vs {
        v, err = v.Add((vv).(gm.Matrix))
        if err != nil {panic(err)}
    }
    setting.Distribute(v)

    // step f
    pm, err := PartialDecryptMatrix(v, sk)
    partials := toMatrixSlice(setting.ReceiveAll())
    partials = append(partials, pm)

    // step g
    v, err = CombineMatrixShares(partials, v, setting)
    if err != nil {panic(err)}
    setting.Distribute(v)

    return v, p_values
}

// step 3 of TPSI-diff
func OuterIntersectionPolyWorker(root_poly gm.Matrix, sk Secret_key, setting AHE_setting) (gm.Matrix, gm.Matrix) {
    sample_max := setting.Threshold() * 3 + 4
    
    // step a
    root_poly = RootMask(root_poly, setting)
    
    // step b
    R_values_enc, R_tilde_values, p_values := EvalIntPolys(root_poly, sample_max, setting)
    setting.Send(R_values_enc)

    // step c
    party_values := (setting.Receive()).(gm.Matrix)

    // step d
    v := MaskRootPoly(p_values, party_values, R_tilde_values, sample_max, setting)
    setting.Send(v)
    
    // step e
    v = (setting.Receive()).(gm.Matrix)
    
    // step f
    pm, err := PartialDecryptMatrix(v, sk)
    if err != nil {panic(err)}
    setting.Send(pm)

    // step g
    v = (setting.Receive()).(gm.Matrix)
    return v, p_values
}

// returns two slices, shared elements & unique elements
func IntersectionWorker(items []*big.Int, sk Secret_key, setting AHE_setting) ([]*big.Int, []*big.Int) {
    root_poly := PolyFromRoots(items, setting.AHE_cryptosystem().N())
    var vs gm.Matrix
    var ps gm.Matrix
    if setting.IsCentral() {
        vs, ps = CentralIntersectionPolyWorker(root_poly, sk, setting)
    } else {
        vs, ps = OuterIntersectionPolyWorker(root_poly, sk, setting)
    }
    
    p := Interpolation(vs, ps, setting)
    shared := make([]*big.Int, 0, len(items))
    unique := make([]*big.Int, 0, len(items))
    for _, item := range items {
        if IsRoot(p, item, setting.AHE_cryptosystem().N()) {
            unique = append(unique, item)
        } else {
            shared = append(shared, item)
        }
    }

    return shared, unique
}

// returns two slices: shared elements & unique elements if cardinality test passes, otherwise nil, nil
func TPSIdiffWorker(items []*big.Int, sk Secret_key, setting AHE_setting) ([]*big.Int, []*big.Int) {
    var pred bool
    if setting.IsCentral() {
        pred = CentralCardinalityTestWorker(items, sk, setting)
    } else {
        pred = OuterCardinalityTestWorker(items, sk, setting)
    }

    // exit if cardinality test doesn't pass
    if pred {
        return IntersectionWorker(items, sk, setting)
    } else {
        return nil, nil
    }
}