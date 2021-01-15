package tpsi

import (
    "math/big"
    "math"
    gm "github.com/ontanj/generic-matrix"
    "crypto/rand"
)

// create a slice of n chan interface{}
func create_chans(n int) []chan interface{} {
    channels := make([]chan interface{}, n)
    for i := 0; i < n; i += 1 {
        channels[i] = make(chan interface{})
    }
    return channels
}

func bigIntSlice(in []int64) []*big.Int {
    bin := make([]*big.Int, len(in))
    for i, v := range in {
        bin[i] = big.NewInt(v)
    }
    return bin
}

// return sum of a slice of big.Ints
func sumSlice(sl []*big.Int, q *big.Int) *big.Int {
    sum := big.NewInt(0)
    for _, val := range sl {
        sum.Add(sum, val)
    }
    return sum.Mod(sum, q);
}

// element-wise multiplication of big.Int-slice
func elMulSlice(sl1, sl2 []*big.Int, q *big.Int) []*big.Int {
    slProd := make([]*big.Int, len(sl1))
    for i := range slProd {
        slProd[i] = big.NewInt(0)
        slProd[i].Mul(sl1[i], sl2[i]).Mod(slProd[i], q)
    }
    return slProd
}

func SetupAHE(n, T int, cs AHE_Cryptosystem) ([]AHESetting) {
    settings := make([]AHESetting, n)
    channels := create_chans(n-1)
    for i := 0; i < n-1; i += 1 {
        settings[i].cs = cs
        settings[i].n = n
        settings[i].channel = channels[i]
        settings[i].T = T
    }
    settings[n-1].cs = cs
    settings[n-1].n = n
    settings[n-1].channels = channels
    settings[n-1].T = T

    return settings
}

func EncodeElements(elements []*big.Int) []*big.Int {
    new_elements := make([]*big.Int, len(elements))
    for i, e := range elements {
        new_elements[i] = new(big.Int).Mul(e, big.NewInt(2))
    }
    return new_elements
}

func DecodeElements(elements []*big.Int) []*big.Int {
    new_elements := make([]*big.Int, len(elements))
    for i, e := range elements {
        new_elements[i] = new(big.Int).Div(e, big.NewInt(2))
    }
    return new_elements
}

// sample a uniform random integer smaller than q
func SampleInt(q *big.Int) (*big.Int, error) {
    return rand.Int(rand.Reader, q)
}

// compute the encrypted Hankel Matrix for central party
func CPComputeHankelMatrix(items []*big.Int, u *big.Int, setting AHE_setting) (H gm.Matrix, err error) {
    H = ComputePlainHankelMatrix(items, u, setting)
    H, err = H.Scale(big.NewInt(int64(setting.Parties()-1)))
    if err != nil {return}
    return EncryptMatrix(H, setting)
}

//step 3b of CTest-diff
func SampleVVector(m gm.Matrix, setting AHE_setting) (v gm.Matrix, err error) {
    v_plain, err := SampleMatrix(m.Cols, 1, setting.AHE_cryptosystem().N())
    if err != nil {return}
    return EncryptMatrix(v_plain, setting)
}

// step 2 of MMult
func GetMulMatrices(A, B gm.Matrix, RAs, RBs []gm.Matrix, setting AHE_setting) (RA, MA, MB gm.Matrix, err error) {
    RA = RAs[0]
    RB := RBs[0]
    for i := 1; i < setting.Parties(); i += 1 {
        RA, err = RA.Add(RAs[i])
        if err != nil {
            return
        }
        RB, err = RB.Add(RBs[i])
        if err != nil {
            return
        }
    }
    MA, err = A.Add(RA)
    if err != nil {
        return
    }
    MB, err = B.Add(RB)
    return
}

// step 4 of MMult
func CombineMatrixMultiplication(MA_enc, MB_enc gm.Matrix, MAis, MBis []gm.Matrix, ctis []gm.Matrix, setting AHE_setting) (AB gm.Matrix, err error) { // todo: mai, mbi partial
    MA, err := CombineMatrixShares(MAis, MA_enc, setting)
    if err != nil {return}
    MB, err := CombineMatrixShares(MBis, MB_enc, setting)
    if err != nil {return}
    MAMB, err := MA.Multiply(MB)
    if err != nil {return}
    AB, err = EncryptMatrix(MAMB, setting)
    if err != nil {return}
    for _, val := range ctis {
        AB, err = AB.Add(val)
        if err != nil {return}
    }
    return
} 

// sample u from step 3e of CTest-diff
func SampleUVector(m gm.Matrix, setting AHE_setting) (u gm.Matrix, err error) {
    return SampleMatrix(1, m.Rows, setting.AHE_cryptosystem().N())
}

// step 3e of CTest-diff
func HSeq(Hvs gm.Matrix, mat_size int, setting AHE_setting) (h_seq gm.Matrix, err error) {
    u, err := SampleUVector(Hvs, setting)
    if err != nil {return}
    Hvs = Hvs.CropHorizontally(2*mat_size)
    return u.Multiply(Hvs)
}

// step 3g of CTest-diff
func MaskH(Hs gm.Matrix, HMasks []gm.Matrix, setting AHE_setting) (diff gm.Matrix, err error) {
    sum := HMasks[0]
    for i := 1; i < len(HMasks); i += 1 {
        sum, err = sum.Add(HMasks[i])
        if err != nil {return}
    }
    return Hs.Subtract(sum)
}

//ASS, step 7
func SecretShare(d, e *big.Int, setting AHE_setting) *big.Int {
    neg := new(big.Int)
    neg.Sub(e, d)
    neg.Mod(neg, setting.AHE_cryptosystem().N())
    return neg
}

// compute the Hankel Matrix for items and (random) u.
func ComputePlainHankelMatrix(items []*big.Int, u *big.Int, setting AHE_setting) gm.Matrix {
    q := setting.AHE_cryptosystem().N()
    m := len(items)
    u_list := make([]*big.Int, m) // stores u^a^i for each a
    u1_list := make([]*big.Int, m) // stores u^a for each a
    H, err := gm.NewMatrix(setting.Threshold() + 1, setting.Threshold() + 1, nil, gm.Bigint{})
    if err != nil {panic(err)}
    H.Set(0, 0, big.NewInt(int64(m)))
    for i := range u1_list {
        u1_list[i] = new(big.Int).Exp(u, items[i], q); // u^a mod q
    }
    copy(u_list, u1_list)
    for i := 1; ; i += 1 { // each unique element in Hankel matrix
        var stopCol int
        var startCol int
        if i <= setting.Threshold() {
            startCol = 0
            stopCol = i + 1
        } else {
            startCol = i - setting.Threshold()
            stopCol = setting.Threshold() + 1
        }
        el := sumSlice(u_list, q)
        for j := startCol; j < stopCol; j += 1 { // each matrix entry with current element
            H.Set(i-j, j, el)
        }
        if i >= 2 * setting.Threshold() {
            break
        }
        u_list = elMulSlice(u_list, u1_list, q)
    }
    return H
}

// compute and encrypt the Hankel Matrix for items and (random) u.
func ComputeHankelMatrix(items []*big.Int, u *big.Int, setting AHE_setting) (gm.Matrix, error) {
    H := ComputePlainHankelMatrix(items, u, setting)
    return EncryptMatrix(H, setting)
}

// encrypt matrix item-wise
func EncryptMatrix(a gm.Matrix, setting AHE_setting) (b gm.Matrix, err error) {
    m, err := a.Apply(func(plain interface{}) (enc interface{}, err error) {
        return setting.AHE_cryptosystem().Encrypt(plain.(*big.Int))
    })
    if err != nil {return}
    m.Space = setting.AHE_cryptosystem().EvaluationSpace()
    return m, nil
}

// perform partial decryption for key share Secret_key
func PartialDecryptMatrix(cipher gm.Matrix, Secret_key Secret_key) (part_mat gm.Matrix, err error) {
    return cipher.Apply(func(plain interface{}) (enc interface{}, err error) {
        return Secret_key.PartialDecrypt(plain.(Ciphertext))
    })
}

// combine partial matrix decryptions to receive plaintext matrix
func CombineMatrixShares(part_mat []gm.Matrix, enc_mat gm.Matrix, setting AHE_setting) (decrypted gm.Matrix, err error) {
    decrypted, err = gm.NewMatrix(part_mat[0].Rows, part_mat[0].Cols, nil, gm.Bigint{}) //todo: space is partial decrypted; gpr det implementera add för partial space
    if err != nil {return}
    var dec *big.Int
    for row := 0; row < part_mat[0].Rows; row += 1 {
        for col := 0; col < part_mat[0].Cols; col += 1 {
            el_vals := make([]Partial_decryption, len(part_mat))
            for j := range part_mat {
                el_vals[j], err = part_mat[j].At(row, col)
                if err != nil {return}
            }
            dec, err = setting.AHE_cryptosystem().CombinePartials(el_vals)
            if err != nil {return}
            decrypted.Set(row, col, dec)
        }
    }
    return decrypted, nil
}

func SampleSlice(l int, q *big.Int) (a []*big.Int, err error) {
    vals := make([]*big.Int, l)
    var r *big.Int
    for i := 0; i < l; i += 1 {
        r, err = SampleInt(q)
        if err != nil {return}
        vals[i] = r
    }
    return vals, nil
}

// sample a matrix with size rows x cols, with elements from field defined by q
func SampleMatrix(rows, cols int, q *big.Int) (a gm.Matrix, err error) {
    vals_big, err := SampleSlice(rows*cols, q)
    if err != nil {return}
    vals := make([]interface{}, len(vals_big))
    for i, val := range vals_big {
        vals[i] = val
    }
    return gm.NewMatrix(rows, cols, vals, gm.Bigint{})
}

//step 1 of MMult
func SampleRMatrices(a, b gm.Matrix, setting AHE_setting) (RAi_plain, RAi_enc, RBi_plain, RBi_enc gm.Matrix, err error) {
    RAi_plain, err = SampleMatrix(a.Rows, a.Cols, setting.AHE_cryptosystem().N())
    if err != nil {return}
    RAi_enc, err = EncryptMatrix(RAi_plain, setting)
    if err != nil {return}
    RBi_plain, err = SampleMatrix(b.Rows, b.Cols, setting.AHE_cryptosystem().N())
    if err != nil {return}
    RBi_enc, err = EncryptMatrix(RBi_plain, setting)
    if err != nil {return}
    return
}

// step 3 of MMult
func GetCti(MA, MB, RA, RAi, RBi gm.Matrix, setting AHE_setting, Secret_key Secret_key) (cti gm.Matrix, MA_part, MB_part gm.Matrix, err error) { //todo: partial
    prod1, err := RA.Multiply(RBi)
    if err != nil {
        return
    }
    prod2, err := MA.Multiply(RBi)
    if err != nil {
        return
    }
    prod3, err := RAi.Multiply(MB)
    if err != nil {
        return
    }
    sum2, err := prod2.Add(prod3)
    if err != nil {
        return
    }
    cti, err = prod1.Subtract(sum2)
    MA_part, err = PartialDecryptMatrix(MA, Secret_key)
    MB_part, err = PartialDecryptMatrix(MB, Secret_key)
    return
}

// calculates how many instances of MMult is needed to get all H,
// according to: n = ceil( log(matrix size) )
// H^2^n being the highest order needed
func NbrMMultInstances(m gm.Matrix) int {
    return int(math.Ceil(math.Log2(float64(m.Cols))))
}

// step 3f of CTest-diff
func SampleHMasks(setting AHE_setting) {
    SampleMatrix(1, 2*(setting.Threshold()+1), setting.AHE_cryptosystem().N())
}

//Additive Secret Sharing

//ASS, step 1
func GetRandomEncrypted(setting AHE_setting) (plain *big.Int, cipher Ciphertext, err error) {
    plain, err = SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {return}
    cipher, err = setting.AHE_cryptosystem().Encrypt(plain)
    return
}

//ASS, step 5 & 6
func SumMasksDecrypt(a Ciphertext, ds []Ciphertext, sk Secret_key, setting AHE_setting) (e_partial Partial_decryption, err error) {
    for _, val := range ds {
        a, err = setting.AHE_cryptosystem().Add(a, val)
        if err != nil {return}
    }
    a_dec, err := sk.PartialDecrypt(a)
    return a_dec, err
}

//ASS, step 7
func NegateValue(d *big.Int, setting AHE_setting) *big.Int {
    neg := new(big.Int)
    neg.Neg(d)
    neg.Mod(neg, setting.AHE_cryptosystem().N())
    return neg
}

//Multiplication

//Mult, step 6
func SumSlice(values []Ciphertext, setting AHE_setting) (sum Ciphertext, err error) {
    sum = values[0]
    for i := 1; i < setting.Parties(); i += 1 {
        sum, err = setting.AHE_cryptosystem().Add(sum, values[i])
        if err != nil {return}
    }
    return
}

// evaluate polynomial p at point x
func EvalPoly(p gm.Matrix, x, mod *big.Int) *big.Int {
    val, err := decodeBI(p.At(0,0))
    if err != nil {panic(err)}
    sum := new(big.Int).Set(val)
    x_raised := new(big.Int).Set(x)
    term := new(big.Int)
    for i := 1; ; i += 1 {
        val, err := decodeBI(p.At(0,i))
        if err != nil {panic(err)}
        term.Mul(val, x_raised)
        sum.Add(sum, term)
        if i >= p.Cols-1 {
            break
        }
        x_raised.Mul(x_raised, x)
    }
    return sum.Mod(sum, mod)
}

// polynomial multiplication
func MultPoly(p1, p2 gm.Matrix) gm.Matrix {
    l := p1.Cols + p2.Cols - 1
    prod := make([]interface{}, l)
    for i := 0; i < l; i += 1 {
        prod[i] = big.NewInt(0)
    }
    for i := 0; i < p1.Cols; i += 1 {
        for j := 0; j < p2.Cols; j += 1 {
            val1, err := decodeBI(p1.At(0,i))
            if err != nil {panic(err)}
            val2, err := decodeBI(p2.At(0,j))
            if err != nil {panic(err)}
            prod[i+j].(*big.Int).Add(prod[i+j].(*big.Int), new(big.Int).Mul(val1, val2))
        }
    }
    new_poly, err := gm.NewMatrix(1, l, prod, p1.Space)
    if err != nil {panic(err)}
    return new_poly
}

func PolyFromRoots(roots []*big.Int, mod *big.Int) gm.Matrix {
    n := new(big.Int)
    n.Set(roots[0]).Neg(n)
    poly, err := gm.NewMatrix(1,2,[]interface{}{n, big.NewInt(1)}, gm.Bigint{})
    if err != nil {panic(err)}
    for i := 1; i < len(roots); i += 1 {
        n = new(big.Int)
        n.Set(roots[i]).Neg(n)
        root, err := gm.NewMatrix(1, 2, []interface{}{n, big.NewInt(1)}, gm.Bigint{})
        if err != nil {panic(err)}
        poly = MultPoly(poly, root)
    }
    poly, err = poly.Apply(func(val interface{}) (interface{}, error) {
        return new(big.Int).Mod(val.(*big.Int), mod), nil
    })
    if err != nil {panic(err)}
    return poly
}

// step 4 of TPSI-diff
func Interpolation(vs, ps gm.Matrix, setting AHE_setting) gm.Matrix {

    sample_max := setting.Threshold() * 3 + 4
    space := gm.Bigint{}
    
    // calculate q
    q_vals := make([]interface{}, vs.Cols)
    for i := range q_vals {
        ps_val, err := decodeBI(ps.At(0,i))
        if err != nil {panic(err)}
        current_q := new(big.Int).ModInverse(ps_val, setting.AHE_cryptosystem().N())
        vs_val, err := decodeBI(vs.At(0,i))
        q_vals[i] = current_q.Mul(current_q, vs_val)
    }
    q, err := gm.NewMatrix(1, vs.Cols, q_vals, space)
    if err != nil {panic(err)}
    relations := make([]gm.Matrix, sample_max)
    x_pow := new(big.Int)
    coeff := new(big.Int)
    
    coeff_pos := 0
    for ; coeff_pos < sample_max; coeff_pos += 1 {
        eq, err := gm.NewMatrix(1, sample_max + 1, nil, space)
        if err != nil {panic(err)}
        x := big.NewInt(int64(2*coeff_pos+1))
        x_pow = big.NewInt(1)
        
        // populate rel_row with full equation
        j := 0
        for ; j <= setting.Threshold() * 2 + 2; j += 1 { // length of V(x)
            coeff.Set(x_pow).Mod(coeff, setting.AHE_cryptosystem().N())
            eq.Set(0, j, new(big.Int).Set(coeff))
            x_pow.Mul(x_pow, x)
        }
        x_pow = big.NewInt(1)
        for ; j <= sample_max; j += 1 { // length of p'(x)
            q_val, err := decodeBI(q.At(0, coeff_pos))
            if err != nil {panic(err)}
            coeff.Mul(q_val, x_pow).Neg(coeff).Mod(coeff, setting.AHE_cryptosystem().N())
            eq.Set(0, j, new(big.Int).Set(coeff))
            x_pow.Mul(x_pow, x)
        }

        // substitue previous coefficents
        for prev_coeff := 0; prev_coeff < coeff_pos; prev_coeff += 1 {
            coeff, err := decodeBI(eq.At(0, prev_coeff))
            crel, err := relations[prev_coeff].Scale(coeff)
            if err != nil {panic(err)}
            eq, err = eq.Add(crel)
            if err != nil {panic(err)}
            eq.Set(0, prev_coeff, big.NewInt(0))
            eq, err = eq.Apply(func(val interface{}) (interface{}, error) {
                return new(big.Int).Mod(val.(*big.Int), setting.AHE_cryptosystem().N()), nil
            })
            if err != nil {panic(err)}
        }
        
        // if we get 0 = 0, we have all coefficients needed
        is_zero, err := decodeBI(eq.At(0, coeff_pos))
        if err != nil {panic(err)}
        if is_zero.Cmp(big.NewInt(0)) == 0 {
            break
        }
        
        // collect current coefficient
        rel_row, err := gm.NewMatrix(1, sample_max + 1, nil, space)
        if err != nil {panic(err)}
        this_coeff, err := decodeBI(eq.At(0, coeff_pos))
        if err != nil {panic(err)}
        coeff_inv := new(big.Int).ModInverse(this_coeff, setting.AHE_cryptosystem().N())
        rem_coeff := 0
        for ; rem_coeff < coeff_pos + 1; rem_coeff += 1 {
            rel_row.Set(0, rem_coeff, new(big.Int).SetInt64(0))
        }
        for ; rem_coeff < sample_max + 1; rem_coeff += 1 {
            rem, err := decodeBI(eq.At(0, rem_coeff))
            if err != nil {panic(err)}
            rel := new(big.Int).Neg(rem)
            rel.Mul(rel, coeff_inv).Mod(rel, setting.AHE_cryptosystem().N())
            rel_row.Set(0, rem_coeff, rel)
        }
        
        relations[coeff_pos] = rel_row
    }

    interpolated_coeffs := make([]interface{}, sample_max + 1)
    interpolated_coeffs[coeff_pos] = big.NewInt(1)

    // solve all coefficients from relations
    for solving_coeff := coeff_pos - 1; solving_coeff >= 0; solving_coeff -= 1 {
        coeff := big.NewInt(0)
        for known_coeff := solving_coeff + 1; known_coeff <= coeff_pos; known_coeff += 1 {
            rel_s, err := decodeBI(relations[solving_coeff].At(0, known_coeff))
            if err != nil {panic(err)}
            coeff.Add(coeff, new(big.Int).Mul(rel_s, interpolated_coeffs[known_coeff].(*big.Int))).Mod(coeff, setting.AHE_cryptosystem().N())
        }
        interpolated_coeffs[solving_coeff] = coeff
    }

    den := interpolated_coeffs[setting.Threshold() * 2 + 3:coeff_pos + 1]
    int_poly, err := gm.NewMatrix(1, len(den), den, space) 
    return int_poly
}

func IsRoot(poly gm.Matrix, x *big.Int, mod *big.Int) bool {
    return EvalPoly(poly, x, mod).Cmp(big.NewInt(0)) == 0
}

func RootMask(root_poly gm.Matrix, setting AHE_setting) (gm.Matrix) {
    r, err := SampleInt(setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}
    random_root, err := gm.NewMatrix(1, 2, []interface{}{r, big.NewInt(1)}, root_poly.Space)
    if err != nil {panic(err)}
    root_poly = MultPoly(root_poly, random_root)
    return root_poly
}

func EvalIntPolys(root_poly gm.Matrix, sample_max int, setting AHE_setting) (R_values_enc, R_tilde_values, p_values gm.Matrix) {
    R, err := SampleMatrix(1, setting.Threshold()+1, setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}
    R_tilde, err := SampleMatrix(1, setting.Threshold()+1, setting.AHE_cryptosystem().N())
    if err != nil {panic(err)}
    R_values, err := gm.NewMatrix(1, sample_max, nil, gm.Bigint{})
    if err != nil {panic(err)}
    R_tilde_values, err = gm.NewMatrix(1, sample_max, nil, gm.Bigint{})
    if err != nil {panic(err)}
    p_values, err = gm.NewMatrix(1, sample_max, nil, gm.Bigint{})
    if err != nil {panic(err)}
    for i := 0; i < sample_max; i += 1 {
        x := big.NewInt(int64(i*2+1))
        R_values.Set(0, i, EvalPoly(R, x, setting.AHE_cryptosystem().N()))
        R_tilde_values.Set(0, i, EvalPoly(R_tilde, x, setting.AHE_cryptosystem().N()))
        p_values.Set(0, i, EvalPoly(root_poly, x, setting.AHE_cryptosystem().N()))
    }
    R_values_enc, err = EncryptMatrix(R_values, setting)
    if err != nil {panic(err)}
    return
}

func MaskRootPoly(p_values, party_values, R_tilde_values gm.Matrix, sample_max int, setting AHE_setting) gm.Matrix {
    v, err := gm.NewMatrix(1, sample_max, nil, setting.AHE_cryptosystem().EvaluationSpace())
    if err != nil {panic(err)}
    R_tilde_values_enc, err := EncryptMatrix(R_tilde_values, setting)
    if err != nil {panic(err)}
    all_masks, err := party_values.Add(R_tilde_values_enc)
    if err != nil {panic(err)}
    for i := 0; i < sample_max; i += 1 {
        mask_val, err := decodeC(all_masks.At(0,i))
        if err != nil {panic(err)}
        p_val, err := decodeBI(p_values.At(0,i))
        if err != nil {panic(err)}
        val, err := setting.AHE_cryptosystem().Scale(mask_val, p_val)
        if err != nil {panic(err)}
        v.Set(0, i, val)
    }
    return v
}

func decodeBI(val interface{}, err error) (*big.Int, error) {
    if err != nil {return nil, err}
    return val.(*big.Int), nil
}

func decodeC(val interface{}, err error) (Ciphertext, error) {
    if err != nil {return nil, err}
    return val.(Ciphertext), nil
}