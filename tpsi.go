package tpsi

import (
    "github.com/niclabs/tcpaillier"
    "math/big"
    "math"
)

type Setting struct {
    pk *tcpaillier.PubKey
    n int // number of participants
    m int // set size
    T int // threshold
}

type PartialMatrix struct {
    values []*tcpaillier.DecryptionShare
    rows, cols int
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

// compute the Hankel Matrix for items and (random) u.
func ComputePlainHankelMatrix(items []int64, u, q *big.Int, setting Setting) BigMatrix {
    // u = big.NewInt(3)
    u_list := make([]*big.Int, setting.m) // stores u^a^i for each a
    u1_list := make([]*big.Int, setting.m) // stores u^a for each a
    H := NewBigMatrix(setting.T + 1, setting.T + 1, nil)
    H.Set(0, 0, big.NewInt(int64(setting.m)))
    for i := range u1_list {
        u1_list[i] = big.NewInt(0)
        u1_list[i].Exp(u, big.NewInt(items[i]), q);
    }
    copy(u_list, u1_list)
    for i := 1; ; i += 1 { // each unique element in Hankel matrix
        var stopCol int
        var startCol int
        if i <= setting.T {
            startCol = 0
            stopCol = i + 1
        } else {
            startCol = i - setting.T
            stopCol = setting.T + 1
        }
        el := sumSlice(u_list, q)
        for j := startCol; j < stopCol; j += 1 { // each matrix entry with current element
            H.Set(i-j, j, el)
        }
        if i >= 2 * setting.T {
            break
        }
        u_list = elMulSlice(u_list, u1_list, q)
    }
    return H
}

// compute and encrypt the Hankel Matrix for items and (random) u.
func ComputeHankelMatrix(items []int64, u *big.Int, setting Setting) (BigMatrix, error) {
    H := ComputePlainHankelMatrix(items, u, setting.pk.N, setting)
    return EncryptMatrix(H, setting)
}

// encrypt single value
func EncryptValue(value *big.Int, setting Setting) (*big.Int, error) {
    cipherText, _, err := setting.pk.Encrypt(value)
    return cipherText, err
}

// encrypt matrix item-wise
func EncryptMatrix(a BigMatrix, setting Setting) (b BigMatrix, err error) {
    b = NewBigMatrix(a.rows, a.cols, nil)
    var c *big.Int
    for i := range a.values {
        c, err = EncryptValue(a.values[i], setting)
        if err != nil {
            return
        }
        b.values[i] = c;
    }
    return
}

// perform partial decryption for key share secret_key
func PartialDecryptValue(cipher *big.Int, secret_key *tcpaillier.KeyShare) (*tcpaillier.DecryptionShare, error) {
    return secret_key.PartialDecrypt(cipher)
}

// perform partial decryption for key share secret_key
func PartialDecryptMatrix(cipher BigMatrix, secret_key *tcpaillier.KeyShare) (part_mat PartialMatrix, err error) {
    dec_vals := make([]*tcpaillier.DecryptionShare, len(cipher.values))
    var part_val *tcpaillier.DecryptionShare
    for i, enc_val := range cipher.values {
        part_val, err = PartialDecryptValue(enc_val, secret_key)
        if err != nil {
            return
        }
        dec_vals[i] = part_val
    }
    part_mat = PartialMatrix{values: dec_vals, rows: cipher.rows, cols: cipher.cols}
    return
}

// combine partial decryptions to receive plaintext
func CombineShares(decryptShares []*tcpaillier.DecryptionShare, setting Setting) (*big.Int, error) {
    return setting.pk.CombineShares(decryptShares...)
}

// combine partial matrix decryptions to receive plaintext matrix
func CombineMatrixShares(part_mat []PartialMatrix, setting Setting) (decrypted BigMatrix, err error) {
    dec_mat_vals := make([]*big.Int, len(part_mat[0].values))
    var dec *big.Int
    for i := range part_mat[0].values {
        el_vals := make([]*tcpaillier.DecryptionShare, len(part_mat))
        for j := range part_mat {
            el_vals[j] = part_mat[j].values[i]
        }
        dec, err = CombineShares(el_vals, setting)
        if err != nil {
            return
        }
        dec_mat_vals[i] = dec
    }
    decrypted = NewBigMatrix(part_mat[0].rows, part_mat[0].cols, dec_mat_vals)
    return
}

// sample a matrix with size rows x cols, with elements from field defined by q
func SampleMatrix(rows, cols int, q *big.Int) (a BigMatrix, err error) {
    vals := make([]*big.Int, rows*cols)
    var r *big.Int
    for i := range vals {
        r, err = SampleInt(q)
        if err != nil {
            return
        }
        vals[i] = r
    }
    a = NewBigMatrix(rows, cols, vals)
    return
}

//step 1 of MMult
func SampleRMatrices(a, b BigMatrix, setting Setting) (RAi_plain, RAi_enc, RBi_plain, RBi_enc BigMatrix, err error) {
    RAi_plain, err = SampleMatrix(a.rows, a.cols, setting.pk.N)
    if err != nil {return}
    RAi_enc, err = EncryptMatrix(RAi_plain, setting)
    if err != nil {return}
    RBi_plain, err = SampleMatrix(b.rows, b.cols, setting.pk.N)
    if err != nil {return}
    RBi_enc, err = EncryptMatrix(RBi_plain, setting)
    if err != nil {return}
    return
}

// step 3 of MMult
func GetCti(MA, MB, RA, RAi, RBi BigMatrix, setting Setting, secret_key *tcpaillier.KeyShare) (cti BigMatrix, MA_part, MB_part PartialMatrix, err error) {
    prod1, err := MatEncRightMul(RA, RBi, setting.pk)
    if err != nil {
        return
    }
    prod2, err := MatEncRightMul(MA, RBi, setting.pk)
    if err != nil {
        return
    }
    prod3, err := MatEncLeftMul(RAi, MB, setting.pk)
    if err != nil {
        return
    }
    sum2, err := MatEncAdd(prod2, prod3, setting.pk) //avoid extra calculation
    if err != nil {
        return
    }
    cti, err = MatEncSub(prod1, sum2, setting.pk)
    MA_part, err = PartialDecryptMatrix(MA, secret_key)
    MB_part, err = PartialDecryptMatrix(MB, secret_key)
    return
}

// calculates how many instances of MMult is needed to get all H,
// according to: n = ceil( log(matrix size) )
// H^2^n being the highest order needed
func NbrMMultInstances(m BigMatrix) int {
    return int(math.Ceil(math.Log2(float64(m.cols))))
}

// step 3f of CTest-diff
func SampleHMasks(setting Setting) {
    SampleMatrix(1, 2*(setting.T+1), setting.pk.N)
}

//Additive Secret Sharing

//ASS, step 1
func GetRandomEncrypted(setting Setting) (plain, cipher *big.Int, err error) {
    plain, err = SampleInt(setting.pk.N)
    if err != nil {return}
    cipher, err = EncryptValue(plain, setting)
    return
}

//ASS, step 5 & 6
func SumMasksDecrypt(a *big.Int, ds []*big.Int, sk *tcpaillier.KeyShare, setting Setting) (e_partial *tcpaillier.DecryptionShare, err error) {
    for _, val := range ds {
        a, err = setting.pk.Add(a, val)
        if err != nil {return}
    }
    return PartialDecryptValue(a, sk)
}

//ASS, step 7
func NegateValue(d *big.Int, setting Setting) *big.Int {
    neg := new(big.Int)
    neg.Neg(d)
    neg.Mod(neg, setting.pk.N)
    return neg
}

//Multiplication

//Mult, step 2
func MultiplyEncrypted(encrypted, plain *big.Int, setting Setting) (*big.Int, error) {
    prod, _, err := setting.pk.Multiply(encrypted, plain)
    return prod, err
}

//Mult, step 6
func SumMultiplication(values []*big.Int, setting Setting) (sum *big.Int, err error) {
    sum, err = setting.pk.Add(values...)
    return
}

// evaluate polynomial p at point x
func EvalPoly(p BigMatrix, x int64, mod *big.Int) *big.Int {
    sum := new(big.Int).Set(p.At(0,0))
    xb := big.NewInt(x)
    x_raised := new(big.Int).Set(xb)
    term := new(big.Int)
    for i := 1; ; i += 1 {
        term.Mul(p.At(0,i), x_raised)
        sum.Add(sum, term)
        if i >= p.cols-1 {
            break
        }
        x_raised.Mul(x_raised, xb)
    }
    return sum.Mod(sum, mod)
}

// polynomial multiplication
func MultPoly(p1, p2 BigMatrix) BigMatrix {
    l := p1.cols + p2.cols - 1
    prod := make([]*big.Int, l)
    for i := 0; i < l; i += 1 {
        prod[i] = big.NewInt(0)
    }
    for i := 0; i < p1.cols; i += 1 {
        for j := 0; j < p2.cols; j += 1 {
            prod[i+j].Add(prod[i+j], new(big.Int).Mul(p1.At(0,i), p2.At(0,j)))
        }
    }
    return NewBigMatrix(1, l, prod)
}

func PolyFromRoots(roots []int64, mod *big.Int) BigMatrix {
    poly := NewBigMatrix(1,2,[]*big.Int{big.NewInt(-roots[0]), big.NewInt(1)})
    for i := 1; i < len(roots); i += 1 {
        root := NewBigMatrix(1, 2, []*big.Int{big.NewInt(-roots[i]), big.NewInt(1)})
        poly = MultPoly(poly, root)
    }
    for _, val := range poly.values {
        val.Mod(val, mod)
    }
    return poly
}

// step 4 of TPSI-diff
func Interpolation(vs, ps BigMatrix, setting Setting) BigMatrix {

    sample_max := setting.T * 3 + 4
    
    // calculate q
    q_vals := make([]*big.Int, vs.cols)
    for i := range q_vals {
        q_vals[i] = new(big.Int).ModInverse(ps.At(0,i), setting.pk.N)
        q_vals[i].Mul(q_vals[i], vs.At(0,i))
    }
    q := NewBigMatrix(1, vs.cols, q_vals)
    relations := make([]BigMatrix, sample_max)
    x_pow := new(big.Int)
    coeff := new(big.Int)
    
    coeff_pos := 0
    for ; coeff_pos < sample_max; coeff_pos += 1 {
        eq := NewBigMatrix(1, sample_max + 1, nil)
        x := big.NewInt(int64(2*coeff_pos+1))
        x_pow = big.NewInt(1)
        
        // populate rel_row with full equation
        j := 0
        for ; j <= setting.T * 2 + 2; j += 1 { // length of V(x)
            coeff.Set(x_pow).Mod(coeff, setting.pk.N)
            eq.At(0, j).Set(coeff)
            x_pow.Mul(x_pow, x)
        }
        x_pow = big.NewInt(1)
        for ; j <= sample_max; j += 1 { // length of p'(x)
            coeff.Mul(q.At(0, coeff_pos), x_pow).Neg(coeff).Mod(coeff, setting.pk.N)
            eq.At(0, j).Set(coeff)
            x_pow.Mul(x_pow, x)
        }

        // substitue previous coefficents
        for prev_coeff := 0; prev_coeff < coeff_pos; prev_coeff += 1 {
            coeff = eq.At(0, prev_coeff)
            crel := MatScaMul(relations[prev_coeff], coeff)
            eq = MatAdd(eq, crel)
            eq.Set(0, prev_coeff, big.NewInt(0))
            eq = MatMod(eq, setting.pk.N)
        }
        
        // if we get 0 = 0, we have all coefficients needed
        if eq.At(0, coeff_pos).Cmp(big.NewInt(0)) == 0 {
            break
        }
        
        // collect current coefficient
        rel_row := NewBigMatrix(1, sample_max + 1, nil)
        coeff_inv := new(big.Int).ModInverse(eq.At(0, coeff_pos), setting.pk.N)
        for rem_coeff := coeff_pos + 1; rem_coeff < sample_max + 1; rem_coeff += 1 {
            rel := new(big.Int).Neg(eq.At(0, rem_coeff))
            rel.Mul(rel, coeff_inv).Mod(rel, setting.pk.N)
            rel_row.Set(0, rem_coeff, rel)
        }
        
        relations[coeff_pos] = rel_row
    }

    interpolated_coeffs := make([]*big.Int, sample_max + 1)
    interpolated_coeffs[coeff_pos] = big.NewInt(1)

    // solve all coefficients from relations
    for solving_coeff := coeff_pos - 1; solving_coeff >= 0; solving_coeff -= 1 {
        coeff := big.NewInt(0)
        for known_coeff := solving_coeff + 1; known_coeff <= coeff_pos; known_coeff += 1 {
            coeff.Add(coeff, new(big.Int).Mul(relations[solving_coeff].At(0, known_coeff), interpolated_coeffs[known_coeff])).Mod(coeff, setting.pk.N)
        }
        interpolated_coeffs[solving_coeff] = coeff
    }

    den := interpolated_coeffs[setting.T * 2 + 3:coeff_pos + 1]
    return NewBigMatrix(1, len(den), den)
}

func IsRoot(poly BigMatrix, x int64, mod *big.Int) bool {
    return EvalPoly(poly, x, mod).Cmp(big.NewInt(0)) == 0
}

func RootMask(root_poly BigMatrix, setting Setting) (BigMatrix) {
    r, err := SampleInt(setting.pk.N)
    if err != nil {panic(err)}
    random_root := NewBigMatrix(1, 2, []*big.Int{r, big.NewInt(1)})
    root_poly = MultPoly(root_poly, random_root)
    return root_poly
}

func EvalIntPolys(root_poly BigMatrix, sample_max int, setting Setting) (R_values_enc, R_tilde_values, p_values BigMatrix) {
    R, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_tilde, err := SampleMatrix(1, setting.T+1, setting.pk.N)
    if err != nil {panic(err)}
    R_values := NewBigMatrix(1, sample_max, nil)
    R_tilde_values = NewBigMatrix(1, sample_max, nil)
    p_values = NewBigMatrix(1, sample_max, nil)
    for i := 0; i < sample_max; i += 1 {
        x := int64(i*2+1)
        R_values.Set(0, i, EvalPoly(R, x, setting.pk.N))
        R_tilde_values.Set(0, i, EvalPoly(R_tilde, x, setting.pk.N))
        p_values.Set(0, i, EvalPoly(root_poly, x, setting.pk.N))
    }
    R_values_enc, err = EncryptMatrix(R_values, setting)
    if err != nil {panic(err)}
    return
}

func MaskRootPoly(p_values, party_values, R_tilde_values BigMatrix, sample_max int, setting Setting) BigMatrix {
    v := NewBigMatrix(1, sample_max, nil)
    R_tilde_values_enc, err := EncryptMatrix(R_tilde_values, setting)
    if err != nil {panic(err)}
    all_masks, err := MatEncAdd(party_values, R_tilde_values_enc, setting.pk)
    if err != nil {panic(err)}
    for i := 0; i < sample_max; i += 1 {
        val, _, err := setting.pk.Multiply(all_masks.At(0,i), p_values.At(0,i))
        if err != nil {panic(err)}
        v.Set(0, i, val)
    }
    return v
}