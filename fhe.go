package tpsi

import (
    "math/big"
)

func CentralInverseWorker(a Ciphertext, sk Secret_key, setting FHE_setting) Ciphertext {
    return CentralInverseWorkerWithFactor(a, big.NewInt(1), sk, setting)
}

func CentralInverseWorkerWithFactor(a Ciphertext, factor *big.Int, sk Secret_key, setting FHE_setting) Ciphertext {
    mask_clear, err := SampleInt(setting.FHE_cryptosystem().N())
    if err != nil {panic(err)}
    mask, err := setting.FHE_cryptosystem().Encrypt(mask_clear)
    if err != nil {panic(err)}

    // recieve all masks
    masks := toCiphertextSlice(setting.ReceiveAll())
    masks = append(masks, mask)

    // distribute all masks
    setting.Distribute(masks)

    // multipy all masks
    mask = masks[0]
    for i := 1; i < setting.Parties(); i += 1 {
        mask, err = setting.FHE_cryptosystem().Multiply(mask, masks[i])
        if err != nil {panic(err)}
    }
    
    // mask ciphertext
    ab_enc, err := setting.FHE_cryptosystem().Multiply(mask, a)
    if err != nil {panic(err)}

    // decrypt and invert
    ab := CentralDecryptionWorker(ab_enc, sk, setting)
    ab.ModInverse(ab, setting.FHE_cryptosystem().N()).Mul(ab, factor)
    ab_inv_enc, err := setting.FHE_cryptosystem().Encrypt(ab)
    if err != nil {panic(err)}
    
    a_inv, err := setting.FHE_cryptosystem().Multiply(ab_inv_enc, mask)
    if err != nil {panic(err)}

    return a_inv
}

func OuterInverseWorker(a Ciphertext, sk Secret_key, setting FHE_setting) Ciphertext {
    return OuterInverseWorkerWithFactor(a, big.NewInt(1), sk, setting)
}

func OuterInverseWorkerWithFactor(a Ciphertext, factor *big.Int, sk Secret_key, setting FHE_setting) Ciphertext {
    mask_clear, err := SampleInt(setting.FHE_cryptosystem().N())
    if err != nil {panic(err)}
    mask, err := setting.FHE_cryptosystem().Encrypt(mask_clear)
    if err != nil {panic(err)}

    // send mask
    setting.Send(mask)

    // reieve all masks
    masks := (setting.Receive()).([]Ciphertext)
    
    // multiply all masks
    mask = masks[0]
    for i := 1; i < setting.Parties(); i += 1 {
        mask, err = setting.FHE_cryptosystem().Multiply(mask, masks[i])
        if err != nil {panic(err)}
    }

    // mask ciphertext
    ab_enc, err := setting.FHE_cryptosystem().Multiply(mask, a)
    if err != nil {panic(err)}

    // decrypt and invert
    ab := OuterDecryptionWorker(ab_enc, sk, setting)
    ab.ModInverse(ab, setting.FHE_cryptosystem().N()).Mul(ab, factor)
    ab_inv_enc, err := setting.FHE_cryptosystem().Encrypt(ab)
    if err != nil {panic(err)}

    a_inv, err := setting.FHE_cryptosystem().Multiply(ab_inv_enc, mask)
    if err != nil {panic(err)}

    return a_inv
}

func FHEInterpolation(q []Ciphertext, sk Secret_key, setting FHE_setting) []Ciphertext {
    sample_max := 2*setting.Threshold() + 3
    var err error
    cs := setting.FHE_cryptosystem()

    relations := make([][]Ciphertext, sample_max)
    zero, err := cs.Encrypt(big.NewInt(0))

    coeff_pos := 0
    for ; coeff_pos < sample_max; coeff_pos += 1 {
        eq := make([]Ciphertext, sample_max + 1)
        
        x := big.NewInt(int64(2*coeff_pos+1))
        x_pow := big.NewInt(1)
        
        // populate rel_row with full equation
        j := 0
        for ; j < setting.Threshold() + 2; j += 1 {
            if setting.IsCentral() {
                eq[j], err = cs.Encrypt(x_pow)
                if err != nil {panic(err)}
                setting.Distribute(eq[j])
            } else {
                eq[j] = (setting.Receive()).(Ciphertext)
            }
            x_pow.Mul(x_pow, x).Mod(x_pow, cs.N())
        }
        x_pow = big.NewInt(1)
        for ; j < sample_max + 1; j += 1 {
            neg_x, err := cs.Encrypt(new(big.Int).Sub(cs.N(), x_pow))
            if err != nil {panic(err)}
            eq[j], err = cs.Multiply(q[coeff_pos], neg_x)
            if err != nil {panic(err)}
            x_pow.Mul(x_pow, x).Mod(x_pow, cs.N())
        }

        // substitue previous coefficents
        for prev_coeff := 0; prev_coeff < coeff_pos; prev_coeff += 1 {
            coeff := eq[prev_coeff]
            for i := prev_coeff + 1; i < sample_max + 1; i += 1 {
                store, err := cs.Multiply(relations[prev_coeff][i], coeff)
                if err != nil {panic(err)}
                eq[i], err = cs.Add(store, eq[i])
                if err != nil {panic(err)}
            }
            eq[prev_coeff], err = cs.Encrypt(big.NewInt(0))
            if err != nil {panic(err)}
        }
        
        // if we get 0 = 0, we have all relations needed
        if setting.IsCentral() {
            if CentralZeroTestWorker(eq[coeff_pos], sk, setting) {
                break
            }
        } else {
            if OuterZeroTestWorker(eq[coeff_pos], sk, setting) {
                break
            }
        }
        
        // collect current coefficient
        rel_row := make([]Ciphertext, sample_max + 1)
        var coeff_inv Ciphertext
        if setting.IsCentral() {
            coeff_inv = CentralInverseWorkerWithFactor(eq[coeff_pos], new(big.Int).Sub(cs.N(),big.NewInt(1)), sk, setting)
        } else {
            coeff_inv = OuterInverseWorkerWithFactor(eq[coeff_pos], new(big.Int).Sub(cs.N(),big.NewInt(1)), sk, setting)
        }
        rem_coeff := 0
        for ; rem_coeff < coeff_pos + 1; rem_coeff += 1 {
            rel_row[rem_coeff] = zero
        }
        for ; rem_coeff < sample_max + 1; rem_coeff += 1 {
            rel, err := cs.Multiply(eq[rem_coeff], coeff_inv)
            if err != nil {panic(err)}
            rel_row[rem_coeff] = rel
        }
        
        relations[coeff_pos] = rel_row
    }

    interpolated_coeffs := make([]Ciphertext, sample_max + 1)
    interpolated_coeffs[coeff_pos], err = cs.Encrypt(big.NewInt(1))
    
    // solve all coefficients from relations
    for solving_coeff := coeff_pos - 1; solving_coeff >= 0; solving_coeff -= 1 {
        var coeff Ciphertext
        if setting.IsCentral() {
            coeff, err = cs.Encrypt(big.NewInt(0))
            if err != nil {panic(err)}
            setting.Distribute(coeff)
        } else {
            coeff = (setting.Receive()).(Ciphertext)
        }

        if err != nil {panic(err)}
        for known_coeff := solving_coeff + 1; known_coeff <= coeff_pos; known_coeff += 1 {
            store, err := cs.Multiply(relations[solving_coeff][known_coeff], interpolated_coeffs[known_coeff])
            if err != nil {panic(err)}
            coeff, err = cs.Add(coeff, store)
            if err != nil {panic(err)}
        }
        
        interpolated_coeffs[solving_coeff] = coeff
    }

    return interpolated_coeffs[:coeff_pos+1]
}

// returns true if cardinality test passes
func CentralFHECardinalityTestWorker(items []*big.Int, sk Secret_key, setting FHE_setting) bool {
    cs := setting.FHE_cryptosystem()

    // step 2
    z, err := SampleInt(cs.N())
    if err != nil {panic(err)}
    setting.Distribute(z)

    // step 3
    // add mask to polynomial
    rand, err := SampleInt(cs.N())
    if err != nil {panic(err)}
    p := PolyFromRoots(append(items, rand), cs.N())
    
    // evaluate root polynomial
    plain_evals := make([]*big.Int, 2*setting.Threshold()+3)
    evals := make([]Ciphertext, 2*setting.Threshold()+3)
    var point *big.Int
    for i := range evals {
        point = big.NewInt(int64(i * 2 + 1))
        e := EvalPoly(p, point, cs.N())
        plain_evals[i] = e.ModInverse(e, cs.N())
        evals[i], err = cs.Encrypt(plain_evals[i])
        if err != nil {panic(err)}
    }
    eval := EvalPoly(p, z, cs.N())
    eval.ModInverse(eval, cs.N())
    z_eval, err := cs.Encrypt(eval)
    if err != nil {panic(err)}

    // collect outer parties evaluations
    all_evals := toCiphertextSliceSlice(setting.ReceiveAll())
    all_evals = append(all_evals, evals)
    z_evals := toCiphertextSlice(setting.ReceiveAll())
    z_evals = append(z_evals, z_eval)

    // distribute evaluations
    setting.Distribute(all_evals)
    setting.Distribute(z_evals)

    // calculate expected z
    z_exp := z_evals[0]
    for i := 1; i < setting.Parties()-1; i += 1 {
        z_exp, err = cs.Add(z_exp, z_evals[i])
        if err != nil {panic(err)}
    }
    z_exp, err = cs.Multiply(z_exp, z_evals[setting.Parties()-1])
    if err != nil {panic(err)}
    
    // step 4
    // evaluate rational polynomial
    evals_sum := make([]Ciphertext, 2*setting.Threshold()+3)
    for i := range evals_sum {
        sum := all_evals[0][i]
        if err != nil {panic(err)}
        for j := 1; j < setting.Parties()-1; j += 1 {
            sum, err = cs.Add(sum, all_evals[j][i])
            if err != nil {panic(err)}
        }
        evals_sum[i], err = cs.Multiply(all_evals[setting.Parties()-1][i], sum)
        if err != nil {panic(err)}
    }
    
    // interpolate
    interpol := FHEInterpolation(evals_sum, sk, setting)
    num := interpol[:setting.Threshold()+2]
    den := interpol[setting.Threshold()+2:]
    
    num_eval := FHEEvaluate(z, num, setting)
    den_eval := FHEEvaluate(z, den, setting)
    
    // compare interpolation with expected result
    den_inv := CentralInverseWorkerWithFactor(den_eval, new(big.Int).Sub(cs.N(), big.NewInt(1)), sk, setting)
    int_eval, err := cs.Multiply(num_eval, den_inv)
    if err != nil {panic(err)}

    pred, err := cs.Add(int_eval, z_exp)
    if err != nil {panic(err)}
    
    return CentralZeroTestWorker(pred, sk, setting)
}

// returns true if cardinality test passes
func OuterFHECardinalityTestWorker(items []*big.Int, sk Secret_key, setting FHE_setting) bool {
    cs := setting.FHE_cryptosystem()

    // step 2
    z := (setting.Receive()).(*big.Int)

    // step 3
    rand, err := SampleInt(setting.FHE_cryptosystem().N())
    if err != nil {panic(err)}
    p := PolyFromRoots(append(items, rand), cs.N())
    
    // evaluate root polynomial
    plain_evals := make([]*big.Int, 2*setting.Threshold()+3)
    evals := make([]Ciphertext, 2*setting.Threshold()+3)
    var point *big.Int
    for i := range evals {
        point = big.NewInt(int64(i * 2 + 1))
        plain_evals[i] = EvalPoly(p, point, cs.N())
        evals[i], err = cs.Encrypt(plain_evals[i])
        if err != nil {panic(err)}
    }
    eval := EvalPoly(p, z, cs.N())
    z_eval, err := cs.Encrypt(eval)
    if err != nil {panic(err)}
    setting.Send(evals)
    setting.Send(z_eval)

    all_evals := (setting.Receive()).([][]Ciphertext)
    z_evals := (setting.Receive()).([]Ciphertext)

    // calculate expected z
    z_exp := z_evals[0]
    for i := 1; i < setting.Parties()-1; i += 1 {
        z_exp, err = cs.Add(z_exp, z_evals[i])
        if err != nil {panic(err)}
    }
    z_exp, err = cs.Multiply(z_exp, z_evals[setting.Parties()-1])
    if err != nil {panic(err)}
    
    // step 4
    // evaluate rational polynomial
    evals_sum := make([]Ciphertext, 2*setting.Threshold()+3)
    for i := range evals_sum {
        sum := all_evals[0][i]
        if err != nil {panic(err)}
        for j := 1; j < setting.Parties()-1; j += 1 {
            sum, err = cs.Add(sum, all_evals[j][i])
            if err != nil {panic(err)}
        }
        evals_sum[i], err = cs.Multiply(all_evals[setting.Parties()-1][i], sum)
        if err != nil {panic(err)}
    }

    // interpolate
    interpol := FHEInterpolation(evals_sum, sk, setting)
    num := interpol[:setting.Threshold()+2]
    den := interpol[setting.Threshold()+2:]

    num_eval := FHEEvaluate(z, num, setting)
    den_eval := FHEEvaluate(z, den, setting)
    
    // compare interpolation with expected result
    den_inv := OuterInverseWorkerWithFactor(den_eval, new(big.Int).Sub(cs.N(), big.NewInt(1)), sk, setting)
    int_eval, err := cs.Multiply(num_eval, den_inv)
    if err != nil {panic(err)}
    
    pred, err := cs.Add(int_eval, z_exp)
    if err != nil {panic(err)}
    
    return OuterZeroTestWorker(pred, sk, setting)       
}

func FHEEvaluate(x *big.Int, poly []Ciphertext, setting FHE_setting) Ciphertext {
    sum := poly[0]
    x_raised := new(big.Int).Set(x)
    for i := 1; i < len(poly); i += 1 {
        x_enc, err := setting.FHE_cryptosystem().Encrypt(x_raised)
        prod, err := setting.FHE_cryptosystem().Multiply(x_enc, poly[i])
        if err != nil {panic(err)}
        sum, err = setting.FHE_cryptosystem().Add(sum, prod)
        if err != nil {panic(err)}
        x_raised.Mul(x_raised, x).Mod(x_raised, setting.FHE_cryptosystem().N())
    }
    return sum
}

// returns two slices: shared elements & unique elements if cardinality test passes, otherwise nil, nil
func TPSIintWorker(items []*big.Int, sk Secret_key, setting FHE_setting) ([]*big.Int, []*big.Int) {
    var pred bool
    if setting.IsCentral() {
        pred = CentralFHECardinalityTestWorker(items, sk, setting)
    } else {
        pred = OuterFHECardinalityTestWorker(items, sk, setting)
    }

    // exit if cardinality test doesn't pass
    if pred {
        return IntersectionWorker(items, sk, setting)
    } else {
        return nil, nil
    }
}