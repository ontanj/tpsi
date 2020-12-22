package tpsi

type AHE_setting interface {
    Threshold() int
    
    Parties() int

    Items() int
    
    AHE_cryptosystem() AHE_Cryptosystem
}

type FHE_setting interface {
    AHE_setting

    FHE_cryptosystem() FHE_Cryptosystem
}

type AHESetting struct {
    cs AHE_Cryptosystem
    n int // number of participants
    m int // set size
    T int // threshold
}

func (s AHESetting) Threshold() int {
    return s.T
}

func (s AHESetting) Parties() int {
    return s.n
}

func (s AHESetting) Items() int {
    return s.m
}

func (s AHESetting) AHE_cryptosystem() AHE_Cryptosystem {
    return s.cs
}

type FHESetting struct {
    cs FHE_Cryptosystem
    n int // number of participants
    m int // set size
    T int // threshold
}

func (s FHESetting) Threshold() int {
    return s.T
}

func (s FHESetting) Parties() int {
    return s.n
}

func (s FHESetting) Items() int {
    return s.m
}

func (s FHESetting) AHE_cryptosystem() AHE_Cryptosystem {
    return s.cs
}

func (s FHESetting) FHE_cryptosystem() FHE_Cryptosystem {
    return s.cs
}