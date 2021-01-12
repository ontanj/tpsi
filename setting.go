package tpsi

type AHE_setting interface {
    // threshold value
    Threshold() int
    
    // numer of parties
    Parties() int
    
    // ahe cryptosystem
    AHE_cryptosystem() AHE_Cryptosystem

    // used by central party to send a value to all
    Distribute(interface{})
    
    // used by outer parties to send to central party
    Send(interface{})

    // used by central party to send
    // a message to given party
    SendTo(int, interface{})
    
    // for central to await messages from all
    // and get them (ordered) in a slice
    ReceiveAll() []interface{}

    // receive a message from central party
    Receive() interface{}

    // true if this party is central
    IsCentral() bool
}

type FHE_setting interface {
    AHE_setting

    // fhe cryptosystem
    FHE_cryptosystem() FHE_Cryptosystem
}

type AHESetting struct {
    cs AHE_Cryptosystem
    n int // number of participants
    T int // threshold
    channels []chan interface{}
    channel chan interface{}
}

func (s AHESetting) Threshold() int {
    return s.T
}

func (s AHESetting) Parties() int {
    return s.n
}

func (s AHESetting) AHE_cryptosystem() AHE_Cryptosystem {
    return s.cs
}

func (s AHESetting) Distribute(any interface{}) {
    for _, ch := range s.channels {
        ch <- any
    }
}

func (s AHESetting) Send(any interface{}) {
    s.channel <- any
}

func (s AHESetting) SendTo(i int, any interface{}) {
    s.channels[i] <- any
}

func (s AHESetting) ReceiveAll() []interface{} {
    sl := make([]interface{}, s.n-1)
    for i, ch := range s.channels {
        sl[i] = <-ch
    }
    return sl
}

func (s AHESetting) Receive() interface{} {
    return <-s.channel
}

func (s AHESetting) IsCentral() bool {
    return s.channels != nil
}

type FHESetting struct {
    AHESetting
    cs FHE_Cryptosystem
}

func (s FHESetting) AHE_cryptosystem() AHE_Cryptosystem {
    return s.cs
}

func (s FHESetting) FHE_cryptosystem() FHE_Cryptosystem {
    return s.cs
}