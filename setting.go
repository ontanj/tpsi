package tpsi

type AHE_setting interface {
    Threshold() int
    
    Parties() int
    
    AHE_cryptosystem() AHE_Cryptosystem

    Distribute(interface{})
    
    Send(interface{})

    SendTo(int, interface{})
    
    ReceiveAll() []interface{}

    Receive() interface{}

    IsCentral() bool
}

type FHE_setting interface {
    AHE_setting

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
    cs FHE_Cryptosystem
    n int // number of participants
    T int // threshold
    channels []chan interface{}
    channel chan interface{}
}

func (s FHESetting) Threshold() int {
    return s.T
}

func (s FHESetting) Parties() int {
    return s.n
}

func (s FHESetting) AHE_cryptosystem() AHE_Cryptosystem {
    return s.cs
}

func (s FHESetting) FHE_cryptosystem() FHE_Cryptosystem {
    return s.cs
}

func (s FHESetting) Distribute(any interface{}) {
    for _, ch := range s.channels {
        ch <- any
    }
}

func (s FHESetting) Send(any interface{}) {
    s.channel <- any
}

func (s FHESetting) SendTo(i int, any interface{}) {
    s.channels[i] <- any
}

func (s FHESetting) ReceiveAll() []interface{} {
    sl := make([]interface{}, s.n-1)
    for i, ch := range s.channels {
        sl[i] = <-ch
    }
    return sl
}

func (s FHESetting) Receive() interface{} {
    return <-s.channel
}

func (s FHESetting) IsCentral() bool {
    return s.channels != nil
}
