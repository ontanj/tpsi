package main

import (
    "fmt"
    "os"
    "io/ioutil"
    "strings"
    "math/big"
    "github.com/ontanj/tpsi"
    "strconv"
    "sync"
    "time"
)

func main() {
    startT := time.Now()
    
    if len(os.Args) != 5 {
        fmt.Println("Wrong number of arguments: protocol cryptosystem threshold file-with-elements")
        os.Exit(1)
    }

    prt := os.Args[1]
    css := os.Args[2]
    T, err := strconv.Atoi(os.Args[3])
    if err != nil {
        fmt.Println("Error when parsing T")
        os.Exit(1)
    }
    elements := parseElementfile(os.Args[4])
    for i, v := range elements {
        fmt.Printf("party %d: %v\n", i+1, readableElements(v))
    }
    fmt.Println("-------")

    n := len(elements)

    var wg sync.WaitGroup
    if prt == "int" {
        var cs []tpsi.FHE_Cryptosystem
        var sks []tpsi.Secret_key
        if css == "bfv" {
            bfvcs, bfvsks := tpsi.SetupBFV(n)
            sks = make([]tpsi.Secret_key, n)
            cs = make([]tpsi.FHE_Cryptosystem, n)
            for i, sk := range bfvsks {
                sks[i] = sk
                cs[i] = bfvcs[i]
            }
        } else {
            fmt.Printf("Cryptosystem %v not available for %v.", css, prt)
            os.Exit(1)
        }
        settings := tpsi.SetupFHE(n, int(T), cs)
        wg.Add(n)
        for i := 0; i < n; i += 1 {
            go func(i int) {
                sh, uq := tpsi.TPSIintWorker(tpsi.EncodeElements(elements[i]), sks[i], settings[i])
                if sh != nil {
                    fmt.Printf("party %d: shared elements: %v\n         unique elements: %v\n", i+1,
                    readableElements(tpsi.DecodeElements(sh)), readableElements(tpsi.DecodeElements(uq)))
                } else {
                    fmt.Printf("party %d: cardinality test failed\n", i)
                }
                wg.Done()
            }(i)
        }
    } else if prt == "diff" {
        var cs tpsi.AHE_Cryptosystem
        var sks []tpsi.Secret_key
        if css == "dj" {
            var djsks []tpsi.DJ_secret_key
            cs, djsks, err = tpsi.NewDJCryptosystem(n)
            if err != nil {panic(err)}
            sks = make([]tpsi.Secret_key, n)
            for i, sk := range djsks {
                sks[i] = sk
            }
        } else if css == "bfv" {
            bfvcs, bfvsks := tpsi.SetupBFV(n)
            cs = bfvcs[0]
            sks = make([]tpsi.Secret_key, n)
            for i, sk := range bfvsks {
                sks[i] = sk
            }
        } else {
            fmt.Printf("Cryptosystem %v not available for %v.", css, prt)
            os.Exit(1)
        }
        settings := tpsi.SetupAHE(n, int(T), cs)
        wg.Add(n)
        for i := 0; i < n; i += 1 {
            go func(i int) {
                sh, uq := tpsi.TPSIdiffWorker(tpsi.EncodeElements(elements[i]), sks[i], settings[i])
                if sh != nil {
                    fmt.Printf("party %d: shared elements: %v\n         unique elements: %v\n", i+1,
                        readableElements(tpsi.DecodeElements(sh)), readableElements(tpsi.DecodeElements(uq)))
                } else {
                    fmt.Printf("party %d: cardinality test failed\n", i)
                }
                wg.Done()
            }(i)
        }
    }
    wg.Wait()
    t := time.Now()
    fmt.Printf("%f s elapsed\n", t.Sub(startT).Seconds())
}

func readableElements(elements []*big.Int) string {
    var sb strings.Builder
    for _, e := range elements {
        sb.WriteString(fmt.Sprintf("%d, ", e))
    }
    str := sb.String()
    if len(str) >= 3 {
        return str[0:len(str)-2]
    } else {
        return "none"
    }
}

func parseElementfile(filename string) [][]*big.Int {
    dat, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Printf("Error when reading file %v\n", filename)
        os.Exit(1)
    }
    file := string(dat)
    file = strings.Replace(file, "\r\n", "\n", -1)
    file = strings.Trim(file, "\r\n")
    file_lines := strings.Split(file, "\n")
    elements := make([][]*big.Int, len(file_lines))
    var succ bool
    for i := 0; i < len(file_lines); i += 1 {
        party := strings.Split(file_lines[i], ",")
        party_elements := make([]*big.Int, len(party))
        for j, v := range party {
            party_elements[j], succ = new(big.Int).SetString(v, 10)
            if !succ {
                fmt.Printf("Error when parsing element %v\n", v)
                os.Exit(1)
            }
        }
        elements[i] = party_elements
        if i > 0 && len(elements[i-1]) != len(elements[i]) {
            fmt.Println("Error: different set sizes")
            os.Exit(1)
        }
    }
    return elements
}