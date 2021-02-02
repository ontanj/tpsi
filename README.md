# Threshold Private Set Intersection

This projects provides implementations of FTPSI-diff using AHE and FTPSI-int described in [Multi-Party Threshold Private Set Intersection with Sublinear Communication](https://eprint.iacr.org/2020/600) by Badrinarayanan, Miao and Rindal. However FTPSI-int is slightly modified as bootstrapping was not enable in the cryptosystem used.
Threshold Private Set Intersection allows multiple distrustful parties find the intersection of the respective sets, if this intersection exceeds a given threshold, without revealing what is not in the intersection.

## Cryptosystems

The protocol used [Paillier Threshold Encryption Scheme Implementation](https://github.com/niclabs/tcpaillier) for the additive homomorphic part and [Lattigo](https://github.com/ldsec/lattigo) for the fully homomorphic part. However the implementations builds on the interfaces `AHE_Cryptosystem` and `FHE_Cryptosystem` which allows the use of any implementation satisfying the homomorphic properties.

## Setting

The setting is described by the interfaces `AHE_setting` and `FHE_setting` which contains the number of parties, the threshold value and means of communication. This implementation has only been run on a single machine with parties modelled as goroutines. However by creating a new setting, network communication should be easily achieved.

## Usage

The basic functionalities are implemented in `TPSIdiffWorker` and `TPSIintWorker`.

A simple example application is provided and can be run as `go run main/main.go diff dj 7 main/elements`, which runs FTPSI-diff using the Damgård-Jurik cryptosystem provided in [Paillier Threshold Encryption Scheme Implementation](https://github.com/niclabs/tcpaillier), with a threshold value of 7.