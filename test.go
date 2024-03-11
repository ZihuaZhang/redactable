package main

import (
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"redactableProject/src"
)

func main() {
	// 公私钥生成
	mpk, msk, _ := src.NewFAME().GenerateMasterKeys()
	gamma := []string{"0", "2", "3", "5"}
	sk, err := src.NewFAME().KeyGen(gamma, msk)
	if err != nil {
		fmt.Println(err)
	}
	//生成哈希
	msp, _ := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", false)
	cipher, err := src.NewFAME().Hash(msp, mpk)
	if err != nil {
		fmt.Println(err)
	}
	//修改
	src.NewFAME().Adapt(cipher, sk, mpk)

}
