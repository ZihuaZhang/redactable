package main

import (
	"encoding/json"
	"fmt"
	"github.com/ZihuaZhang/redactable/src"
	"github.com/fentec-project/gofe/abe"
)

type Testkkk struct {
	isYes bool
}

func main() {
	// 公私钥生成
	mpk, msk, _ := src.NewFAME().GenerateMasterKeys()

	kkk := Testkkk{isYes: true}
	fmt.Println(kkk)
	gamma := []string{"0", "2", "3", "5"}
	sk, err := src.NewFAME().KeyGen(gamma, msk)
	if err != nil {
		fmt.Println(err)
	}
	//生成哈希
	msp, _ := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", false)

	//将 mpk 转换为 JSON 字节切片
	kkkJSON, err := json.Marshal(kkk)
	if err != nil {
		// 处理错误
		panic(err)
	}
	fmt.Println("kkk JSON:", string(kkkJSON))

	// 将 msp 转换为 JSON 字节切片
	mspJSON, err := json.Marshal(msp)
	if err != nil {
		// 处理错误
		panic(err)
	}
	fmt.Println("msp JSON:", mspJSON)

	// 反向操作：将 JSON 字节切片解码为 mpk 结构体
	var decodedMPK Testkkk
	err = json.Unmarshal(kkkJSON, &decodedMPK)
	if err != nil {
		// 处理错误
		panic(err)
	}
	fmt.Println("Decoded mpk:", decodedMPK)

	// 反向操作：将 JSON 字节切片解码为 msp 结构体
	var decodedMSP abe.MSP
	err = json.Unmarshal(mspJSON, &decodedMSP)
	if err != nil {
		// 处理错误
		panic(err)
	}
	fmt.Println("Decoded msp:", decodedMSP)

	cipher, err := src.NewFAME().Hash(msp, mpk)
	if err != nil {
		fmt.Println(err)
	}
	//修改
	src.NewFAME().Adapt(cipher, sk, mpk)

}
