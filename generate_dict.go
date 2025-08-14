//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
)

// generateDictPasswords 生成常见的8位密码组合
func generateDictPasswords() []string {
	var passwords []string

	// 常见的8位密码模式
	patterns := []string{
		// 纯数字
		"12345678", "87654321", "11111111", "00000000",
		"12341234", "56785678", "98769876", "13579135",
		"24681357", "19900101", "20000101", "20230101",

		// 字母+数字组合
		"admin123", "root1234", "password", "qwerty12",
		"abc12345", "test1234", "user1234", "guest123",
		"admin888", "root0000", "xiaomi01", "redmi123",

		// 路由器常见密码
		"admin888", "12345678", "password", "admin123",
		"root1234", "xiaomi88", "redmi888", "miwifi01",
		"router01", "wifi1234", "internet", "network1",

		// 年份相关
		"20231234", "20221234", "20211234", "20201234",
		"19901234", "19951234", "20001234", "20101234",
	}

	// 添加基础模式
	for _, pattern := range patterns {
		if len(pattern) == 8 {
			passwords = append(passwords, pattern)
		}
	}

	// 生成数字序列
	for i := 0; i <= 99999999; i += 11111111 {
		password := fmt.Sprintf("%08d", i)
		passwords = append(passwords, password)
	}

	return passwords
}

// saveDictToFile 保存密码字典到文件
func saveDictToFile(passwords []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, password := range passwords {
		_, err := file.WriteString(password + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func mainDict() {
	// 生成密码字典并保存到文件
	passwords := generateDictPasswords()
	err := saveDictToFile(passwords, "password_dict.txt")
	if err != nil {
		fmt.Printf("保存密码字典失败: %v\n", err)
		return
	}
	fmt.Printf("成功生成 %d 个密码，保存到 password_dict.txt\n", len(passwords))
}

func main() {
	mainDict()
}
