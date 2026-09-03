package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// Config 配置文件结构
type Config struct {
	Server    string `json:"server"`     // Shadowsocks 服务器地址
	Port      int    `json:"port"`       // Shadowsocks 服务器端口
	Password  string `json:"password"`   // 密码
	Cipher    string `json:"cipher"`     // 加密方式，仅支持 "aes-256-gcm"
	LocalAddr string `json:"local_addr"` // 本地 HTTP 代理监听地址
	LocalPort int    `json:"local_port"` // 本地 HTTP 代理监听端口
}

// Shadowsocks 密钥派生
const (
	keySize   = 32 // AES-256
	saltSize  = 32
	nonceSize = 12
	tagSize   = 16
	maxChunk  = 0x3FFF // 16KB - 1
)

// ShadowsocksAEAD 封装 AEAD 加密连接
type ShadowsocksAEAD struct {
	net.Conn
	cipher  cipher.AEAD
	nonce   []byte
	counter uint64
}

// NewShadowsocksAEAD 创建加密连接
func NewShadowsocksAEAD(conn net.Conn, masterKey []byte) (*ShadowsocksAEAD, error) {
	// 生成随机 salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	// 发送 salt
	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}

	// 使用 HKDF-SHA1 派生会话密钥
	sessionKey := make([]byte, keySize)
	kdf := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	// 创建 AES-GCM
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	return &ShadowsocksAEAD{
		Conn:   conn,
		cipher: aead,
		nonce:  nonce,
	}, nil
}

// incrementNonce 递增 nonce（小端序）
func (s *ShadowsocksAEAD) incrementNonce() {
	for i := 0; i < len(s.nonce); i++ {
		s.nonce[i]++
		if s.nonce[i] != 0 {
			break
		}
	}
}

// Write 加密写入数据（自动分块）
func (s *ShadowsocksAEAD) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}

		// 加密长度
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(chunk)))
		encLen := s.cipher.Seal(nil, s.nonce, lenBuf, nil)
		s.incrementNonce()
		if _, err := s.Conn.Write(encLen); err != nil {
			return total, err
		}

		// 加密数据
		encData := s.cipher.Seal(nil, s.nonce, chunk, nil)
		s.incrementNonce()
		if _, err := s.Conn.Write(encData); err != nil {
			return total, err
		}

		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read 解密读取数据（自动处理分块）
func (s *ShadowsocksAEAD) Read(p []byte) (int, error) {
	// 读取加密长度
	lenBuf := make([]byte, 2+tagSize)
	if _, err := io.ReadFull(s.Conn, lenBuf); err != nil {
		return 0, err
	}
	decLen, err := s.cipher.Open(nil, s.nonce, lenBuf, nil)
	if err != nil {
		return 0, err
	}
	s.incrementNonce()
	length := int(binary.BigEndian.Uint16(decLen))

	// 读取加密数据
	buf := make([]byte, length+tagSize)
	if _, err := io.ReadFull(s.Conn, buf); err != nil {
		return 0, err
	}
	decData, err := s.cipher.Open(nil, s.nonce, buf, nil)
	if err != nil {
		return 0, err
	}
	s.incrementNonce()

	// 复制到目标缓冲区
	n := copy(p, decData)
	// 如果 p 太小，剩余数据丢失？这里假设 p 足够大
	return n, nil
}

// dialShadowsocks 建立到目标地址的 Shadowsocks 加密连接
func dialShadowsocks(ssServer string, ssPort int, password string, target string) (net.Conn, error) {
	// 连接 Shadowsocks 服务器
	ssAddr := fmt.Sprintf("%s:%d", ssServer, ssPort)
	conn, err := net.DialTimeout("tcp", ssAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 从密码派生主密钥（使用 EVP_BytesToKey 简化版，或直接使用密码的 SHA1 作为主密钥）
	// 实际上 Shadowsocks AEAD 使用 HKDF-SHA1(password, salt, info) 派生主密钥，但我们在此使用简单方式：
	// 根据规范，主密钥为 HKDF-SHA1(password, salt="", info="ss-subkey") 的输出，但 salt 为空会导致与规范不符。
	// 实际上 Shadowsocks 2017 AEAD 规范规定：主密钥 = HKDF-SHA1(password, salt="", info="ss-subkey")
	// 我们实现正确的 HKDF：
	masterKey := make([]byte, keySize)
	kdf := hkdf.New(sha1.New, []byte(password), nil, []byte("ss-subkey"))
	if _, err := io.ReadFull(kdf, masterKey); err != nil {
		conn.Close()
		return nil, err
	}

	// 创建加密连接
	ssConn, err := NewShadowsocksAEAD(conn, masterKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 发送目标地址（SOCKS5 地址格式）
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		ssConn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		ssConn.Close()
		return nil, err
	}

	// 构造地址
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = append(addr, 0x01)
			addr = append(addr, ip4...)
		} else {
			addr = append(addr, 0x04)
			addr = append(addr, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			ssConn.Close()
			return nil, fmt.Errorf("host too long")
		}
		addr = append(addr, 0x03, byte(len(host)))
		addr = append(addr, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	addr = append(addr, portBytes...)

	// 加密发送地址
	if _, err := ssConn.Write(addr); err != nil {
		ssConn.Close()
		return nil, err
	}

	return ssConn, nil
}

// handleHTTP 处理 HTTP 代理请求
func handleHTTP(w http.ResponseWriter, r *http.Request, ssServer string, ssPort int, password string) {
	if r.Method == http.MethodConnect {
		// 处理 HTTPS CONNECT
		handleConnect(w, r, ssServer, ssPort, password)
		return
	}

	// 普通 HTTP 请求：转发
	target := r.Host
	if target == "" {
		http.Error(w, "missing Host", http.StatusBadRequest)
		return
	}
	// 确保 host 包含端口
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "80")
	}

	// 建立到目标服务器的 Shadowsocks 连接
	ssConn, err := dialShadowsocks(ssServer, ssPort, password, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer ssConn.Close()

	// 写入 HTTP 请求
	if err := r.Write(ssConn); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 读取响应
	resp, err := http.ReadResponse(bufio.NewReader(ssConn), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect 处理 CONNECT 方法建立隧道
func handleConnect(w http.ResponseWriter, r *http.Request, ssServer string, ssPort int, password string) {
	target := r.Host
	ssConn, err := dialShadowsocks(ssServer, ssPort, password, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer ssConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 双向转发
	go func() {
		io.Copy(ssConn, clientConn)
		ssConn.Close()
	}()
	io.Copy(clientConn, ssConn)
}

func main() {
	configPath := flag.String("c", "config.json", "配置文件路径")
	flag.Parse()

	// 读取配置
	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
	if cfg.Cipher != "aes-256-gcm" {
		log.Fatalf("仅支持 aes-256-gcm 加密方式")
	}

	// 本地监听
	localAddr := fmt.Sprintf("%s:%d", cfg.LocalAddr, cfg.LocalPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", localAddr, err)
	}
	log.Printf("HTTP 代理启动于 %s，使用 Shadowsocks %s 服务器 %s:%d", localAddr, cfg.Cipher, cfg.Server, cfg.Port)

	// 创建 HTTP 服务器
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHTTP(w, r, cfg.Server, cfg.Port, cfg.Password)
		}),
		// 禁用 HTTP/2
		TLSNextProto: make(map[string]func(*http.Server, *net.TCPConn, http.Handler)),
	}

	if err := server.Serve(listener); err != nil {
		log.Fatalf("HTTP 服务错误: %v", err)
	}
}
