package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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
	"strconv"
	"time"
)

// Config 配置文件结构
type Config struct {
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Password  string `json:"password"`
	Cipher    string `json:"cipher"` // 目前仅支持 aes-256-gcm
	LocalAddr string `json:"local_addr"`
	LocalPort int    `json:"local_port"`
}

const (
	keySize   = 32 // AES-256
	saltSize  = 32
	nonceSize = 12
	tagSize   = 16
	maxChunk  = 0x3FFF
)

// hkdfSHA1 实现 HKDF-SHA1，提取和扩展两个阶段
func hkdfSHA1(secret, salt, info []byte, length int) []byte {
	// 如果 salt 为空，使用长度等于 hash 输出大小的零字节串（SHA1 输出 20 字节）
	if len(salt) == 0 {
		salt = make([]byte, sha1.Size)
	}
	// 提取阶段
	extract := hmac.New(sha1.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)

	// 扩展阶段
	var result []byte
	t := []byte{}
	counter := byte(1)
	for len(result) < length {
		expand := hmac.New(sha1.New, prk)
		expand.Write(t)
		expand.Write(info)
		expand.Write([]byte{counter})
		t = expand.Sum(nil)
		result = append(result, t...)
		counter++
	}
	return result[:length]
}

// ShadowsocksAEAD 封装 AEAD 加密连接
type ShadowsocksAEAD struct {
	net.Conn
	cipher  cipher.AEAD
	nonce   []byte
}

func NewShadowsocksAEAD(conn net.Conn, masterKey []byte) (*ShadowsocksAEAD, error) {
	// 生成随机 salt
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := conn.Write(salt); err != nil {
		return nil, err
	}

	// 从主密钥和 salt 派生会话密钥
	sessionKey := hkdfSHA1(masterKey, salt, []byte("ss-subkey"), keySize)

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

// incrementNonce 小端递增
func (s *ShadowsocksAEAD) incrementNonce() {
	for i := 0; i < len(s.nonce); i++ {
		s.nonce[i]++
		if s.nonce[i] != 0 {
			break
		}
	}
}

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

	return copy(p, decData), nil
}

// dialShadowsocks 建立到目标地址的 Shadowsocks 加密连接
func dialShadowsocks(ssServer string, ssPort int, password string, target string) (net.Conn, error) {
	// 连接服务器
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ssServer, ssPort), 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 从密码派生主密钥（HKDF-SHA1(password, nil, "ss-subkey")）
	masterKey := hkdfSHA1([]byte(password), nil, []byte("ss-subkey"), keySize)

	// 创建加密连接
	ssConn, err := NewShadowsocksAEAD(conn, masterKey)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 解析目标地址
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

	// 构造 SOCKS5 地址
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
			return nil, fmt.Errorf("主机名过长")
		}
		addr = append(addr, 0x03, byte(len(host)))
		addr = append(addr, host...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	addr = append(addr, portBytes...)

	// 发送目标地址
	if _, err := ssConn.Write(addr); err != nil {
		ssConn.Close()
		return nil, err
	}
	return ssConn, nil
}

// handleHTTP 处理 HTTP 代理请求
func handleHTTP(w http.ResponseWriter, r *http.Request, ssServer string, ssPort int, password string) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r, ssServer, ssPort, password)
		return
	}

	target := r.Host
	if target == "" {
		http.Error(w, "缺少 Host", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "80")
	}

	ssConn, err := dialShadowsocks(ssServer, ssPort, password, target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer ssConn.Close()

	if err := r.Write(ssConn); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(ssConn), r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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
		http.Error(w, "不支持 Hijacker", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		io.Copy(ssConn, clientConn)
		ssConn.Close()
	}()
	io.Copy(clientConn, ssConn)
}

func main() {
	configPath := flag.String("c", "config.json", "配置文件路径")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("读取配置文件失败: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("解析配置文件失败: %v", err)
	}
	if cfg.Cipher != "aes-256-gcm" {
		log.Fatalf("仅支持 aes-256-gcm")
	}

	localAddr := fmt.Sprintf("%s:%d", cfg.LocalAddr, cfg.LocalPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", localAddr, err)
	}
	log.Printf("HTTP 代理启动于 %s，使用 Shadowsocks 服务器 %s:%d", localAddr, cfg.Server, cfg.Port)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHTTP(w, r, cfg.Server, cfg.Port, cfg.Password)
		}),
		TLSNextProto: make(map[string]func(*http.Server, *net.TCPConn, http.Handler)),
	}

	if err := server.Serve(listener); err != nil {
		log.Fatalf("HTTP 服务错误: %v", err)
	}
}
