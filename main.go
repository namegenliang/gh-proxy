package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sizeLimit int64 = 10 << 30 // 默认最大下载大小：10GB
	host            = "0.0.0.0" // 默认监听地址
	port            = 8080      // 默认监听端口
)

//go:embed public/*
var public embed.FS

var (
	exps = []*regexp.Regexp{
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:releases|archive)/.*$`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:blob|raw)/.*$`),
		regexp.MustCompile(`^(?:https?://)?github\.com/([^/]+)/([^/]+)/(?:info|git-).*$`),
		regexp.MustCompile(`^(?:https?://)?raw\.github(?:usercontent|)\.com/([^/]+)/([^/]+)/.+?/.+$`),
		regexp.MustCompile(`^(?:https?://)?gist\.github\.com/([^/]+)/.+?/.+$`),
	}
	httpClient *http.Client
	config     *Config
	configLock sync.RWMutex
)

type Config struct {
	Host           string   `json:"host"`
	Port           int64    `json:"port"`
	SizeLimit      int64    `json:"sizeLimit"`
	WhiteList      []string `json:"whiteList"`
	BlackList      []string `json:"blackList"`
	AllowProxyAll  bool     `json:"allowProxyAll"`
	OtherWhiteList []string `json:"otherWhiteList"`
	OtherBlackList []string `json:"otherBlackList"`
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 300 * time.Second,
		},
	}

	loadConfig()
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			loadConfig()
		}
	}()

	if config.Port == 0 {
		config.Port = port
	}
	if config.SizeLimit <= 0 {
		config.SizeLimit = sizeLimit
	}

	subFS, err := fs.Sub(public, "public")
	if err != nil {
		panic(fmt.Sprintf("无法创建子文件系统: %v", err))
	}
	router.StaticFS("/", http.FS(subFS))
	router.NoRoute(handler)

	fmt.Printf("HTTP 服务已启动: %s:%d\n", config.Host, config.Port)
	err = router.Run(fmt.Sprintf("%s:%d", config.Host, config.Port))
	if err != nil {
		fmt.Printf("启动服务失败: %v\n", err)
	}
}

func handler(c *gin.Context) {
	rawPath := strings.TrimPrefix(c.Request.URL.RequestURI(), "/")
	for strings.HasPrefix(rawPath, "/") {
		rawPath = strings.TrimPrefix(rawPath, "/")
	}

	if !strings.HasPrefix(rawPath, "http") {
		rawPath = "https://" + rawPath
	}

	matches := checkURL(rawPath)
	if matches != nil {
		if len(config.WhiteList) > 0 && !checkList(matches, config.WhiteList) {
			c.String(http.StatusForbidden, "Forbidden by white list.")
			return
		}
		if len(config.BlackList) > 0 && checkList(matches, config.BlackList) {
			c.String(http.StatusForbidden, "Forbidden by black list.")
			return
		}
	} else {
		if !config.AllowProxyAll {
			c.String(http.StatusForbidden, "Invalid input.")
			return
		}
		if len(config.OtherWhiteList) > 0 && !checkOtherList(rawPath, config.OtherWhiteList) {
			c.String(http.StatusForbidden, "Forbidden by white list.")
			return
		}
		if len(config.OtherBlackList) > 0 && checkOtherList(rawPath, config.OtherBlackList) {
			c.String(http.StatusForbidden, "Forbidden by black list.")
			return
		}
	}

	if exps[1].MatchString(rawPath) {
		rawPath = strings.Replace(rawPath, "/blob/", "/raw/", 1)
	}

	proxy(c, rawPath)
}

func proxy(c *gin.Context, u string) {
	req, err := http.NewRequest(c.Request.Method, u, c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, "server error: %v", err)
		return
	}
	for key, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Del("Host")

	resp, err := httpClient.Do(req)
	if err != nil {
		c.String(http.StatusInternalServerError, "fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > config.SizeLimit {
			c.String(http.StatusRequestEntityTooLarge, "File too large.")
			return
		}
	}

	for _, h := range []string{"Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security"} {
		resp.Header.Del(h)
	}
	for k, v := range resp.Header {
		for _, val := range v {
			c.Header(k, val)
		}
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		if checkURL(loc) != nil {
			c.Header("Location", "/" + loc)
		} else {
			proxy(c, loc)
			return
		}
	}

	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		fmt.Printf("加载配置文件失败: %v\n", err)
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var newConfig Config
	if err := decoder.Decode(&newConfig); err != nil {
		fmt.Printf("解析配置文件失败: %v\n", err)
		return
	}

	configLock.Lock()
	config = &newConfig
	configLock.Unlock()
}

func checkURL(u string) []string {
	for _, exp := range exps {
		if matches := exp.FindStringSubmatch(u); matches != nil {
			return matches[1:]
		}
	}
	return nil
}

func checkList(matches, list []string) bool {
	for _, item := range list {
		if strings.HasPrefix(matches[0], item) {
			return true
		}
	}
	return false
}

func checkOtherList(u string, list []string) bool {
	for _, item := range list {
		if strings.Contains(u, item) {
			return true
		}
	}
	return false
}