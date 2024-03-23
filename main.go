package main

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"randomproxy/signals"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/os/gcache"

	"github.com/spf13/cast"
	"golang.org/x/sync/errgroup"

	"github.com/gogf/gf/v2/container/garray"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/util/gconv"
)

var DNSCache = gcache.New()

// randomIPV6FromSubnet generates a random IPv6 address from a given subnet.[根据指定的Port获取随机IP]
func randomIPV6FromSubnet(network string, key string) (net.IP, error) {
	_, subnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}

	ones, bits := subnet.Mask.Size()
	prefix := make([]byte, len(subnet.IP))
	copy(prefix, subnet.IP)

	if key != "" {
		hasher := md5.New()
		hasher.Write([]byte(key))
		hashedKey := hasher.Sum(nil)

		for i := ones / 8; i < len(prefix); i++ {
			if i < len(hashedKey) {
				prefix[i] = hashedKey[i-(ones/8)]
			} else {
				prefix[i] = byte(rand.Intn(256))
			}
		}
	} else {
		for i := ones / 8; i < len(prefix); i++ {
			if i*8 >= ones {
				prefix[i] = byte(rand.Intn(256))
			}
		}
	}

	randomIP := net.IP(prefix)
	if bits == 128 {
		return randomIP, nil
	}
	return nil, err
}

func handleTunneling(ctx g.Ctx, key string, w http.ResponseWriter, r *http.Request) {
	var IPS []interface{}
	// 获取域名不带端口
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		g.Log().Error(ctx, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// g.Log().Debug(ctx, "host", host)
	// 根据r.Host获取IP

	_, isipv6, err := getIPAddress(ctx, host)
	if err != nil {
		g.Log().Error(ctx, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if isipv6 {
		// g.Log().Debug(ctx, "serverIP", serverIP)
		IPS = g.Cfg().MustGet(ctx, "IP6S").Slice()
	} else {
		// g.Log().Debug(ctx, "serverIP", serverIP)
		IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
	}
	if len(IPS) == 0 {
		IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
	}

	IPA := garray.NewArrayFrom(IPS)
	IP, found := IPA.Rand()
	if !found {
		g.Log().Error(ctx, "no ip found")
		http.Error(w, "no ip found", http.StatusServiceUnavailable)
		return
	}
	ip := gconv.String(IP)
	ipv6sub := g.Cfg().MustGet(ctx, "IP6SUB").String()
	if isipv6 && ipv6sub != "" {
		tempIP, _ := randomIPV6FromSubnet(ipv6sub, key)
		ip = tempIP.String()
	}

	// g.Log().Debug(ctx, "ip", ip)
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 0},
	}
	// 创建一个 WaitGroup 对象
	var wg sync.WaitGroup

	// 创建代理服务器连接
	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		g.Log().Error(ctx, err.Error())

		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	// 启动两个 goroutine 进行数据传输
	wg.Add(2)
	go func() {
		defer wg.Done()
		transfer(destConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		transfer(clientConn, destConn)
	}()
	g.Log().Debug(ctx, r.Host, clientConn.RemoteAddr().String(), destConn.RemoteAddr().String(), destConn.LocalAddr().String())

	// 等待所有 goroutine 完成
	wg.Wait()
	// g.Log().Debug(ctx, "will close", r.Host, clientConn.RemoteAddr().String(), destConn.RemoteAddr().String(), destConn.LocalAddr().String())
	// 关闭连接
	clientConn.Close()
	destConn.Close()
	// g.Log().Debug(ctx, "close", r.Host, clientConn.RemoteAddr().String(), destConn.RemoteAddr().String(), destConn.LocalAddr().String())

}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func getIPAddress(ctx g.Ctx, domain string) (ip string, ipv6 bool, err error) {
	var ipAddresses []string
	// 先从缓存中获取
	if v := DNSCache.MustGet(ctx, domain).Strings(); len(v) > 0 {
		ipAddresses = v
	} else {
		ipAddresses, err = net.LookupHost(domain)
		if err != nil {
			return "", false, err
		}
		DNSCache.Set(ctx, domain, ipAddresses, 5*time.Minute)
	}
	for _, ipAddress := range ipAddresses {
		// 如果是地址包含 : 说明是IPV6地址
		if strings.Contains(ipAddress, ":") {
			return ipAddress, true, nil
		}
	}
	return ipAddresses[0], false, nil
}

func main() {
	var (
		ctx       = signals.WithStandardSignals(gctx.New())
		startPort = g.Cfg().MustGetWithEnv(ctx, "PORT").String()
		startLen  = g.Cfg().MustGetWithEnv(ctx, "PORT_LEN").Int()
		ewg       = new(errgroup.Group)
		servers   []*http.Server
		lock      sync.Mutex
	)

	// set random seed.
	rand.Seed(time.Now().UnixNano())

	// set start port default value.
	if startPort == "" {
		startPort = "30000"
	}

	// set start length default value.
	if startLen <= 0 {
		startLen = 10000
	}

	// start multiple http servers.
	for i := 0; i <= startLen; i++ {
		currentPort := fmt.Sprintf(":%d", cast.ToInt(startPort)+i)
		g.Log().Info(ctx, "Starting http/https proxy server on ", currentPort)

		ewg.Go(func() error {
			server := &http.Server{
				Addr: currentPort,
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodConnect {
						handleTunneling(ctx, currentPort, w, r)
					} else {
						handleHTTP(ctx, w, r)
					}
				}),
			}

			lock.Lock()
			servers = append(servers, server)
			lock.Unlock()
			if err := server.ListenAndServe(); err != http.ErrServerClosed {
				g.Log().Error(ctx, err)
				return err
			}

			g.Log().Info(ctx, "Stopping http/https proxy server on ", currentPort)
			return nil
		})
	}

	go func() {
		<-ctx.Done()
		for _, server := range servers {
			if err := server.Shutdown(context.Background()); err != nil {
				g.Log().Error(ctx, err)
			}
		}
	}()

	if err := ewg.Wait(); err != nil {
		g.Log().Error(ctx, err)
	}

	g.Log().Info(ctx, "Servers Shutdown")
}

// handleHTTP is the handler for http requests.
func handleHTTP(ctx g.Ctx, w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// copyHeader copies the header from src to dst.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
