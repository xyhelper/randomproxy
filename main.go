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
// 直接用端口号替换的/48到/64中间的16位
// 端口号0-65535 正好16位
func randomIPV6FromSubnet(network string, key string) (net.IP, error) {
	// 解析CIDR和包含网络地址和子网掩码
	_, subnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}

	// 获取子网掩码位长度
	// 确定固定部分和需要随机化的部分
	ones, bits := subnet.Mask.Size()
	prefix := make([]byte, len(subnet.IP))
	copy(prefix, subnet.IP)

	// 使用端口生成MD5值
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
		// 随机数来生成IP地址的随机部分
		for i := ones / 8; i < len(prefix); i++ {
			if i*8 >= ones {
				prefix[i] = byte(rand.Intn(256))
			}
		}
	}

	randomIP := net.IP(prefix)
	if bits == 128 {
		// 获取随机生成的IPV6地址
		return randomIP, nil
	}
	return nil, fmt.Errorf("network is not an IPv6 subnet")
}

// handleTunneling is the handler for tunneling requests.
func handleTunneling(ctx g.Ctx, key string, w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		g.Log().Error(ctx, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, isipv6, err := getIPAddress(ctx, host)
	if err != nil {
		g.Log().Error(ctx, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	var IPS []interface{}
	if isipv6 {
		IPS = g.Cfg().MustGet(ctx, "IP6S").Slice()
	} else {
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

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP(ip),
			Port: 0,
		},
	}

	destConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		g.Log().Error(ctx, err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	var wg sync.WaitGroup

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

	wg.Wait()
}

// transfer copies data from src to dst and vice versa.
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer func() {
		_ = dst.Close()
		_ = src.Close()
	}()
	_, _ = io.Copy(dst, src)
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
		i := i
		ewg.Go(func() error {
			currentPort := fmt.Sprintf(":%d", cast.ToInt(startPort)+i)
			g.Log().Info(ctx, "Starting http/https proxy server on ", currentPort)
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
