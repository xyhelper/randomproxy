package main

import (
	"io"
	"log"
	"net"
	"net/http"

	"github.com/gogf/gf/v2/container/garray"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"
	"github.com/gogf/gf/v2/util/gconv"
)

func handleTunneling(ctx g.Ctx, w http.ResponseWriter, r *http.Request) {
	var IPS []interface{}
	// 根据r.Host获取IP
	serverIP := net.ParseIP(r.Host)
	if serverIP != nil {
		g.Log().Debug(ctx, "serverIP", serverIP.String())
		// 如果是IPV4地址
		if serverIP.To4() != nil {
			g.Log().Debug(ctx, "serverIP.To4()", serverIP.To4().String())
			IPS = g.Cfg().MustGet(ctx, "IPS").Slice()
		}
		// 如果是IPV6地址
		if serverIP.To16() != nil {
			g.Log().Debug(ctx, "serverIP.To16()", serverIP.To16().String())
			IPS = g.Cfg().MustGet(ctx, "IP6S").Slice()
		}
	}
	IPA := garray.NewArrayFrom(IPS)
	IP, found := IPA.Rand()
	if !found {
		g.Log().Error(ctx, "no ip found")
		http.Error(w, "no ip found", http.StatusServiceUnavailable)
		return
	}
	ip := gconv.String(IP)
	g.Log().Debug(ctx, "ip", ip)
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 0},
	}
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
	// g.Dump(clientConn.RemoteAddr().String())

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
	g.Log().Debug(ctx, r.Host, clientConn.RemoteAddr().String(), destConn.RemoteAddr().String(), destConn.LocalAddr().String())
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

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

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	ctx := gctx.New()

	server := &http.Server{
		Addr: ":31280",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// g.DumpWithType(r.Header)
			if r.Method == http.MethodConnect {
				g.Log().Debug(ctx, "handleTunneling", r.Host)

				handleTunneling(ctx, w, r)
			} else {
				g.Log().Debug(ctx, "handleHTTP", r.Host)
				handleHTTP(ctx, w, r)
			}
		}),
	}

	log.Printf("Starting http/https proxy server on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
