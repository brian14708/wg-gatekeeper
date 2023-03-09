package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/brian14708/wg-gatekeeper/auditlog"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/grpc"
)

var (
	auditDB *auditlog.DB
)

func startLog() {
	d, err := auditlog.New()
	if err != nil {
		log.Fatalf("failed to open auditlog: %v", err)
	}
	auditDB = d

	grpcServer := grpc.NewServer()
	v3.RegisterAccessLogServiceServer(grpcServer, &LogServer{d})

	l, err := net.Listen("tcp", ":9001")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	go grpcServer.Serve(l)
}

type LogServer struct {
	db *auditlog.DB
}

func (ls *LogServer) StreamAccessLogs(s v3.AccessLogService_StreamAccessLogsServer) error {
	for {
		msg, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, l := range msg.GetHttpLogs().GetLogEntry() {
			var ts time.Time
			if t := l.GetCommonProperties().GetStartTime(); t == nil {
				ts = time.Now()
			} else {
				ts = t.AsTime()
			}
			err := ls.db.Insert(
				net.ParseIP(l.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetAddress()),
				uint16(l.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetPortValue()),
				net.ParseIP(l.GetCommonProperties().GetUpstreamRemoteAddress().GetSocketAddress().GetAddress()),
				uint16(l.GetCommonProperties().GetUpstreamRemoteAddress().GetSocketAddress().GetPortValue()),
				l.GetRequest().GetRequestHeadersBytes()+l.GetRequest().GetRequestBodyBytes(),
				l.GetResponse().GetResponseHeadersBytes()+l.GetResponse().GetResponseBodyBytes(),
				auditlog.ProtocolHTTP,
				l.GetRequest().GetAuthority(),
				ts,
			)
			if err != nil {
				fmt.Println(err)
			}
		}
		for _, l := range msg.GetTcpLogs().GetLogEntry() {
			var ts time.Time
			if t := l.GetCommonProperties().GetStartTime(); t == nil {
				ts = time.Now()
			} else {
				ts = t.AsTime()
			}
			proto := auditlog.ProtocolTCP
			if l.GetCommonProperties().GetTlsProperties() != nil {
				proto = auditlog.ProtocolTLS
			}
			err := ls.db.Insert(
				net.ParseIP(l.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetAddress()),
				uint16(l.GetCommonProperties().GetDownstreamDirectRemoteAddress().GetSocketAddress().GetPortValue()),
				net.ParseIP(l.GetCommonProperties().GetUpstreamRemoteAddress().GetSocketAddress().GetAddress()),
				uint16(l.GetCommonProperties().GetUpstreamRemoteAddress().GetSocketAddress().GetPortValue()),
				l.GetConnectionProperties().GetReceivedBytes(),
				l.GetConnectionProperties().GetSentBytes(),
				proto,
				l.GetCommonProperties().GetTlsProperties().GetTlsSniHostname(),
				ts,
			)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}
