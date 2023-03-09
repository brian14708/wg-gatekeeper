package main

import (
	"context"
	"fmt"
	"time"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	grpcv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	http_inspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/http_inspector/v3"
	original_dstv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/original_dst/v3"
	tls_inspectorv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	http_connection_managerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tcp_proxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

type XdsServer struct {
	xds server.Server
	sc  cache.SnapshotCache
}

func newXdsServer(srv *grpc.Server) {
	sc := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
	s := &XdsServer{
		xds: server.NewServer(context.Background(), sc, nil),
		sc:  sc,
	}

	ss, err := snapshot()
	if err != nil {
		panic(err)
	}
	if err := sc.SetSnapshot(context.Background(), "proxy", ss); err != nil {
		panic(err)
	}

	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(srv, s.xds)
	clusterservice.RegisterClusterDiscoveryServiceServer(srv, s.xds)
	listenerservice.RegisterListenerDiscoveryServiceServer(srv, s.xds)
}

func snapshot() (*cache.Snapshot, error) {
	ss, err := cache.NewSnapshot(
		fmt.Sprintf("%d", time.Now().Unix()),
		map[resource.Type][]types.Resource{
			resource.ClusterType: {
				&clusterv3.Cluster{
					Name: "passthrough",
					ClusterDiscoveryType: &clusterv3.Cluster_Type{
						Type: clusterv3.Cluster_ORIGINAL_DST,
					},
					ConnectTimeout: durationpb.New(10 * time.Second),
					LbPolicy:       clusterv3.Cluster_CLUSTER_PROVIDED,
				},
				&clusterv3.Cluster{
					Name: "accesslog",
					ClusterDiscoveryType: &clusterv3.Cluster_Type{
						Type: clusterv3.Cluster_STATIC,
					},
					ConnectTimeout: durationpb.New(5 * time.Second),
					LbPolicy:       clusterv3.Cluster_ROUND_ROBIN,
					LoadAssignment: &endpointv3.ClusterLoadAssignment{
						ClusterName: "accesslog",
						Endpoints: []*endpointv3.LocalityLbEndpoints{{
							LbEndpoints: []*endpointv3.LbEndpoint{{
								HostIdentifier: &endpointv3.LbEndpoint_Endpoint{
									Endpoint: &endpointv3.Endpoint{
										Address: &corev3.Address{
											Address: &corev3.Address_SocketAddress{
												SocketAddress: &corev3.SocketAddress{
													Address: "127.0.0.1",
													PortSpecifier: &corev3.SocketAddress_PortValue{
														PortValue: uint32(*flagEnvoyListen),
													},
												},
											},
										},
									},
								},
							}},
						}},
					},
					TypedExtensionProtocolOptions: map[string]*anypb.Any{
						"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": mustMarshalAny(&httpv3.HttpProtocolOptions{
							UpstreamProtocolOptions: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_{
								ExplicitHttpConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig{
									ProtocolConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
								},
							},
						}),
					},
				},
			},
			resource.ListenerType: {
				&listenerv3.Listener{
					Name: "proxy",
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Protocol: corev3.SocketAddress_TCP,
								Address:  "0.0.0.0",
								PortSpecifier: &corev3.SocketAddress_PortValue{
									PortValue: uint32(*flagEnvoyTcp),
								},
							},
						},
					},
					ListenerFilters: []*listenerv3.ListenerFilter{
						{
							Name: "envoy.filters.listener.tls_inspector",
							ConfigType: &listenerv3.ListenerFilter_TypedConfig{
								TypedConfig: mustMarshalAny(&tls_inspectorv3.TlsInspector{}),
							},
						},
						{
							Name: "envoy.filters.listener.http_inspector",
							ConfigType: &listenerv3.ListenerFilter_TypedConfig{
								TypedConfig: mustMarshalAny(&http_inspectorv3.HttpInspector{}),
							},
						},
						{
							Name: "envoy.filters.listener.original_dst",
							ConfigType: &listenerv3.ListenerFilter_TypedConfig{
								TypedConfig: mustMarshalAny(&original_dstv3.OriginalDst{}),
							},
						},
					},
					FilterChains: []*listenerv3.FilterChain{
						{
							FilterChainMatch: &listenerv3.FilterChainMatch{
								TransportProtocol: "tls",
							},
							Filters: []*listenerv3.Filter{{
								Name: "envoy.filters.network.tcp_proxy",
								ConfigType: &listenerv3.Filter_TypedConfig{
									TypedConfig: mustMarshalAny(&tcp_proxyv3.TcpProxy{
										StatPrefix: "tls_proxy",
										ClusterSpecifier: &tcp_proxyv3.TcpProxy_Cluster{
											Cluster: "passthrough",
										},
										AccessLog: []*accesslogv3.AccessLog{{
											Name: "envoy.access_loggers.tcp_grpc",
											ConfigType: &accesslogv3.AccessLog_TypedConfig{
												TypedConfig: mustMarshalAny(&grpcv3.TcpGrpcAccessLogConfig{
													CommonConfig: &grpcv3.CommonGrpcAccessLogConfig{
														LogName: "tls_proxy",
														GrpcService: &corev3.GrpcService{
															TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
																EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
																	ClusterName: "accesslog",
																},
															},
														},
														TransportApiVersion: corev3.ApiVersion_V3,
													},
												}),
											},
										}},
									}),
								},
							}},
						},
						{
							FilterChainMatch: &listenerv3.FilterChainMatch{
								ApplicationProtocols: []string{"http/1.0", "http/1.1"},
							},
							Filters: []*listenerv3.Filter{{
								Name: "envoy.filters.network.http_connection_manager",
								ConfigType: &listenerv3.Filter_TypedConfig{
									TypedConfig: mustMarshalAny(&http_connection_managerv3.HttpConnectionManager{
										StatPrefix: "http_proxy",
										HttpFilters: []*http_connection_managerv3.HttpFilter{{
											Name: "envoy.filters.http.router",
											ConfigType: &http_connection_managerv3.HttpFilter_TypedConfig{
												TypedConfig: mustMarshalAny(&routerv3.Router{}),
											},
										}},
										RouteSpecifier: &http_connection_managerv3.HttpConnectionManager_RouteConfig{
											RouteConfig: &routev3.RouteConfiguration{
												Name: "http_proxy",
												VirtualHosts: []*routev3.VirtualHost{{
													Name:    "http_proxy",
													Domains: []string{"*"},
													Routes: []*routev3.Route{{
														Match: &routev3.RouteMatch{
															PathSpecifier: &routev3.RouteMatch_Prefix{
																Prefix: "/",
															},
														},
														Action: &routev3.Route_Route{
															Route: &routev3.RouteAction{
																ClusterSpecifier: &routev3.RouteAction_Cluster{
																	Cluster: "passthrough",
																},
															},
														},
													}},
												}},
											},
										},
										AccessLog: []*accesslogv3.AccessLog{{
											Name: "envoy.access_loggers.http_grpc",
											ConfigType: &accesslogv3.AccessLog_TypedConfig{
												TypedConfig: mustMarshalAny(&grpcv3.HttpGrpcAccessLogConfig{
													CommonConfig: &grpcv3.CommonGrpcAccessLogConfig{
														LogName: "http_proxy",
														GrpcService: &corev3.GrpcService{
															TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
																EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
																	ClusterName: "accesslog",
																},
															},
														},
														TransportApiVersion: corev3.ApiVersion_V3,
													},
												}),
											},
										}},
									}),
								},
							}},
						},
					},
					DefaultFilterChain: &listenerv3.FilterChain{
						Filters: []*listenerv3.Filter{{
							Name: "envoy.filters.network.tcp_proxy",
							ConfigType: &listenerv3.Filter_TypedConfig{
								TypedConfig: mustMarshalAny(&tcp_proxyv3.TcpProxy{
									StatPrefix: "tcp_proxy",
									ClusterSpecifier: &tcp_proxyv3.TcpProxy_Cluster{
										Cluster: "passthrough",
									},
									AccessLog: []*accesslogv3.AccessLog{{
										Name: "envoy.access_loggers.tcp_grpc",
										ConfigType: &accesslogv3.AccessLog_TypedConfig{
											TypedConfig: mustMarshalAny(&grpcv3.TcpGrpcAccessLogConfig{
												CommonConfig: &grpcv3.CommonGrpcAccessLogConfig{
													LogName: "tcp_proxy",
													GrpcService: &corev3.GrpcService{
														TargetSpecifier: &corev3.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &corev3.GrpcService_EnvoyGrpc{
																ClusterName: "accesslog",
															},
														},
													},
													TransportApiVersion: corev3.ApiVersion_V3,
												},
											}),
										},
									}},
								}),
							},
						}},
					},
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if err = ss.Consistent(); err != nil {
		return nil, err
	}
	return ss, nil
}

func mustMarshalAny(pb proto.Message) *anypb.Any {
	m, err := anypb.New(pb)
	if err != nil {
		panic(err)
	}
	return m
}
