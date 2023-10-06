// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.3
// source: app/router/config.proto

package router

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RoutingRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to TargetTag:
	//
	//	*RoutingRule_Tag
	TargetTag  isRoutingRule_TargetTag `protobuf_oneof:"target_tag"`
	InboundTag []string                `protobuf:"bytes,8,rep,name=inbound_tag,json=inboundTag,proto3" json:"inbound_tag,omitempty"`
	Protocol   []string                `protobuf:"bytes,9,rep,name=protocol,proto3" json:"protocol,omitempty"`
}

func (x *RoutingRule) Reset() {
	*x = RoutingRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RoutingRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RoutingRule) ProtoMessage() {}

func (x *RoutingRule) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RoutingRule.ProtoReflect.Descriptor instead.
func (*RoutingRule) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{0}
}

func (m *RoutingRule) GetTargetTag() isRoutingRule_TargetTag {
	if m != nil {
		return m.TargetTag
	}
	return nil
}

func (x *RoutingRule) GetTag() string {
	if x, ok := x.GetTargetTag().(*RoutingRule_Tag); ok {
		return x.Tag
	}
	return ""
}

func (x *RoutingRule) GetInboundTag() []string {
	if x != nil {
		return x.InboundTag
	}
	return nil
}

func (x *RoutingRule) GetProtocol() []string {
	if x != nil {
		return x.Protocol
	}
	return nil
}

type isRoutingRule_TargetTag interface {
	isRoutingRule_TargetTag()
}

type RoutingRule_Tag struct {
	// Tag of outbound that this rule is pointing to.
	Tag string `protobuf:"bytes,1,opt,name=tag,proto3,oneof"`
}

func (*RoutingRule_Tag) isRoutingRule_TargetTag() {}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Rule []*RoutingRule `protobuf:"bytes,2,rep,name=rule,proto3" json:"rule,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_router_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_router_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_app_router_config_proto_rawDescGZIP(), []int{1}
}

func (x *Config) GetRule() []*RoutingRule {
	if x != nil {
		return x.Rule
	}
	return nil
}

var File_app_router_config_proto protoreflect.FileDescriptor

var file_app_router_config_proto_rawDesc = []byte{
	0x0a, 0x17, 0x61, 0x70, 0x70, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x78, 0x72, 0x61, 0x79, 0x2e,
	0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x22, 0x6c, 0x0a, 0x0b, 0x52, 0x6f,
	0x75, 0x74, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x12, 0x0a, 0x03, 0x74, 0x61, 0x67,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x74, 0x61, 0x67, 0x12, 0x1f, 0x0a,
	0x0b, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x74, 0x61, 0x67, 0x18, 0x08, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0a, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x54, 0x61, 0x67, 0x12, 0x1a,
	0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x09, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x42, 0x0c, 0x0a, 0x0a, 0x74, 0x61,
	0x72, 0x67, 0x65, 0x74, 0x5f, 0x74, 0x61, 0x67, 0x22, 0x3a, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x30, 0x0a, 0x04, 0x72, 0x75, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x72, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x04,
	0x72, 0x75, 0x6c, 0x65, 0x42, 0x4f, 0x0a, 0x13, 0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x72, 0x61, 0x79,
	0x2e, 0x61, 0x70, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x50, 0x01, 0x5a, 0x24, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x78, 0x74, 0x6c, 0x73, 0x2f, 0x78,
	0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x70, 0x2f, 0x72, 0x6f, 0x75,
	0x74, 0x65, 0x72, 0xaa, 0x02, 0x0f, 0x58, 0x72, 0x61, 0x79, 0x2e, 0x41, 0x70, 0x70, 0x2e, 0x52,
	0x6f, 0x75, 0x74, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_router_config_proto_rawDescOnce sync.Once
	file_app_router_config_proto_rawDescData = file_app_router_config_proto_rawDesc
)

func file_app_router_config_proto_rawDescGZIP() []byte {
	file_app_router_config_proto_rawDescOnce.Do(func() {
		file_app_router_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_router_config_proto_rawDescData)
	})
	return file_app_router_config_proto_rawDescData
}

var file_app_router_config_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_app_router_config_proto_goTypes = []interface{}{
	(*RoutingRule)(nil), // 0: xray.app.router.RoutingRule
	(*Config)(nil),      // 1: xray.app.router.Config
}
var file_app_router_config_proto_depIdxs = []int32{
	0, // 0: xray.app.router.Config.rule:type_name -> xray.app.router.RoutingRule
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_app_router_config_proto_init() }
func file_app_router_config_proto_init() {
	if File_app_router_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_router_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RoutingRule); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_app_router_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_app_router_config_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*RoutingRule_Tag)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_app_router_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_router_config_proto_goTypes,
		DependencyIndexes: file_app_router_config_proto_depIdxs,
		MessageInfos:      file_app_router_config_proto_msgTypes,
	}.Build()
	File_app_router_config_proto = out.File
	file_app_router_config_proto_rawDesc = nil
	file_app_router_config_proto_goTypes = nil
	file_app_router_config_proto_depIdxs = nil
}
