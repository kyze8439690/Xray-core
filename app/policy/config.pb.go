// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.0
// source: app/policy/config.proto

package policy

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

type Second struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Value uint32 `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *Second) Reset() {
	*x = Second{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_policy_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Second) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Second) ProtoMessage() {}

func (x *Second) ProtoReflect() protoreflect.Message {
	mi := &file_app_policy_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Second.ProtoReflect.Descriptor instead.
func (*Second) Descriptor() ([]byte, []int) {
	return file_app_policy_config_proto_rawDescGZIP(), []int{0}
}

func (x *Second) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

type Policy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Timeout *Policy_Timeout `protobuf:"bytes,1,opt,name=timeout,proto3" json:"timeout,omitempty"`
	Buffer  *Policy_Buffer  `protobuf:"bytes,3,opt,name=buffer,proto3" json:"buffer,omitempty"`
}

func (x *Policy) Reset() {
	*x = Policy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_policy_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy) ProtoMessage() {}

func (x *Policy) ProtoReflect() protoreflect.Message {
	mi := &file_app_policy_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy.ProtoReflect.Descriptor instead.
func (*Policy) Descriptor() ([]byte, []int) {
	return file_app_policy_config_proto_rawDescGZIP(), []int{1}
}

func (x *Policy) GetTimeout() *Policy_Timeout {
	if x != nil {
		return x.Timeout
	}
	return nil
}

func (x *Policy) GetBuffer() *Policy_Buffer {
	if x != nil {
		return x.Buffer
	}
	return nil
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Level map[uint32]*Policy `protobuf:"bytes,1,rep,name=level,proto3" json:"level,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_policy_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_app_policy_config_proto_msgTypes[2]
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
	return file_app_policy_config_proto_rawDescGZIP(), []int{2}
}

func (x *Config) GetLevel() map[uint32]*Policy {
	if x != nil {
		return x.Level
	}
	return nil
}

// Timeout is a message for timeout settings in various stages, in seconds.
type Policy_Timeout struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Handshake      *Second `protobuf:"bytes,1,opt,name=handshake,proto3" json:"handshake,omitempty"`
	ConnectionIdle *Second `protobuf:"bytes,2,opt,name=connection_idle,json=connectionIdle,proto3" json:"connection_idle,omitempty"`
	UplinkOnly     *Second `protobuf:"bytes,3,opt,name=uplink_only,json=uplinkOnly,proto3" json:"uplink_only,omitempty"`
	DownlinkOnly   *Second `protobuf:"bytes,4,opt,name=downlink_only,json=downlinkOnly,proto3" json:"downlink_only,omitempty"`
}

func (x *Policy_Timeout) Reset() {
	*x = Policy_Timeout{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_policy_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy_Timeout) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy_Timeout) ProtoMessage() {}

func (x *Policy_Timeout) ProtoReflect() protoreflect.Message {
	mi := &file_app_policy_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy_Timeout.ProtoReflect.Descriptor instead.
func (*Policy_Timeout) Descriptor() ([]byte, []int) {
	return file_app_policy_config_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Policy_Timeout) GetHandshake() *Second {
	if x != nil {
		return x.Handshake
	}
	return nil
}

func (x *Policy_Timeout) GetConnectionIdle() *Second {
	if x != nil {
		return x.ConnectionIdle
	}
	return nil
}

func (x *Policy_Timeout) GetUplinkOnly() *Second {
	if x != nil {
		return x.UplinkOnly
	}
	return nil
}

func (x *Policy_Timeout) GetDownlinkOnly() *Second {
	if x != nil {
		return x.DownlinkOnly
	}
	return nil
}

type Policy_Buffer struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Buffer size per connection, in bytes. -1 for unlimited buffer.
	Connection int32 `protobuf:"varint,1,opt,name=connection,proto3" json:"connection,omitempty"`
}

func (x *Policy_Buffer) Reset() {
	*x = Policy_Buffer{}
	if protoimpl.UnsafeEnabled {
		mi := &file_app_policy_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Policy_Buffer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Policy_Buffer) ProtoMessage() {}

func (x *Policy_Buffer) ProtoReflect() protoreflect.Message {
	mi := &file_app_policy_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Policy_Buffer.ProtoReflect.Descriptor instead.
func (*Policy_Buffer) Descriptor() ([]byte, []int) {
	return file_app_policy_config_proto_rawDescGZIP(), []int{1, 1}
}

func (x *Policy_Buffer) GetConnection() int32 {
	if x != nil {
		return x.Connection
	}
	return 0
}

var File_app_policy_config_proto protoreflect.FileDescriptor

var file_app_policy_config_proto_rawDesc = []byte{
	0x0a, 0x17, 0x61, 0x70, 0x70, 0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0f, 0x78, 0x72, 0x61, 0x79, 0x2e,
	0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22, 0x1e, 0x0a, 0x06, 0x53, 0x65,
	0x63, 0x6f, 0x6e, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0xa2, 0x03, 0x0a, 0x06, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x39, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70,
	0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x12, 0x36, 0x0a, 0x06, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1e, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72,
	0x52, 0x06, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x1a, 0xfa, 0x01, 0x0a, 0x07, 0x54, 0x69, 0x6d,
	0x65, 0x6f, 0x75, 0x74, 0x12, 0x35, 0x0a, 0x09, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b,
	0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61,
	0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64,
	0x52, 0x09, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65, 0x12, 0x40, 0x0a, 0x0f, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x6c, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e,
	0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x52, 0x0e, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x6c, 0x65, 0x12, 0x38, 0x0a,
	0x0b, 0x75, 0x70, 0x6c, 0x69, 0x6e, 0x6b, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x17, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x2e, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x52, 0x0a, 0x75, 0x70, 0x6c,
	0x69, 0x6e, 0x6b, 0x4f, 0x6e, 0x6c, 0x79, 0x12, 0x3c, 0x0a, 0x0d, 0x64, 0x6f, 0x77, 0x6e, 0x6c,
	0x69, 0x6e, 0x6b, 0x5f, 0x6f, 0x6e, 0x6c, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x2e, 0x53, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x52, 0x0c, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x69, 0x6e,
	0x6b, 0x4f, 0x6e, 0x6c, 0x79, 0x1a, 0x28, 0x0a, 0x06, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x12,
	0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22,
	0x95, 0x01, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x38, 0x0a, 0x05, 0x6c, 0x65,
	0x76, 0x65, 0x6c, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x78, 0x72, 0x61, 0x79,
	0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x1a, 0x51, 0x0a, 0x0a, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x2d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x4f, 0x0a, 0x13, 0x63, 0x6f, 0x6d, 0x2e, 0x78,
	0x72, 0x61, 0x79, 0x2e, 0x61, 0x70, 0x70, 0x2e, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x50, 0x01,
	0x5a, 0x24, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x78, 0x74, 0x6c,
	0x73, 0x2f, 0x78, 0x72, 0x61, 0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x70, 0x70, 0x2f,
	0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0xaa, 0x02, 0x0f, 0x58, 0x72, 0x61, 0x79, 0x2e, 0x41, 0x70,
	0x70, 0x2e, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_app_policy_config_proto_rawDescOnce sync.Once
	file_app_policy_config_proto_rawDescData = file_app_policy_config_proto_rawDesc
)

func file_app_policy_config_proto_rawDescGZIP() []byte {
	file_app_policy_config_proto_rawDescOnce.Do(func() {
		file_app_policy_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_app_policy_config_proto_rawDescData)
	})
	return file_app_policy_config_proto_rawDescData
}

var file_app_policy_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_app_policy_config_proto_goTypes = []interface{}{
	(*Second)(nil),         // 0: xray.app.policy.Second
	(*Policy)(nil),         // 1: xray.app.policy.Policy
	(*Config)(nil),         // 2: xray.app.policy.Config
	(*Policy_Timeout)(nil), // 3: xray.app.policy.Policy.Timeout
	(*Policy_Buffer)(nil),  // 4: xray.app.policy.Policy.Buffer
	nil,                    // 5: xray.app.policy.Config.LevelEntry
}
var file_app_policy_config_proto_depIdxs = []int32{
	3, // 0: xray.app.policy.Policy.timeout:type_name -> xray.app.policy.Policy.Timeout
	4, // 1: xray.app.policy.Policy.buffer:type_name -> xray.app.policy.Policy.Buffer
	5, // 2: xray.app.policy.Config.level:type_name -> xray.app.policy.Config.LevelEntry
	0, // 3: xray.app.policy.Policy.Timeout.handshake:type_name -> xray.app.policy.Second
	0, // 4: xray.app.policy.Policy.Timeout.connection_idle:type_name -> xray.app.policy.Second
	0, // 5: xray.app.policy.Policy.Timeout.uplink_only:type_name -> xray.app.policy.Second
	0, // 6: xray.app.policy.Policy.Timeout.downlink_only:type_name -> xray.app.policy.Second
	1, // 7: xray.app.policy.Config.LevelEntry.value:type_name -> xray.app.policy.Policy
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_app_policy_config_proto_init() }
func file_app_policy_config_proto_init() {
	if File_app_policy_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_app_policy_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Second); i {
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
		file_app_policy_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy); i {
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
		file_app_policy_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
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
		file_app_policy_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy_Timeout); i {
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
		file_app_policy_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Policy_Buffer); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_app_policy_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_app_policy_config_proto_goTypes,
		DependencyIndexes: file_app_policy_config_proto_depIdxs,
		MessageInfos:      file_app_policy_config_proto_msgTypes,
	}.Build()
	File_app_policy_config_proto = out.File
	file_app_policy_config_proto_rawDesc = nil
	file_app_policy_config_proto_goTypes = nil
	file_app_policy_config_proto_depIdxs = nil
}
