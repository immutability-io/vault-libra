// Code generated by protoc-gen-go. DO NOT EDIT.
// source: secret_service.proto

package secret_service

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ErrorCode int32

const (
	ErrorCode_Success              ErrorCode = 0
	ErrorCode_KeyIdNotFound        ErrorCode = 1
	ErrorCode_WrongLength          ErrorCode = 2
	ErrorCode_InvalidParameters    ErrorCode = 3
	ErrorCode_AuthenticationFailed ErrorCode = 4
	ErrorCode_Unspecified          ErrorCode = 5
)

var ErrorCode_name = map[int32]string{
	0: "Success",
	1: "KeyIdNotFound",
	2: "WrongLength",
	3: "InvalidParameters",
	4: "AuthenticationFailed",
	5: "Unspecified",
}

var ErrorCode_value = map[string]int32{
	"Success":              0,
	"KeyIdNotFound":        1,
	"WrongLength":          2,
	"InvalidParameters":    3,
	"AuthenticationFailed": 4,
	"Unspecified":          5,
}

func (x ErrorCode) String() string {
	return proto.EnumName(ErrorCode_name, int32(x))
}

func (ErrorCode) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{0}
}

type KeyType int32

const (
	KeyType_Ed25519  KeyType = 0
	KeyType_BLS12381 KeyType = 1
)

var KeyType_name = map[int32]string{
	0: "Ed25519",
	1: "BLS12381",
}

var KeyType_value = map[string]int32{
	"Ed25519":  0,
	"BLS12381": 1,
}

func (x KeyType) String() string {
	return proto.EnumName(KeyType_name, int32(x))
}

func (KeyType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{1}
}

type GenerateKeyRequest struct {
	// Spec gives a way to generate the key (potentially BIP32 private derivation path here)
	Spec                 KeyType  `protobuf:"varint,1,opt,name=spec,proto3,enum=secret_service.KeyType" json:"spec,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GenerateKeyRequest) Reset()         { *m = GenerateKeyRequest{} }
func (m *GenerateKeyRequest) String() string { return proto.CompactTextString(m) }
func (*GenerateKeyRequest) ProtoMessage()    {}
func (*GenerateKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{0}
}

func (m *GenerateKeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateKeyRequest.Unmarshal(m, b)
}
func (m *GenerateKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateKeyRequest.Marshal(b, m, deterministic)
}
func (m *GenerateKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateKeyRequest.Merge(m, src)
}
func (m *GenerateKeyRequest) XXX_Size() int {
	return xxx_messageInfo_GenerateKeyRequest.Size(m)
}
func (m *GenerateKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateKeyRequest proto.InternalMessageInfo

func (m *GenerateKeyRequest) GetSpec() KeyType {
	if m != nil {
		return m.Spec
	}
	return KeyType_Ed25519
}

type GenerateKeyResponse struct {
	KeyId                []byte    `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Code                 ErrorCode `protobuf:"varint,2,opt,name=code,proto3,enum=secret_service.ErrorCode" json:"code,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *GenerateKeyResponse) Reset()         { *m = GenerateKeyResponse{} }
func (m *GenerateKeyResponse) String() string { return proto.CompactTextString(m) }
func (*GenerateKeyResponse) ProtoMessage()    {}
func (*GenerateKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{1}
}

func (m *GenerateKeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GenerateKeyResponse.Unmarshal(m, b)
}
func (m *GenerateKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GenerateKeyResponse.Marshal(b, m, deterministic)
}
func (m *GenerateKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenerateKeyResponse.Merge(m, src)
}
func (m *GenerateKeyResponse) XXX_Size() int {
	return xxx_messageInfo_GenerateKeyResponse.Size(m)
}
func (m *GenerateKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GenerateKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GenerateKeyResponse proto.InternalMessageInfo

func (m *GenerateKeyResponse) GetKeyId() []byte {
	if m != nil {
		return m.KeyId
	}
	return nil
}

func (m *GenerateKeyResponse) GetCode() ErrorCode {
	if m != nil {
		return m.Code
	}
	return ErrorCode_Success
}

type PublicKeyRequest struct {
	KeyId                []byte   `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PublicKeyRequest) Reset()         { *m = PublicKeyRequest{} }
func (m *PublicKeyRequest) String() string { return proto.CompactTextString(m) }
func (*PublicKeyRequest) ProtoMessage()    {}
func (*PublicKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{2}
}

func (m *PublicKeyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicKeyRequest.Unmarshal(m, b)
}
func (m *PublicKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicKeyRequest.Marshal(b, m, deterministic)
}
func (m *PublicKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKeyRequest.Merge(m, src)
}
func (m *PublicKeyRequest) XXX_Size() int {
	return xxx_messageInfo_PublicKeyRequest.Size(m)
}
func (m *PublicKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKeyRequest proto.InternalMessageInfo

func (m *PublicKeyRequest) GetKeyId() []byte {
	if m != nil {
		return m.KeyId
	}
	return nil
}

type PublicKeyResponse struct {
	PublicKey            []byte    `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	Code                 ErrorCode `protobuf:"varint,2,opt,name=code,proto3,enum=secret_service.ErrorCode" json:"code,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *PublicKeyResponse) Reset()         { *m = PublicKeyResponse{} }
func (m *PublicKeyResponse) String() string { return proto.CompactTextString(m) }
func (*PublicKeyResponse) ProtoMessage()    {}
func (*PublicKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{3}
}

func (m *PublicKeyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PublicKeyResponse.Unmarshal(m, b)
}
func (m *PublicKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PublicKeyResponse.Marshal(b, m, deterministic)
}
func (m *PublicKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PublicKeyResponse.Merge(m, src)
}
func (m *PublicKeyResponse) XXX_Size() int {
	return xxx_messageInfo_PublicKeyResponse.Size(m)
}
func (m *PublicKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PublicKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PublicKeyResponse proto.InternalMessageInfo

func (m *PublicKeyResponse) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *PublicKeyResponse) GetCode() ErrorCode {
	if m != nil {
		return m.Code
	}
	return ErrorCode_Success
}

type SignRequest struct {
	KeyId []byte `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// message_hash should be a prehashed message of length crypto::HashValue::LENGTH = 32 bytes
	MessageHash          []byte   `protobuf:"bytes,2,opt,name=message_hash,json=messageHash,proto3" json:"message_hash,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignRequest) Reset()         { *m = SignRequest{} }
func (m *SignRequest) String() string { return proto.CompactTextString(m) }
func (*SignRequest) ProtoMessage()    {}
func (*SignRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{4}
}

func (m *SignRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignRequest.Unmarshal(m, b)
}
func (m *SignRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignRequest.Marshal(b, m, deterministic)
}
func (m *SignRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignRequest.Merge(m, src)
}
func (m *SignRequest) XXX_Size() int {
	return xxx_messageInfo_SignRequest.Size(m)
}
func (m *SignRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SignRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SignRequest proto.InternalMessageInfo

func (m *SignRequest) GetKeyId() []byte {
	if m != nil {
		return m.KeyId
	}
	return nil
}

func (m *SignRequest) GetMessageHash() []byte {
	if m != nil {
		return m.MessageHash
	}
	return nil
}

type SignResponse struct {
	Signature            []byte    `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	Code                 ErrorCode `protobuf:"varint,2,opt,name=code,proto3,enum=secret_service.ErrorCode" json:"code,omitempty"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *SignResponse) Reset()         { *m = SignResponse{} }
func (m *SignResponse) String() string { return proto.CompactTextString(m) }
func (*SignResponse) ProtoMessage()    {}
func (*SignResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d77f0ab6512386d, []int{5}
}

func (m *SignResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignResponse.Unmarshal(m, b)
}
func (m *SignResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignResponse.Marshal(b, m, deterministic)
}
func (m *SignResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignResponse.Merge(m, src)
}
func (m *SignResponse) XXX_Size() int {
	return xxx_messageInfo_SignResponse.Size(m)
}
func (m *SignResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignResponse proto.InternalMessageInfo

func (m *SignResponse) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *SignResponse) GetCode() ErrorCode {
	if m != nil {
		return m.Code
	}
	return ErrorCode_Success
}

func init() {
	proto.RegisterEnum("secret_service.ErrorCode", ErrorCode_name, ErrorCode_value)
	proto.RegisterEnum("secret_service.KeyType", KeyType_name, KeyType_value)
	proto.RegisterType((*GenerateKeyRequest)(nil), "secret_service.GenerateKeyRequest")
	proto.RegisterType((*GenerateKeyResponse)(nil), "secret_service.GenerateKeyResponse")
	proto.RegisterType((*PublicKeyRequest)(nil), "secret_service.PublicKeyRequest")
	proto.RegisterType((*PublicKeyResponse)(nil), "secret_service.PublicKeyResponse")
	proto.RegisterType((*SignRequest)(nil), "secret_service.SignRequest")
	proto.RegisterType((*SignResponse)(nil), "secret_service.SignResponse")
}

func init() { proto.RegisterFile("secret_service.proto", fileDescriptor_2d77f0ab6512386d) }

var fileDescriptor_2d77f0ab6512386d = []byte{
	// 458 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0xc1, 0x6f, 0xd3, 0x30,
	0x18, 0xc5, 0xdb, 0xd2, 0x6d, 0xf4, 0x4b, 0x36, 0x5c, 0xb3, 0x89, 0x52, 0x86, 0xb4, 0x05, 0x0e,
	0x30, 0xc4, 0xa4, 0x76, 0x9a, 0x04, 0xc7, 0x31, 0x6d, 0x65, 0xea, 0x84, 0xa6, 0x84, 0x09, 0xa4,
	0x1d, 0x2a, 0x2f, 0xfe, 0x48, 0xac, 0x76, 0x76, 0xb0, 0x9d, 0x49, 0xb9, 0x70, 0xe3, 0xff, 0x46,
	0x49, 0xd3, 0xaa, 0x0b, 0x53, 0xa5, 0x5e, 0x9f, 0x9f, 0x7f, 0x7e, 0x9f, 0xfd, 0x0c, 0xdb, 0x06,
	0x43, 0x8d, 0x76, 0x64, 0x50, 0xdf, 0x8b, 0x10, 0x0f, 0x13, 0xad, 0xac, 0xa2, 0x5b, 0x0f, 0x55,
	0xef, 0x04, 0xe8, 0x00, 0x25, 0x6a, 0x66, 0x71, 0x88, 0x99, 0x8f, 0xbf, 0x53, 0x34, 0x96, 0x7e,
	0x80, 0xa6, 0x49, 0x30, 0xec, 0xd4, 0xf7, 0xea, 0xef, 0xb6, 0xfa, 0x2f, 0x0e, 0x2b, 0xa8, 0x21,
	0x66, 0xdf, 0xb3, 0x04, 0xfd, 0xc2, 0xe4, 0xdd, 0xc0, 0xf3, 0x07, 0x08, 0x93, 0x28, 0x69, 0x90,
	0xee, 0xc0, 0xfa, 0x18, 0xb3, 0x91, 0xe0, 0x05, 0xc5, 0xf5, 0xd7, 0xc6, 0x98, 0x5d, 0x70, 0xfa,
	0x11, 0x9a, 0xa1, 0xe2, 0xd8, 0x69, 0x14, 0xe8, 0x97, 0x55, 0xf4, 0x99, 0xd6, 0x4a, 0x9f, 0x2a,
	0x8e, 0x7e, 0x61, 0xf3, 0xde, 0x03, 0xb9, 0x4a, 0x6f, 0x27, 0x22, 0x5c, 0x48, 0xf7, 0x38, 0xd9,
	0x63, 0xd0, 0x5e, 0xb0, 0x96, 0x29, 0x5e, 0x03, 0x24, 0x85, 0x38, 0x1a, 0x63, 0x56, 0xfa, 0x5b,
	0xc9, 0xcc, 0xb6, 0x6a, 0x9a, 0x01, 0x38, 0x81, 0x88, 0xe4, 0xf2, 0x20, 0x74, 0x1f, 0xdc, 0x3b,
	0x34, 0x86, 0x45, 0x38, 0x8a, 0x99, 0x89, 0x0b, 0xb8, 0xeb, 0x3b, 0xa5, 0xf6, 0x95, 0x99, 0xd8,
	0xbb, 0x01, 0x77, 0x0a, 0x2a, 0x63, 0xee, 0x42, 0xcb, 0x88, 0x48, 0x32, 0x9b, 0x6a, 0x9c, 0xa5,
	0x9c, 0x0b, 0x2b, 0xa6, 0x3c, 0xf8, 0x03, 0xad, 0xb9, 0x44, 0x1d, 0xd8, 0x08, 0xd2, 0x30, 0x44,
	0x63, 0x48, 0x8d, 0xb6, 0x61, 0x73, 0x98, 0x47, 0xfc, 0xa6, 0xec, 0xb9, 0x4a, 0x25, 0x27, 0x75,
	0xfa, 0x0c, 0x9c, 0x1f, 0x5a, 0xc9, 0xe8, 0x12, 0x65, 0x64, 0x63, 0xd2, 0xa0, 0x3b, 0xd0, 0xbe,
	0x90, 0xf7, 0x6c, 0x22, 0xf8, 0x15, 0xd3, 0xec, 0x0e, 0x2d, 0x6a, 0x43, 0x9e, 0xd0, 0x0e, 0x6c,
	0x9f, 0xa4, 0x36, 0x46, 0x69, 0x45, 0xc8, 0xac, 0x50, 0xf2, 0x9c, 0x89, 0x09, 0x72, 0xd2, 0xcc,
	0x09, 0xd7, 0x32, 0x6f, 0x82, 0xf8, 0x25, 0x90, 0x93, 0xb5, 0x83, 0xb7, 0xb0, 0x51, 0x36, 0x24,
	0x3f, 0xfd, 0x8c, 0xf7, 0x8f, 0x8f, 0x7b, 0x9f, 0x49, 0x8d, 0xba, 0xf0, 0xf4, 0xcb, 0x65, 0xd0,
	0xeb, 0x1f, 0x7d, 0xea, 0x91, 0x7a, 0xff, 0x6f, 0x03, 0x36, 0x83, 0x62, 0x90, 0x60, 0x3a, 0x07,
	0xfd, 0x09, 0xce, 0x42, 0x91, 0xa8, 0x57, 0x9d, 0xf3, 0xff, 0xa2, 0x76, 0xdf, 0x2c, 0xf5, 0x4c,
	0x2f, 0xd7, 0xab, 0xd1, 0x6b, 0x70, 0x07, 0x68, 0xe7, 0xed, 0xa0, 0x7b, 0xd5, 0x6d, 0xd5, 0x8e,
	0x75, 0xf7, 0x97, 0x38, 0xe6, 0xd8, 0x53, 0x68, 0xe6, 0xaf, 0x48, 0x5f, 0x55, 0xcd, 0x0b, 0x25,
	0xe9, 0xee, 0x3e, 0xbe, 0x38, 0x83, 0xdc, 0xae, 0x17, 0x1f, 0xf3, 0xe8, 0x5f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xd4, 0xe6, 0x35, 0x8e, 0xb0, 0x03, 0x00, 0x00,
}
