// Code generated by protoc-gen-go. DO NOT EDIT.
// source: network.proto

package network

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

// A `PeerInfo` represents the network address(es) of a Peer at some epoch.
type PeerInfo struct {
	// Addresses this peer can be reached at.
	// An address is a byte array in the
	// [multiaddr](https://multiformats.io/multiaddr/) format.
	Addrs [][]byte `protobuf:"bytes,1,rep,name=addrs,proto3" json:"addrs,omitempty"`
	// Monotonically increasing incarnation number. This is usually a timestamp.
	Epoch                uint64   `protobuf:"varint,2,opt,name=epoch,proto3" json:"epoch,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PeerInfo) Reset()         { *m = PeerInfo{} }
func (m *PeerInfo) String() string { return proto.CompactTextString(m) }
func (*PeerInfo) ProtoMessage()    {}
func (*PeerInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{0}
}

func (m *PeerInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PeerInfo.Unmarshal(m, b)
}
func (m *PeerInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PeerInfo.Marshal(b, m, deterministic)
}
func (m *PeerInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PeerInfo.Merge(m, src)
}
func (m *PeerInfo) XXX_Size() int {
	return xxx_messageInfo_PeerInfo.Size(m)
}
func (m *PeerInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_PeerInfo.DiscardUnknown(m)
}

var xxx_messageInfo_PeerInfo proto.InternalMessageInfo

func (m *PeerInfo) GetAddrs() [][]byte {
	if m != nil {
		return m.Addrs
	}
	return nil
}

func (m *PeerInfo) GetEpoch() uint64 {
	if m != nil {
		return m.Epoch
	}
	return 0
}

// A `Note` represents a signed PeerInfo. The signature should be of the peer
// whose info is being sent.
type Note struct {
	// Id of the peer.
	PeerId []byte `protobuf:"bytes,1,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	// Serialized PeerInfo.
	PeerInfo []byte `protobuf:"bytes,2,opt,name=peer_info,json=peerInfo,proto3" json:"peer_info,omitempty"`
	// Each peer signs its serialized PeerInfo and includes both the PeerInfo and
	// the sign in a note it sends to another peer.
	Signature            []byte   `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Note) Reset()         { *m = Note{} }
func (m *Note) String() string { return proto.CompactTextString(m) }
func (*Note) ProtoMessage()    {}
func (*Note) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{1}
}

func (m *Note) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Note.Unmarshal(m, b)
}
func (m *Note) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Note.Marshal(b, m, deterministic)
}
func (m *Note) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Note.Merge(m, src)
}
func (m *Note) XXX_Size() int {
	return xxx_messageInfo_Note.Size(m)
}
func (m *Note) XXX_DiscardUnknown() {
	xxx_messageInfo_Note.DiscardUnknown(m)
}

var xxx_messageInfo_Note proto.InternalMessageInfo

func (m *Note) GetPeerId() []byte {
	if m != nil {
		return m.PeerId
	}
	return nil
}

func (m *Note) GetPeerInfo() []byte {
	if m != nil {
		return m.PeerInfo
	}
	return nil
}

func (m *Note) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

// Discovery message exchanged as part of the discovery protocol.
// The discovery message sent by a peer consists of notes for all the peers the
// sending peer knows about.
type DiscoveryMsg struct {
	Notes                []*Note  `protobuf:"bytes,1,rep,name=notes,proto3" json:"notes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DiscoveryMsg) Reset()         { *m = DiscoveryMsg{} }
func (m *DiscoveryMsg) String() string { return proto.CompactTextString(m) }
func (*DiscoveryMsg) ProtoMessage()    {}
func (*DiscoveryMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{2}
}

func (m *DiscoveryMsg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DiscoveryMsg.Unmarshal(m, b)
}
func (m *DiscoveryMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DiscoveryMsg.Marshal(b, m, deterministic)
}
func (m *DiscoveryMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DiscoveryMsg.Merge(m, src)
}
func (m *DiscoveryMsg) XXX_Size() int {
	return xxx_messageInfo_DiscoveryMsg.Size(m)
}
func (m *DiscoveryMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_DiscoveryMsg.DiscardUnknown(m)
}

var xxx_messageInfo_DiscoveryMsg proto.InternalMessageInfo

func (m *DiscoveryMsg) GetNotes() []*Note {
	if m != nil {
		return m.Notes
	}
	return nil
}

// Identity message exchanged as part of the Identity protocol.
type IdentityMsg struct {
	PeerId               []byte   `protobuf:"bytes,1,opt,name=peer_id,json=peerId,proto3" json:"peer_id,omitempty"`
	SupportedProtocols   [][]byte `protobuf:"bytes,2,rep,name=supported_protocols,json=supportedProtocols,proto3" json:"supported_protocols,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IdentityMsg) Reset()         { *m = IdentityMsg{} }
func (m *IdentityMsg) String() string { return proto.CompactTextString(m) }
func (*IdentityMsg) ProtoMessage()    {}
func (*IdentityMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{3}
}

func (m *IdentityMsg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IdentityMsg.Unmarshal(m, b)
}
func (m *IdentityMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IdentityMsg.Marshal(b, m, deterministic)
}
func (m *IdentityMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IdentityMsg.Merge(m, src)
}
func (m *IdentityMsg) XXX_Size() int {
	return xxx_messageInfo_IdentityMsg.Size(m)
}
func (m *IdentityMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_IdentityMsg.DiscardUnknown(m)
}

var xxx_messageInfo_IdentityMsg proto.InternalMessageInfo

func (m *IdentityMsg) GetPeerId() []byte {
	if m != nil {
		return m.PeerId
	}
	return nil
}

func (m *IdentityMsg) GetSupportedProtocols() [][]byte {
	if m != nil {
		return m.SupportedProtocols
	}
	return nil
}

// Ping message sent as liveness probe.
type Ping struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ping) Reset()         { *m = Ping{} }
func (m *Ping) String() string { return proto.CompactTextString(m) }
func (*Ping) ProtoMessage()    {}
func (*Ping) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{4}
}

func (m *Ping) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ping.Unmarshal(m, b)
}
func (m *Ping) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ping.Marshal(b, m, deterministic)
}
func (m *Ping) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ping.Merge(m, src)
}
func (m *Ping) XXX_Size() int {
	return xxx_messageInfo_Ping.Size(m)
}
func (m *Ping) XXX_DiscardUnknown() {
	xxx_messageInfo_Ping.DiscardUnknown(m)
}

var xxx_messageInfo_Ping proto.InternalMessageInfo

// Pong message sent as response to liveness probe.
type Pong struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Pong) Reset()         { *m = Pong{} }
func (m *Pong) String() string { return proto.CompactTextString(m) }
func (*Pong) ProtoMessage()    {}
func (*Pong) Descriptor() ([]byte, []int) {
	return fileDescriptor_8571034d60397816, []int{5}
}

func (m *Pong) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Pong.Unmarshal(m, b)
}
func (m *Pong) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Pong.Marshal(b, m, deterministic)
}
func (m *Pong) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Pong.Merge(m, src)
}
func (m *Pong) XXX_Size() int {
	return xxx_messageInfo_Pong.Size(m)
}
func (m *Pong) XXX_DiscardUnknown() {
	xxx_messageInfo_Pong.DiscardUnknown(m)
}

var xxx_messageInfo_Pong proto.InternalMessageInfo

func init() {
	proto.RegisterType((*PeerInfo)(nil), "network.PeerInfo")
	proto.RegisterType((*Note)(nil), "network.Note")
	proto.RegisterType((*DiscoveryMsg)(nil), "network.DiscoveryMsg")
	proto.RegisterType((*IdentityMsg)(nil), "network.IdentityMsg")
	proto.RegisterType((*Ping)(nil), "network.Ping")
	proto.RegisterType((*Pong)(nil), "network.Pong")
}

func init() { proto.RegisterFile("network.proto", fileDescriptor_8571034d60397816) }

var fileDescriptor_8571034d60397816 = []byte{
	// 244 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0x41, 0x4b, 0xc3, 0x30,
	0x14, 0xc7, 0xe9, 0xd6, 0x75, 0xdb, 0x5b, 0x77, 0x89, 0x82, 0x01, 0x3d, 0x94, 0x78, 0xe9, 0x69,
	0x82, 0x03, 0x3f, 0x81, 0x97, 0x1e, 0x94, 0x92, 0x8b, 0xe0, 0x65, 0xcc, 0xe6, 0xad, 0x06, 0x25,
	0x2f, 0x24, 0xa9, 0xe2, 0xb7, 0x97, 0x26, 0x56, 0x4f, 0x9e, 0xc2, 0xef, 0xfd, 0xf8, 0x93, 0xff,
	0x7b, 0xb0, 0x35, 0x18, 0x3e, 0xc9, 0xbd, 0xed, 0xac, 0xa3, 0x40, 0x6c, 0xf9, 0x83, 0xe2, 0x0e,
	0x56, 0x2d, 0xa2, 0x6b, 0xcc, 0x89, 0xd8, 0x39, 0x2c, 0x8e, 0x4a, 0x39, 0xcf, 0xb3, 0x6a, 0x5e,
	0x97, 0x32, 0xc1, 0x38, 0x45, 0x4b, 0xdd, 0x2b, 0x9f, 0x55, 0x59, 0x9d, 0xcb, 0x04, 0xe2, 0x19,
	0xf2, 0x47, 0x0a, 0xc8, 0x2e, 0x60, 0x69, 0x11, 0xdd, 0x41, 0x2b, 0x9e, 0x55, 0x59, 0x5d, 0xca,
	0x62, 0xc4, 0x46, 0xb1, 0x4b, 0x58, 0x27, 0x61, 0x4e, 0x14, 0xa3, 0xa5, 0x5c, 0xd9, 0xe9, 0xa7,
	0x2b, 0x58, 0x7b, 0xdd, 0x9b, 0x63, 0x18, 0x1c, 0xf2, 0x79, 0x94, 0x7f, 0x03, 0xb1, 0x87, 0xf2,
	0x5e, 0xfb, 0x8e, 0x3e, 0xd0, 0x7d, 0x3d, 0xf8, 0x9e, 0x5d, 0xc3, 0xc2, 0x50, 0xc0, 0xd4, 0x6b,
	0x73, 0xbb, 0xdd, 0x4d, 0xbb, 0x8c, 0x0d, 0x64, 0x72, 0xe2, 0x09, 0x36, 0x8d, 0x42, 0x13, 0x74,
	0x88, 0x99, 0x7f, 0x7b, 0xdd, 0xc0, 0x99, 0x1f, 0xac, 0x25, 0x17, 0x50, 0x1d, 0xe2, 0x31, 0x3a,
	0x7a, 0xf7, 0x7c, 0x16, 0x57, 0x66, 0xbf, 0xaa, 0x9d, 0x8c, 0x28, 0x20, 0x6f, 0xb5, 0xe9, 0xe3,
	0x4b, 0xa6, 0x7f, 0x29, 0x62, 0x68, 0xff, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x1a, 0x7f, 0xa1, 0xc6,
	0x52, 0x01, 0x00, 0x00,
}