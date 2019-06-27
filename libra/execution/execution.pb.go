// Code generated by protoc-gen-go. DO NOT EDIT.
// source: execution.proto

package execution

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

type CommitBlockStatus int32

const (
	// The block is persisted.
	CommitBlockStatus_SUCCEEDED CommitBlockStatus = 0
	// Something went wrong.
	CommitBlockStatus_FAILED CommitBlockStatus = 1
)

var CommitBlockStatus_name = map[int32]string{
	0: "SUCCEEDED",
	1: "FAILED",
}

var CommitBlockStatus_value = map[string]int32{
	"SUCCEEDED": 0,
	"FAILED":    1,
}

func (x CommitBlockStatus) String() string {
	return proto.EnumName(CommitBlockStatus_name, int32(x))
}

func (CommitBlockStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{0}
}

type ExecuteBlockRequest struct {
	// The list of transactions from consensus.
	Transactions []*SignedTransaction `protobuf:"bytes,1,rep,name=transactions,proto3" json:"transactions,omitempty"`
	// Id of the parent block.
	// We're going to use a special GENESIS_BLOCK_ID constant defined in
	// crypto::hash module to refer to the block id of the Genesis block, which is
	// executed in a special way.
	ParentBlockId []byte `protobuf:"bytes,2,opt,name=parent_block_id,json=parentBlockId,proto3" json:"parent_block_id,omitempty"`
	// Id of the current block.
	BlockId              []byte   `protobuf:"bytes,3,opt,name=block_id,json=blockId,proto3" json:"block_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExecuteBlockRequest) Reset()         { *m = ExecuteBlockRequest{} }
func (m *ExecuteBlockRequest) String() string { return proto.CompactTextString(m) }
func (*ExecuteBlockRequest) ProtoMessage()    {}
func (*ExecuteBlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{0}
}

func (m *ExecuteBlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExecuteBlockRequest.Unmarshal(m, b)
}
func (m *ExecuteBlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExecuteBlockRequest.Marshal(b, m, deterministic)
}
func (m *ExecuteBlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExecuteBlockRequest.Merge(m, src)
}
func (m *ExecuteBlockRequest) XXX_Size() int {
	return xxx_messageInfo_ExecuteBlockRequest.Size(m)
}
func (m *ExecuteBlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ExecuteBlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ExecuteBlockRequest proto.InternalMessageInfo

func (m *ExecuteBlockRequest) GetTransactions() []*SignedTransaction {
	if m != nil {
		return m.Transactions
	}
	return nil
}

func (m *ExecuteBlockRequest) GetParentBlockId() []byte {
	if m != nil {
		return m.ParentBlockId
	}
	return nil
}

func (m *ExecuteBlockRequest) GetBlockId() []byte {
	if m != nil {
		return m.BlockId
	}
	return nil
}

// Result of transaction execution.
type ExecuteBlockResponse struct {
	// Root hash of the ledger after applying all the transactions in this
	// block.
	RootHash []byte `protobuf:"bytes,1,opt,name=root_hash,json=rootHash,proto3" json:"root_hash,omitempty"`
	// The execution result of the transactions. Each transaction has a status
	// field that indicates whether it should be included in the ledger once the
	// block is committed.
	Status []*VMStatus `protobuf:"bytes,2,rep,name=status,proto3" json:"status,omitempty"`
	// The corresponding ledger version when this block is committed.
	Version uint64 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	// If set, this field designates that if this block is committed, then the
	// next epoch will start immediately with the included set of validators.
	Validators           *ValidatorSet `protobuf:"bytes,4,opt,name=validators,proto3" json:"validators,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ExecuteBlockResponse) Reset()         { *m = ExecuteBlockResponse{} }
func (m *ExecuteBlockResponse) String() string { return proto.CompactTextString(m) }
func (*ExecuteBlockResponse) ProtoMessage()    {}
func (*ExecuteBlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{1}
}

func (m *ExecuteBlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExecuteBlockResponse.Unmarshal(m, b)
}
func (m *ExecuteBlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExecuteBlockResponse.Marshal(b, m, deterministic)
}
func (m *ExecuteBlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExecuteBlockResponse.Merge(m, src)
}
func (m *ExecuteBlockResponse) XXX_Size() int {
	return xxx_messageInfo_ExecuteBlockResponse.Size(m)
}
func (m *ExecuteBlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ExecuteBlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ExecuteBlockResponse proto.InternalMessageInfo

func (m *ExecuteBlockResponse) GetRootHash() []byte {
	if m != nil {
		return m.RootHash
	}
	return nil
}

func (m *ExecuteBlockResponse) GetStatus() []*VMStatus {
	if m != nil {
		return m.Status
	}
	return nil
}

func (m *ExecuteBlockResponse) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *ExecuteBlockResponse) GetValidators() *ValidatorSet {
	if m != nil {
		return m.Validators
	}
	return nil
}

type CommitBlockRequest struct {
	// The ledger info with signatures from 2f+1 validators. It contains the id
	// of the block consensus wants to commit. This will cause the given block
	// and all the uncommitted ancestors to be committed to storage.
	LedgerInfoWithSigs   *LedgerInfoWithSignatures `protobuf:"bytes,1,opt,name=ledger_info_with_sigs,json=ledgerInfoWithSigs,proto3" json:"ledger_info_with_sigs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *CommitBlockRequest) Reset()         { *m = CommitBlockRequest{} }
func (m *CommitBlockRequest) String() string { return proto.CompactTextString(m) }
func (*CommitBlockRequest) ProtoMessage()    {}
func (*CommitBlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{2}
}

func (m *CommitBlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CommitBlockRequest.Unmarshal(m, b)
}
func (m *CommitBlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CommitBlockRequest.Marshal(b, m, deterministic)
}
func (m *CommitBlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommitBlockRequest.Merge(m, src)
}
func (m *CommitBlockRequest) XXX_Size() int {
	return xxx_messageInfo_CommitBlockRequest.Size(m)
}
func (m *CommitBlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CommitBlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CommitBlockRequest proto.InternalMessageInfo

func (m *CommitBlockRequest) GetLedgerInfoWithSigs() *LedgerInfoWithSignatures {
	if m != nil {
		return m.LedgerInfoWithSigs
	}
	return nil
}

type CommitBlockResponse struct {
	Status               CommitBlockStatus `protobuf:"varint,1,opt,name=status,proto3,enum=execution.CommitBlockStatus" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *CommitBlockResponse) Reset()         { *m = CommitBlockResponse{} }
func (m *CommitBlockResponse) String() string { return proto.CompactTextString(m) }
func (*CommitBlockResponse) ProtoMessage()    {}
func (*CommitBlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{3}
}

func (m *CommitBlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CommitBlockResponse.Unmarshal(m, b)
}
func (m *CommitBlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CommitBlockResponse.Marshal(b, m, deterministic)
}
func (m *CommitBlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommitBlockResponse.Merge(m, src)
}
func (m *CommitBlockResponse) XXX_Size() int {
	return xxx_messageInfo_CommitBlockResponse.Size(m)
}
func (m *CommitBlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CommitBlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CommitBlockResponse proto.InternalMessageInfo

func (m *CommitBlockResponse) GetStatus() CommitBlockStatus {
	if m != nil {
		return m.Status
	}
	return CommitBlockStatus_SUCCEEDED
}

// Ask Execution service to execute and commit a chunk of contiguous
// transactions. All the transactions in this chunk should belong to the same
// epoch E. If the caller has a list of transactions that span two epochs, it
// should split the transactions.
type ExecuteChunkRequest struct {
	TxnListWithProof     *TransactionListWithProof `protobuf:"bytes,1,opt,name=txn_list_with_proof,json=txnListWithProof,proto3" json:"txn_list_with_proof,omitempty"`
	LedgerInfoWithSigs   *LedgerInfoWithSignatures `protobuf:"bytes,2,opt,name=ledger_info_with_sigs,json=ledgerInfoWithSigs,proto3" json:"ledger_info_with_sigs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *ExecuteChunkRequest) Reset()         { *m = ExecuteChunkRequest{} }
func (m *ExecuteChunkRequest) String() string { return proto.CompactTextString(m) }
func (*ExecuteChunkRequest) ProtoMessage()    {}
func (*ExecuteChunkRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{4}
}

func (m *ExecuteChunkRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExecuteChunkRequest.Unmarshal(m, b)
}
func (m *ExecuteChunkRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExecuteChunkRequest.Marshal(b, m, deterministic)
}
func (m *ExecuteChunkRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExecuteChunkRequest.Merge(m, src)
}
func (m *ExecuteChunkRequest) XXX_Size() int {
	return xxx_messageInfo_ExecuteChunkRequest.Size(m)
}
func (m *ExecuteChunkRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ExecuteChunkRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ExecuteChunkRequest proto.InternalMessageInfo

func (m *ExecuteChunkRequest) GetTxnListWithProof() *TransactionListWithProof {
	if m != nil {
		return m.TxnListWithProof
	}
	return nil
}

func (m *ExecuteChunkRequest) GetLedgerInfoWithSigs() *LedgerInfoWithSignatures {
	if m != nil {
		return m.LedgerInfoWithSigs
	}
	return nil
}

// Either all transactions are successfully executed and persisted, or nothing
// happens.
type ExecuteChunkResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ExecuteChunkResponse) Reset()         { *m = ExecuteChunkResponse{} }
func (m *ExecuteChunkResponse) String() string { return proto.CompactTextString(m) }
func (*ExecuteChunkResponse) ProtoMessage()    {}
func (*ExecuteChunkResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_776e2c5022e94aef, []int{5}
}

func (m *ExecuteChunkResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ExecuteChunkResponse.Unmarshal(m, b)
}
func (m *ExecuteChunkResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ExecuteChunkResponse.Marshal(b, m, deterministic)
}
func (m *ExecuteChunkResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExecuteChunkResponse.Merge(m, src)
}
func (m *ExecuteChunkResponse) XXX_Size() int {
	return xxx_messageInfo_ExecuteChunkResponse.Size(m)
}
func (m *ExecuteChunkResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ExecuteChunkResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ExecuteChunkResponse proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("execution.CommitBlockStatus", CommitBlockStatus_name, CommitBlockStatus_value)
	proto.RegisterType((*ExecuteBlockRequest)(nil), "execution.ExecuteBlockRequest")
	proto.RegisterType((*ExecuteBlockResponse)(nil), "execution.ExecuteBlockResponse")
	proto.RegisterType((*CommitBlockRequest)(nil), "execution.CommitBlockRequest")
	proto.RegisterType((*CommitBlockResponse)(nil), "execution.CommitBlockResponse")
	proto.RegisterType((*ExecuteChunkRequest)(nil), "execution.ExecuteChunkRequest")
	proto.RegisterType((*ExecuteChunkResponse)(nil), "execution.ExecuteChunkResponse")
}

func init() { proto.RegisterFile("execution.proto", fileDescriptor_776e2c5022e94aef) }

var fileDescriptor_776e2c5022e94aef = []byte{
	// 518 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x94, 0xcf, 0x92, 0xd2, 0x40,
	0x10, 0xc6, 0x09, 0xbb, 0xc5, 0x2e, 0x0d, 0x2b, 0x30, 0xa8, 0x15, 0x51, 0x77, 0xa9, 0x1c, 0x94,
	0xf2, 0xc0, 0x81, 0xf5, 0xe8, 0x45, 0x21, 0x96, 0x94, 0xb8, 0xa5, 0xc1, 0x3f, 0xc7, 0x54, 0x80,
	0x81, 0x4c, 0x09, 0x19, 0x9c, 0x6e, 0x10, 0x8f, 0xbe, 0x84, 0x2f, 0xe1, 0x13, 0xf8, 0x76, 0x56,
	0x26, 0x21, 0x7f, 0x56, 0xb8, 0x78, 0xa4, 0xfb, 0x9b, 0x6f, 0x7e, 0xf3, 0x75, 0x13, 0xa8, 0xf1,
	0x1d, 0x9f, 0x6e, 0x48, 0xc8, 0xa0, 0xbb, 0x56, 0x92, 0x24, 0x2b, 0x27, 0x85, 0x56, 0x63, 0xc9,
	0x67, 0x0b, 0xae, 0x5c, 0x11, 0xcc, 0x65, 0xd4, 0x6d, 0x35, 0x48, 0x79, 0x01, 0x7a, 0xd3, 0xf4,
	0x40, 0xab, 0xb9, 0xf5, 0x96, 0x62, 0xe6, 0x91, 0x54, 0x2e, 0x72, 0x8a, 0x8b, 0xb5, 0xed, 0xca,
	0xe5, 0x4a, 0x49, 0x85, 0x51, 0xc1, 0xfa, 0x65, 0x40, 0xd3, 0xd6, 0xce, 0xfc, 0xd5, 0x52, 0x4e,
	0xbf, 0x3a, 0xfc, 0xdb, 0x86, 0x23, 0xb1, 0x17, 0x50, 0xcd, 0x58, 0xa2, 0x69, 0xb4, 0x4f, 0x3a,
	0x95, 0x9e, 0xd9, 0xa5, 0x1f, 0x6b, 0x8e, 0xdd, 0xb1, 0x58, 0x04, 0x7c, 0xf6, 0x31, 0x15, 0x38,
	0x39, 0x35, 0x7b, 0x02, 0xb5, 0xb5, 0xa7, 0x78, 0x40, 0xee, 0x24, 0x34, 0x75, 0xc5, 0xcc, 0x2c,
	0xb6, 0x8d, 0x4e, 0xd5, 0xb9, 0x88, 0xca, 0xfa, 0xaa, 0xe1, 0x8c, 0x3d, 0x80, 0xf3, 0x44, 0x70,
	0xa2, 0x05, 0x67, 0x93, 0xa8, 0x65, 0xfd, 0x36, 0xe0, 0x6e, 0x1e, 0x0c, 0xd7, 0x32, 0x40, 0xce,
	0x1e, 0x42, 0x59, 0x49, 0x49, 0xae, 0xef, 0xa1, 0x6f, 0x1a, 0xfa, 0xd0, 0x79, 0x58, 0x78, 0xe3,
	0xa1, 0xcf, 0x9e, 0x42, 0x09, 0xc9, 0xa3, 0x0d, 0x9a, 0x45, 0x0d, 0x5c, 0x8b, 0x81, 0x3f, 0xbf,
	0x1b, 0xeb, 0xb2, 0x13, 0xb7, 0x99, 0x09, 0x67, 0x5b, 0xae, 0x50, 0xc8, 0x40, 0x5f, 0x7c, 0xea,
	0xec, 0x7f, 0xb2, 0x6b, 0x80, 0x24, 0x39, 0x34, 0x4f, 0xdb, 0x46, 0xa7, 0xd2, 0x6b, 0xee, 0x6d,
	0xf6, 0x8d, 0x31, 0x27, 0x27, 0x23, 0xb3, 0x7c, 0x60, 0x7d, 0xb9, 0x5a, 0x09, 0xca, 0x85, 0xe8,
	0xc0, 0xbd, 0xcc, 0xa8, 0xdc, 0xef, 0x82, 0x7c, 0x17, 0xc5, 0x02, 0x35, 0x76, 0xa5, 0x77, 0x15,
	0xbb, 0x8e, 0xb4, 0x66, 0x18, 0xcc, 0xe5, 0x17, 0x41, 0x7e, 0x98, 0xad, 0x47, 0x1b, 0xc5, 0xd1,
	0x61, 0xcb, 0xdb, 0x1d, 0xb4, 0xde, 0x42, 0x33, 0x77, 0x53, 0x9c, 0xca, 0xf3, 0xe4, 0xe1, 0xa1,
	0xf7, 0x9d, 0xde, 0xa3, 0x6e, 0xba, 0x40, 0x19, 0x7d, 0x3e, 0x05, 0xeb, 0x4f, 0x3a, 0xfd, 0xbe,
	0xbf, 0x09, 0x12, 0xf0, 0x1b, 0x68, 0xd2, 0x2e, 0x70, 0x97, 0x02, 0x29, 0xa2, 0x5e, 0x2b, 0x29,
	0xe7, 0xb7, 0xb0, 0x33, 0xe3, 0x1f, 0x09, 0xa4, 0x90, 0xf0, 0x7d, 0x28, 0x73, 0xea, 0xb4, 0xcb,
	0x57, 0x8e, 0x07, 0x51, 0xfc, 0xff, 0x20, 0xee, 0x27, 0xfb, 0x11, 0xa3, 0x47, 0x49, 0x3c, 0xeb,
	0x42, 0xe3, 0x9f, 0x07, 0xb3, 0x0b, 0x28, 0x8f, 0x3f, 0xf5, 0xfb, 0xb6, 0x3d, 0xb0, 0x07, 0xf5,
	0x02, 0x03, 0x28, 0xbd, 0x7e, 0x39, 0x1c, 0xd9, 0x83, 0xba, 0xd1, 0xfb, 0x59, 0x84, 0xb2, 0xbd,
	0xcf, 0x8a, 0x7d, 0x80, 0x6a, 0x76, 0xeb, 0xd8, 0x65, 0x26, 0xc7, 0x03, 0xff, 0x93, 0xd6, 0xd5,
	0xd1, 0x7e, 0x84, 0x63, 0x15, 0xd8, 0x0d, 0x54, 0x32, 0x40, 0xec, 0xf1, 0xe1, 0xc9, 0xec, 0x0d,
	0x2f, 0x8f, 0xb5, 0x13, 0xbf, 0x14, 0x51, 0x3f, 0xfc, 0x10, 0x62, 0x76, 0x98, 0x87, 0x10, 0x73,
	0x89, 0x59, 0x85, 0x49, 0x49, 0x7f, 0x0c, 0xae, 0xff, 0x06, 0x00, 0x00, 0xff, 0xff, 0x5a, 0x49,
	0x71, 0x16, 0x76, 0x04, 0x00, 0x00,
}