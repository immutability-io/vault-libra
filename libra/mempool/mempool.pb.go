// Code generated by protoc-gen-go. DO NOT EDIT.
// source: mempool.proto

package mempool

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
	shared "shared"
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

type AddTransactionWithValidationRequest struct {
	// Transaction from a wallet
	SignedTxn *SignedTransaction `protobuf:"bytes,1,opt,name=signed_txn,json=signedTxn,proto3" json:"signed_txn,omitempty"`
	// Max amount of gas required to execute the transaction
	// Without running the program, it is very difficult to determine this number,
	// so we use the max gas specified by the signed transaction.
	// This field is still included separately from the signed transaction so that
	// if we have a better methodology in the future, we can more accurately
	// specify the max gas.
	MaxGasCost uint64 `protobuf:"varint,2,opt,name=max_gas_cost,json=maxGasCost,proto3" json:"max_gas_cost,omitempty"`
	// Latest sequence number of the involved account from state db.
	LatestSequenceNumber uint64 `protobuf:"varint,3,opt,name=latest_sequence_number,json=latestSequenceNumber,proto3" json:"latest_sequence_number,omitempty"`
	// Latest account balance of the involved account from state db.
	AccountBalance       uint64   `protobuf:"varint,4,opt,name=account_balance,json=accountBalance,proto3" json:"account_balance,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *AddTransactionWithValidationRequest) Reset()         { *m = AddTransactionWithValidationRequest{} }
func (m *AddTransactionWithValidationRequest) String() string { return proto.CompactTextString(m) }
func (*AddTransactionWithValidationRequest) ProtoMessage()    {}
func (*AddTransactionWithValidationRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{0}
}

func (m *AddTransactionWithValidationRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddTransactionWithValidationRequest.Unmarshal(m, b)
}
func (m *AddTransactionWithValidationRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddTransactionWithValidationRequest.Marshal(b, m, deterministic)
}
func (m *AddTransactionWithValidationRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddTransactionWithValidationRequest.Merge(m, src)
}
func (m *AddTransactionWithValidationRequest) XXX_Size() int {
	return xxx_messageInfo_AddTransactionWithValidationRequest.Size(m)
}
func (m *AddTransactionWithValidationRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_AddTransactionWithValidationRequest.DiscardUnknown(m)
}

var xxx_messageInfo_AddTransactionWithValidationRequest proto.InternalMessageInfo

func (m *AddTransactionWithValidationRequest) GetSignedTxn() *SignedTransaction {
	if m != nil {
		return m.SignedTxn
	}
	return nil
}

func (m *AddTransactionWithValidationRequest) GetMaxGasCost() uint64 {
	if m != nil {
		return m.MaxGasCost
	}
	return 0
}

func (m *AddTransactionWithValidationRequest) GetLatestSequenceNumber() uint64 {
	if m != nil {
		return m.LatestSequenceNumber
	}
	return 0
}

func (m *AddTransactionWithValidationRequest) GetAccountBalance() uint64 {
	if m != nil {
		return m.AccountBalance
	}
	return 0
}

type AddTransactionWithValidationResponse struct {
	// The ledger version at the time of the transaction submitted. The submitted
	// transaction will have version bigger than this 'current_version'
	CurrentVersion uint64 `protobuf:"varint,1,opt,name=current_version,json=currentVersion,proto3" json:"current_version,omitempty"`
	// The result of the transaction submission
	Status               shared.MempoolAddTransactionStatus `protobuf:"varint,2,opt,name=status,proto3,enum=mempool.MempoolAddTransactionStatus" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                           `json:"-"`
	XXX_unrecognized     []byte                             `json:"-"`
	XXX_sizecache        int32                              `json:"-"`
}

func (m *AddTransactionWithValidationResponse) Reset()         { *m = AddTransactionWithValidationResponse{} }
func (m *AddTransactionWithValidationResponse) String() string { return proto.CompactTextString(m) }
func (*AddTransactionWithValidationResponse) ProtoMessage()    {}
func (*AddTransactionWithValidationResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{1}
}

func (m *AddTransactionWithValidationResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AddTransactionWithValidationResponse.Unmarshal(m, b)
}
func (m *AddTransactionWithValidationResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AddTransactionWithValidationResponse.Marshal(b, m, deterministic)
}
func (m *AddTransactionWithValidationResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AddTransactionWithValidationResponse.Merge(m, src)
}
func (m *AddTransactionWithValidationResponse) XXX_Size() int {
	return xxx_messageInfo_AddTransactionWithValidationResponse.Size(m)
}
func (m *AddTransactionWithValidationResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_AddTransactionWithValidationResponse.DiscardUnknown(m)
}

var xxx_messageInfo_AddTransactionWithValidationResponse proto.InternalMessageInfo

func (m *AddTransactionWithValidationResponse) GetCurrentVersion() uint64 {
	if m != nil {
		return m.CurrentVersion
	}
	return 0
}

func (m *AddTransactionWithValidationResponse) GetStatus() shared.MempoolAddTransactionStatus {
	if m != nil {
		return m.Status
	}
	return shared.MempoolAddTransactionStatus_Valid
}

// -----------------------------------------------------------------------------
// ---------------- GetBlock
// -----------------------------------------------------------------------------
type GetBlockRequest struct {
	MaxBlockSize         uint64                  `protobuf:"varint,1,opt,name=max_block_size,json=maxBlockSize,proto3" json:"max_block_size,omitempty"`
	Transactions         []*TransactionExclusion `protobuf:"bytes,2,rep,name=transactions,proto3" json:"transactions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                `json:"-"`
	XXX_unrecognized     []byte                  `json:"-"`
	XXX_sizecache        int32                   `json:"-"`
}

func (m *GetBlockRequest) Reset()         { *m = GetBlockRequest{} }
func (m *GetBlockRequest) String() string { return proto.CompactTextString(m) }
func (*GetBlockRequest) ProtoMessage()    {}
func (*GetBlockRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{2}
}

func (m *GetBlockRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetBlockRequest.Unmarshal(m, b)
}
func (m *GetBlockRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetBlockRequest.Marshal(b, m, deterministic)
}
func (m *GetBlockRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetBlockRequest.Merge(m, src)
}
func (m *GetBlockRequest) XXX_Size() int {
	return xxx_messageInfo_GetBlockRequest.Size(m)
}
func (m *GetBlockRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetBlockRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetBlockRequest proto.InternalMessageInfo

func (m *GetBlockRequest) GetMaxBlockSize() uint64 {
	if m != nil {
		return m.MaxBlockSize
	}
	return 0
}

func (m *GetBlockRequest) GetTransactions() []*TransactionExclusion {
	if m != nil {
		return m.Transactions
	}
	return nil
}

type GetBlockResponse struct {
	Block                *SignedTransactionsBlock `protobuf:"bytes,1,opt,name=block,proto3" json:"block,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *GetBlockResponse) Reset()         { *m = GetBlockResponse{} }
func (m *GetBlockResponse) String() string { return proto.CompactTextString(m) }
func (*GetBlockResponse) ProtoMessage()    {}
func (*GetBlockResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{3}
}

func (m *GetBlockResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetBlockResponse.Unmarshal(m, b)
}
func (m *GetBlockResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetBlockResponse.Marshal(b, m, deterministic)
}
func (m *GetBlockResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetBlockResponse.Merge(m, src)
}
func (m *GetBlockResponse) XXX_Size() int {
	return xxx_messageInfo_GetBlockResponse.Size(m)
}
func (m *GetBlockResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetBlockResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetBlockResponse proto.InternalMessageInfo

func (m *GetBlockResponse) GetBlock() *SignedTransactionsBlock {
	if m != nil {
		return m.Block
	}
	return nil
}

type TransactionExclusion struct {
	Sender               []byte   `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	SequenceNumber       uint64   `protobuf:"varint,2,opt,name=sequence_number,json=sequenceNumber,proto3" json:"sequence_number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TransactionExclusion) Reset()         { *m = TransactionExclusion{} }
func (m *TransactionExclusion) String() string { return proto.CompactTextString(m) }
func (*TransactionExclusion) ProtoMessage()    {}
func (*TransactionExclusion) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{4}
}

func (m *TransactionExclusion) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransactionExclusion.Unmarshal(m, b)
}
func (m *TransactionExclusion) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransactionExclusion.Marshal(b, m, deterministic)
}
func (m *TransactionExclusion) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransactionExclusion.Merge(m, src)
}
func (m *TransactionExclusion) XXX_Size() int {
	return xxx_messageInfo_TransactionExclusion.Size(m)
}
func (m *TransactionExclusion) XXX_DiscardUnknown() {
	xxx_messageInfo_TransactionExclusion.DiscardUnknown(m)
}

var xxx_messageInfo_TransactionExclusion proto.InternalMessageInfo

func (m *TransactionExclusion) GetSender() []byte {
	if m != nil {
		return m.Sender
	}
	return nil
}

func (m *TransactionExclusion) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

// -----------------------------------------------------------------------------
// ---------------- CommitTransactions
// -----------------------------------------------------------------------------
type CommitTransactionsRequest struct {
	Transactions []*CommittedTransaction `protobuf:"bytes,1,rep,name=transactions,proto3" json:"transactions,omitempty"`
	// agreed monotonic timestamp microseconds since the epoch for a committed block
	// used by Mempool to GC expired transactions
	BlockTimestampUsecs  uint64   `protobuf:"varint,2,opt,name=block_timestamp_usecs,json=blockTimestampUsecs,proto3" json:"block_timestamp_usecs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CommitTransactionsRequest) Reset()         { *m = CommitTransactionsRequest{} }
func (m *CommitTransactionsRequest) String() string { return proto.CompactTextString(m) }
func (*CommitTransactionsRequest) ProtoMessage()    {}
func (*CommitTransactionsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{5}
}

func (m *CommitTransactionsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CommitTransactionsRequest.Unmarshal(m, b)
}
func (m *CommitTransactionsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CommitTransactionsRequest.Marshal(b, m, deterministic)
}
func (m *CommitTransactionsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommitTransactionsRequest.Merge(m, src)
}
func (m *CommitTransactionsRequest) XXX_Size() int {
	return xxx_messageInfo_CommitTransactionsRequest.Size(m)
}
func (m *CommitTransactionsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CommitTransactionsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CommitTransactionsRequest proto.InternalMessageInfo

func (m *CommitTransactionsRequest) GetTransactions() []*CommittedTransaction {
	if m != nil {
		return m.Transactions
	}
	return nil
}

func (m *CommitTransactionsRequest) GetBlockTimestampUsecs() uint64 {
	if m != nil {
		return m.BlockTimestampUsecs
	}
	return 0
}

type CommitTransactionsResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CommitTransactionsResponse) Reset()         { *m = CommitTransactionsResponse{} }
func (m *CommitTransactionsResponse) String() string { return proto.CompactTextString(m) }
func (*CommitTransactionsResponse) ProtoMessage()    {}
func (*CommitTransactionsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{6}
}

func (m *CommitTransactionsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CommitTransactionsResponse.Unmarshal(m, b)
}
func (m *CommitTransactionsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CommitTransactionsResponse.Marshal(b, m, deterministic)
}
func (m *CommitTransactionsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommitTransactionsResponse.Merge(m, src)
}
func (m *CommitTransactionsResponse) XXX_Size() int {
	return xxx_messageInfo_CommitTransactionsResponse.Size(m)
}
func (m *CommitTransactionsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CommitTransactionsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CommitTransactionsResponse proto.InternalMessageInfo

type CommittedTransaction struct {
	Sender               []byte   `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	SequenceNumber       uint64   `protobuf:"varint,2,opt,name=sequence_number,json=sequenceNumber,proto3" json:"sequence_number,omitempty"`
	IsRejected           bool     `protobuf:"varint,3,opt,name=is_rejected,json=isRejected,proto3" json:"is_rejected,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CommittedTransaction) Reset()         { *m = CommittedTransaction{} }
func (m *CommittedTransaction) String() string { return proto.CompactTextString(m) }
func (*CommittedTransaction) ProtoMessage()    {}
func (*CommittedTransaction) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{7}
}

func (m *CommittedTransaction) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_CommittedTransaction.Unmarshal(m, b)
}
func (m *CommittedTransaction) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_CommittedTransaction.Marshal(b, m, deterministic)
}
func (m *CommittedTransaction) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommittedTransaction.Merge(m, src)
}
func (m *CommittedTransaction) XXX_Size() int {
	return xxx_messageInfo_CommittedTransaction.Size(m)
}
func (m *CommittedTransaction) XXX_DiscardUnknown() {
	xxx_messageInfo_CommittedTransaction.DiscardUnknown(m)
}

var xxx_messageInfo_CommittedTransaction proto.InternalMessageInfo

func (m *CommittedTransaction) GetSender() []byte {
	if m != nil {
		return m.Sender
	}
	return nil
}

func (m *CommittedTransaction) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *CommittedTransaction) GetIsRejected() bool {
	if m != nil {
		return m.IsRejected
	}
	return false
}

// -----------------------------------------------------------------------------
// ---------------- HealthCheck
// -----------------------------------------------------------------------------
type HealthCheckRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HealthCheckRequest) Reset()         { *m = HealthCheckRequest{} }
func (m *HealthCheckRequest) String() string { return proto.CompactTextString(m) }
func (*HealthCheckRequest) ProtoMessage()    {}
func (*HealthCheckRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{8}
}

func (m *HealthCheckRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckRequest.Unmarshal(m, b)
}
func (m *HealthCheckRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckRequest.Marshal(b, m, deterministic)
}
func (m *HealthCheckRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckRequest.Merge(m, src)
}
func (m *HealthCheckRequest) XXX_Size() int {
	return xxx_messageInfo_HealthCheckRequest.Size(m)
}
func (m *HealthCheckRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckRequest.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckRequest proto.InternalMessageInfo

type HealthCheckResponse struct {
	// Indicate whether Mempool is in healthy condition.
	IsHealthy            bool     `protobuf:"varint,1,opt,name=is_healthy,json=isHealthy,proto3" json:"is_healthy,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HealthCheckResponse) Reset()         { *m = HealthCheckResponse{} }
func (m *HealthCheckResponse) String() string { return proto.CompactTextString(m) }
func (*HealthCheckResponse) ProtoMessage()    {}
func (*HealthCheckResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_a84c3667d8c2093a, []int{9}
}

func (m *HealthCheckResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckResponse.Unmarshal(m, b)
}
func (m *HealthCheckResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckResponse.Marshal(b, m, deterministic)
}
func (m *HealthCheckResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckResponse.Merge(m, src)
}
func (m *HealthCheckResponse) XXX_Size() int {
	return xxx_messageInfo_HealthCheckResponse.Size(m)
}
func (m *HealthCheckResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckResponse.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckResponse proto.InternalMessageInfo

func (m *HealthCheckResponse) GetIsHealthy() bool {
	if m != nil {
		return m.IsHealthy
	}
	return false
}

func init() {
	proto.RegisterType((*AddTransactionWithValidationRequest)(nil), "mempool.AddTransactionWithValidationRequest")
	proto.RegisterType((*AddTransactionWithValidationResponse)(nil), "mempool.AddTransactionWithValidationResponse")
	proto.RegisterType((*GetBlockRequest)(nil), "mempool.GetBlockRequest")
	proto.RegisterType((*GetBlockResponse)(nil), "mempool.GetBlockResponse")
	proto.RegisterType((*TransactionExclusion)(nil), "mempool.TransactionExclusion")
	proto.RegisterType((*CommitTransactionsRequest)(nil), "mempool.CommitTransactionsRequest")
	proto.RegisterType((*CommitTransactionsResponse)(nil), "mempool.CommitTransactionsResponse")
	proto.RegisterType((*CommittedTransaction)(nil), "mempool.CommittedTransaction")
	proto.RegisterType((*HealthCheckRequest)(nil), "mempool.HealthCheckRequest")
	proto.RegisterType((*HealthCheckResponse)(nil), "mempool.HealthCheckResponse")
}

func init() { proto.RegisterFile("mempool.proto", fileDescriptor_a84c3667d8c2093a) }

var fileDescriptor_a84c3667d8c2093a = []byte{
	// 620 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x54, 0x5d, 0x4f, 0x13, 0x41,
	0x14, 0x75, 0x01, 0xf9, 0xb8, 0xc5, 0xa2, 0x43, 0x25, 0x65, 0x01, 0x25, 0x0b, 0x89, 0x3c, 0x68,
	0x4d, 0x2a, 0x89, 0x2f, 0xbe, 0x00, 0x31, 0x10, 0x13, 0x7d, 0xd8, 0x22, 0x3c, 0x4e, 0xa6, 0xbb,
	0x37, 0x74, 0x74, 0x77, 0xa7, 0xee, 0x9d, 0x35, 0x85, 0xc4, 0x9f, 0xe0, 0x8b, 0x7f, 0xd0, 0xbf,
	0xe1, 0xa3, 0xd9, 0x99, 0xe9, 0xd2, 0x96, 0xda, 0x90, 0xf8, 0xb4, 0x99, 0x7b, 0xce, 0x9d, 0x33,
	0x73, 0xce, 0x9d, 0x85, 0x47, 0x29, 0xa6, 0x7d, 0xa5, 0x92, 0x56, 0x3f, 0x57, 0x5a, 0xb1, 0x25,
	0xb7, 0xf4, 0x9f, 0xe8, 0x5c, 0x64, 0x24, 0x22, 0x2d, 0x55, 0x66, 0x31, 0x7f, 0x8b, 0x7a, 0x22,
	0xc7, 0xf8, 0xb5, 0xa3, 0x70, 0xd2, 0x42, 0x17, 0x64, 0xc1, 0xe0, 0xb7, 0x07, 0x7b, 0x47, 0x71,
	0x7c, 0x7e, 0xdb, 0x75, 0x29, 0x75, 0xef, 0x42, 0x24, 0x32, 0x16, 0xe5, 0x2a, 0xc4, 0x6f, 0x05,
	0x92, 0x66, 0x6f, 0x01, 0x48, 0x5e, 0x65, 0x18, 0x73, 0x3d, 0xc8, 0x9a, 0xde, 0xae, 0x77, 0x50,
	0x6b, 0x37, 0x5b, 0xfa, 0xba, 0x8f, 0xd4, 0xea, 0x18, 0x60, 0x64, 0x8b, 0x70, 0xc5, 0x72, 0xcf,
	0x07, 0x19, 0xdb, 0x85, 0xd5, 0x54, 0x0c, 0xf8, 0x95, 0x20, 0x1e, 0x29, 0xd2, 0xcd, 0xb9, 0x5d,
	0xef, 0x60, 0x21, 0x84, 0x54, 0x0c, 0x4e, 0x05, 0x9d, 0x28, 0xd2, 0xec, 0x10, 0x36, 0x12, 0xa1,
	0x91, 0x34, 0xa7, 0x52, 0x2c, 0x8b, 0x90, 0x67, 0x45, 0xda, 0xc5, 0xbc, 0x39, 0x6f, 0xb8, 0x0d,
	0x8b, 0x76, 0x1c, 0xf8, 0xc9, 0x60, 0xec, 0x05, 0xac, 0x89, 0x28, 0x52, 0x45, 0xa6, 0x79, 0x57,
	0x24, 0x22, 0x8b, 0xb0, 0xb9, 0x60, 0xe8, 0x75, 0x57, 0x3e, 0xb6, 0xd5, 0xe0, 0xa7, 0x07, 0xfb,
	0xb3, 0x6f, 0x48, 0x7d, 0x95, 0x11, 0x96, 0x3b, 0x46, 0x45, 0x9e, 0x63, 0xa6, 0xf9, 0x77, 0xcc,
	0x49, 0x2a, 0x7b, 0xcf, 0x85, 0xb0, 0xee, 0xca, 0x17, 0xb6, 0xca, 0xde, 0xc1, 0xa2, 0xf5, 0xd0,
	0x5c, 0xa6, 0xde, 0xde, 0x6f, 0x0d, 0xc3, 0xf8, 0x68, 0xbf, 0xe3, 0x72, 0x1d, 0xc3, 0x0d, 0x5d,
	0x4f, 0x70, 0x03, 0x6b, 0xa7, 0xa8, 0x8f, 0x13, 0x15, 0x7d, 0x1d, 0x9a, 0xbb, 0x0f, 0xf5, 0xd2,
	0xa3, 0x6e, 0x59, 0xe3, 0x24, 0x6f, 0xd0, 0x09, 0x97, 0xce, 0x19, 0x62, 0x47, 0xde, 0x20, 0x3b,
	0x82, 0xd5, 0x91, 0x70, 0x4b, 0xf1, 0xf9, 0x83, 0x5a, 0x7b, 0xa7, 0x12, 0x1f, 0x91, 0x7c, 0x3f,
	0x88, 0x92, 0xa2, 0x3c, 0x6b, 0x38, 0xd6, 0x12, 0x9c, 0xc1, 0xe3, 0x5b, 0x6d, 0x77, 0xed, 0x43,
	0x78, 0x68, 0x84, 0x5d, 0xa8, 0xcf, 0xfe, 0x15, 0x2a, 0xd9, 0x36, 0x4b, 0x0e, 0x2e, 0xa1, 0x31,
	0x4d, 0x8f, 0x6d, 0xc0, 0x22, 0x61, 0x16, 0x63, 0x6e, 0xb6, 0x5b, 0x0d, 0xdd, 0xaa, 0x34, 0x77,
	0x32, 0x5d, 0x3b, 0x09, 0x75, 0x1a, 0xcb, 0x35, 0xf8, 0xe5, 0xc1, 0xe6, 0x89, 0x4a, 0x53, 0xa9,
	0x47, 0xb5, 0x87, 0x4e, 0x4d, 0x7a, 0xe0, 0x4d, 0x78, 0x60, 0x3b, 0xf5, 0xf8, 0x34, 0x8e, 0xb5,
	0xb0, 0x36, 0x3c, 0xb5, 0x46, 0x6b, 0x99, 0x22, 0x69, 0x91, 0xf6, 0x79, 0x41, 0x18, 0x91, 0x3b,
	0xcf, 0xba, 0x01, 0xcf, 0x87, 0xd8, 0xe7, 0x12, 0x0a, 0xb6, 0xc1, 0x9f, 0x76, 0x26, 0xeb, 0x60,
	0x30, 0x80, 0xc6, 0x34, 0xdd, 0xff, 0xf6, 0x82, 0x3d, 0x87, 0x9a, 0x24, 0x9e, 0xe3, 0x17, 0x8c,
	0x34, 0xc6, 0xe6, 0x39, 0x2c, 0x87, 0x20, 0x29, 0x74, 0x95, 0xa0, 0x01, 0xec, 0x0c, 0x45, 0xa2,
	0x7b, 0x27, 0x3d, 0xac, 0xc6, 0x29, 0x38, 0x84, 0xf5, 0xb1, 0xaa, 0x0b, 0x7a, 0x07, 0x40, 0x12,
	0xef, 0x19, 0xe4, 0xda, 0x1c, 0x69, 0x39, 0x5c, 0x91, 0x64, 0xa9, 0xd7, 0xed, 0x3f, 0x73, 0xb0,
	0xe4, 0xe6, 0x97, 0xfd, 0x80, 0xed, 0x59, 0x4f, 0x86, 0xbd, 0xac, 0x0c, 0xbf, 0xc7, 0xbf, 0xc3,
	0x7f, 0x75, 0x4f, 0xb6, 0xb3, 0xf3, 0x01, 0x3b, 0x82, 0xe5, 0xe1, 0x98, 0xb2, 0x66, 0xd5, 0x3c,
	0xf1, 0x6a, 0xfc, 0xcd, 0x29, 0x48, 0xb5, 0x05, 0x07, 0x76, 0x37, 0x31, 0x16, 0x4c, 0x0c, 0xca,
	0x94, 0x11, 0xf3, 0xf7, 0x66, 0x72, 0x2a, 0x81, 0x0f, 0x50, 0x1b, 0x31, 0x99, 0x6d, 0x55, 0x5d,
	0x77, 0x03, 0xf1, 0xb7, 0xa7, 0x83, 0xc3, 0xbd, 0xba, 0x8b, 0xe6, 0x5f, 0xfc, 0xe6, 0x6f, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x68, 0xfa, 0x06, 0xf3, 0xd5, 0x05, 0x00, 0x00,
}
