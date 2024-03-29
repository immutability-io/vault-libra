// Code generated by protoc-gen-go. DO NOT EDIT.
// source: consensus.proto

package grpc

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

type BlockRetrievalStatus int32

const (
	// Successfully fill in the request.
	BlockRetrievalStatus_SUCCEEDED BlockRetrievalStatus = 0
	// Can not find the block corresponding to block_id.
	BlockRetrievalStatus_ID_NOT_FOUND BlockRetrievalStatus = 1
	// Can not find enough blocks but find some.
	BlockRetrievalStatus_NOT_ENOUGH_BLOCKS BlockRetrievalStatus = 2
)

var BlockRetrievalStatus_name = map[int32]string{
	0: "SUCCEEDED",
	1: "ID_NOT_FOUND",
	2: "NOT_ENOUGH_BLOCKS",
}

var BlockRetrievalStatus_value = map[string]int32{
	"SUCCEEDED":         0,
	"ID_NOT_FOUND":      1,
	"NOT_ENOUGH_BLOCKS": 2,
}

func (x BlockRetrievalStatus) String() string {
	return proto.EnumName(BlockRetrievalStatus_name, int32(x))
}

func (BlockRetrievalStatus) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{0}
}

type ConsensusMsg struct {
	// Types that are valid to be assigned to Message:
	//	*ConsensusMsg_Proposal
	//	*ConsensusMsg_Vote
	//	*ConsensusMsg_RequestBlock
	//	*ConsensusMsg_RespondBlock
	//	*ConsensusMsg_NewRound
	//	*ConsensusMsg_RequestChunk
	//	*ConsensusMsg_RespondChunk
	Message              isConsensusMsg_Message `protobuf_oneof:"message"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *ConsensusMsg) Reset()         { *m = ConsensusMsg{} }
func (m *ConsensusMsg) String() string { return proto.CompactTextString(m) }
func (*ConsensusMsg) ProtoMessage()    {}
func (*ConsensusMsg) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{0}
}

func (m *ConsensusMsg) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConsensusMsg.Unmarshal(m, b)
}
func (m *ConsensusMsg) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConsensusMsg.Marshal(b, m, deterministic)
}
func (m *ConsensusMsg) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConsensusMsg.Merge(m, src)
}
func (m *ConsensusMsg) XXX_Size() int {
	return xxx_messageInfo_ConsensusMsg.Size(m)
}
func (m *ConsensusMsg) XXX_DiscardUnknown() {
	xxx_messageInfo_ConsensusMsg.DiscardUnknown(m)
}

var xxx_messageInfo_ConsensusMsg proto.InternalMessageInfo

type isConsensusMsg_Message interface {
	isConsensusMsg_Message()
}

type ConsensusMsg_Proposal struct {
	Proposal *Proposal `protobuf:"bytes,1,opt,name=proposal,proto3,oneof"`
}

type ConsensusMsg_Vote struct {
	Vote *Vote `protobuf:"bytes,2,opt,name=vote,proto3,oneof"`
}

type ConsensusMsg_RequestBlock struct {
	RequestBlock *RequestBlock `protobuf:"bytes,3,opt,name=request_block,json=requestBlock,proto3,oneof"`
}

type ConsensusMsg_RespondBlock struct {
	RespondBlock *RespondBlock `protobuf:"bytes,4,opt,name=respond_block,json=respondBlock,proto3,oneof"`
}

type ConsensusMsg_NewRound struct {
	NewRound *NewRound `protobuf:"bytes,5,opt,name=new_round,json=newRound,proto3,oneof"`
}

type ConsensusMsg_RequestChunk struct {
	RequestChunk *RequestChunk `protobuf:"bytes,6,opt,name=request_chunk,json=requestChunk,proto3,oneof"`
}

type ConsensusMsg_RespondChunk struct {
	RespondChunk *RespondChunk `protobuf:"bytes,7,opt,name=respond_chunk,json=respondChunk,proto3,oneof"`
}

func (*ConsensusMsg_Proposal) isConsensusMsg_Message() {}

func (*ConsensusMsg_Vote) isConsensusMsg_Message() {}

func (*ConsensusMsg_RequestBlock) isConsensusMsg_Message() {}

func (*ConsensusMsg_RespondBlock) isConsensusMsg_Message() {}

func (*ConsensusMsg_NewRound) isConsensusMsg_Message() {}

func (*ConsensusMsg_RequestChunk) isConsensusMsg_Message() {}

func (*ConsensusMsg_RespondChunk) isConsensusMsg_Message() {}

func (m *ConsensusMsg) GetMessage() isConsensusMsg_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (m *ConsensusMsg) GetProposal() *Proposal {
	if x, ok := m.GetMessage().(*ConsensusMsg_Proposal); ok {
		return x.Proposal
	}
	return nil
}

func (m *ConsensusMsg) GetVote() *Vote {
	if x, ok := m.GetMessage().(*ConsensusMsg_Vote); ok {
		return x.Vote
	}
	return nil
}

func (m *ConsensusMsg) GetRequestBlock() *RequestBlock {
	if x, ok := m.GetMessage().(*ConsensusMsg_RequestBlock); ok {
		return x.RequestBlock
	}
	return nil
}

func (m *ConsensusMsg) GetRespondBlock() *RespondBlock {
	if x, ok := m.GetMessage().(*ConsensusMsg_RespondBlock); ok {
		return x.RespondBlock
	}
	return nil
}

func (m *ConsensusMsg) GetNewRound() *NewRound {
	if x, ok := m.GetMessage().(*ConsensusMsg_NewRound); ok {
		return x.NewRound
	}
	return nil
}

func (m *ConsensusMsg) GetRequestChunk() *RequestChunk {
	if x, ok := m.GetMessage().(*ConsensusMsg_RequestChunk); ok {
		return x.RequestChunk
	}
	return nil
}

func (m *ConsensusMsg) GetRespondChunk() *RespondChunk {
	if x, ok := m.GetMessage().(*ConsensusMsg_RespondChunk); ok {
		return x.RespondChunk
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*ConsensusMsg) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*ConsensusMsg_Proposal)(nil),
		(*ConsensusMsg_Vote)(nil),
		(*ConsensusMsg_RequestBlock)(nil),
		(*ConsensusMsg_RespondBlock)(nil),
		(*ConsensusMsg_NewRound)(nil),
		(*ConsensusMsg_RequestChunk)(nil),
		(*ConsensusMsg_RespondChunk)(nil),
	}
}

type Proposal struct {
	// The proposed block
	ProposedBlock *Block `protobuf:"bytes,1,opt,name=proposed_block,json=proposedBlock,proto3" json:"proposed_block,omitempty"`
	// Author of the proposal
	Proposer []byte `protobuf:"bytes,2,opt,name=proposer,proto3" json:"proposer,omitempty"`
	// Optional timeout quorum certificate if this proposal is generated by
	// timeout
	TimeoutQuorumCert *PacemakerTimeoutCertificate `protobuf:"bytes,3,opt,name=timeout_quorum_cert,json=timeoutQuorumCert,proto3" json:"timeout_quorum_cert,omitempty"`
	// The highest ledger info
	HighestLedgerInfo    *QuorumCert `protobuf:"bytes,4,opt,name=highest_ledger_info,json=highestLedgerInfo,proto3" json:"highest_ledger_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *Proposal) Reset()         { *m = Proposal{} }
func (m *Proposal) String() string { return proto.CompactTextString(m) }
func (*Proposal) ProtoMessage()    {}
func (*Proposal) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{1}
}

func (m *Proposal) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Proposal.Unmarshal(m, b)
}
func (m *Proposal) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Proposal.Marshal(b, m, deterministic)
}
func (m *Proposal) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Proposal.Merge(m, src)
}
func (m *Proposal) XXX_Size() int {
	return xxx_messageInfo_Proposal.Size(m)
}
func (m *Proposal) XXX_DiscardUnknown() {
	xxx_messageInfo_Proposal.DiscardUnknown(m)
}

var xxx_messageInfo_Proposal proto.InternalMessageInfo

func (m *Proposal) GetProposedBlock() *Block {
	if m != nil {
		return m.ProposedBlock
	}
	return nil
}

func (m *Proposal) GetProposer() []byte {
	if m != nil {
		return m.Proposer
	}
	return nil
}

func (m *Proposal) GetTimeoutQuorumCert() *PacemakerTimeoutCertificate {
	if m != nil {
		return m.TimeoutQuorumCert
	}
	return nil
}

func (m *Proposal) GetHighestLedgerInfo() *QuorumCert {
	if m != nil {
		return m.HighestLedgerInfo
	}
	return nil
}

type PacemakerTimeout struct {
	// Round that has timed out (e.g. we propose to switch to round + 1)
	Round uint64 `protobuf:"varint,1,opt,name=round,proto3" json:"round,omitempty"`
	// Author of timeout
	Author []byte `protobuf:"bytes,2,opt,name=author,proto3" json:"author,omitempty"`
	// Signature that this timeout was authored by owner
	Signature            []byte   `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PacemakerTimeout) Reset()         { *m = PacemakerTimeout{} }
func (m *PacemakerTimeout) String() string { return proto.CompactTextString(m) }
func (*PacemakerTimeout) ProtoMessage()    {}
func (*PacemakerTimeout) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{2}
}

func (m *PacemakerTimeout) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PacemakerTimeout.Unmarshal(m, b)
}
func (m *PacemakerTimeout) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PacemakerTimeout.Marshal(b, m, deterministic)
}
func (m *PacemakerTimeout) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PacemakerTimeout.Merge(m, src)
}
func (m *PacemakerTimeout) XXX_Size() int {
	return xxx_messageInfo_PacemakerTimeout.Size(m)
}
func (m *PacemakerTimeout) XXX_DiscardUnknown() {
	xxx_messageInfo_PacemakerTimeout.DiscardUnknown(m)
}

var xxx_messageInfo_PacemakerTimeout proto.InternalMessageInfo

func (m *PacemakerTimeout) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *PacemakerTimeout) GetAuthor() []byte {
	if m != nil {
		return m.Author
	}
	return nil
}

func (m *PacemakerTimeout) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type NewRound struct {
	// Highest quorum certificate known after a timeout ouf a round.
	HighestQuorumCert *QuorumCert `protobuf:"bytes,1,opt,name=highest_quorum_cert,json=highestQuorumCert,proto3" json:"highest_quorum_cert,omitempty"`
	// Timeout
	PacemakerTimeout *PacemakerTimeout `protobuf:"bytes,2,opt,name=pacemaker_timeout,json=pacemakerTimeout,proto3" json:"pacemaker_timeout,omitempty"`
	// Author of new round message
	Author []byte `protobuf:"bytes,3,opt,name=author,proto3" json:"author,omitempty"`
	// Signature that this timeout was authored by owner
	Signature []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	// The highest ledger info
	HighestLedgerInfo    *QuorumCert `protobuf:"bytes,5,opt,name=highest_ledger_info,json=highestLedgerInfo,proto3" json:"highest_ledger_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *NewRound) Reset()         { *m = NewRound{} }
func (m *NewRound) String() string { return proto.CompactTextString(m) }
func (*NewRound) ProtoMessage()    {}
func (*NewRound) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{3}
}

func (m *NewRound) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NewRound.Unmarshal(m, b)
}
func (m *NewRound) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NewRound.Marshal(b, m, deterministic)
}
func (m *NewRound) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NewRound.Merge(m, src)
}
func (m *NewRound) XXX_Size() int {
	return xxx_messageInfo_NewRound.Size(m)
}
func (m *NewRound) XXX_DiscardUnknown() {
	xxx_messageInfo_NewRound.DiscardUnknown(m)
}

var xxx_messageInfo_NewRound proto.InternalMessageInfo

func (m *NewRound) GetHighestQuorumCert() *QuorumCert {
	if m != nil {
		return m.HighestQuorumCert
	}
	return nil
}

func (m *NewRound) GetPacemakerTimeout() *PacemakerTimeout {
	if m != nil {
		return m.PacemakerTimeout
	}
	return nil
}

func (m *NewRound) GetAuthor() []byte {
	if m != nil {
		return m.Author
	}
	return nil
}

func (m *NewRound) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *NewRound) GetHighestLedgerInfo() *QuorumCert {
	if m != nil {
		return m.HighestLedgerInfo
	}
	return nil
}

type PacemakerTimeoutCertificate struct {
	// Round for which this certificate was created
	Round uint64 `protobuf:"varint,1,opt,name=round,proto3" json:"round,omitempty"`
	// List of certified timeouts
	Timeouts             []*PacemakerTimeout `protobuf:"bytes,2,rep,name=timeouts,proto3" json:"timeouts,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *PacemakerTimeoutCertificate) Reset()         { *m = PacemakerTimeoutCertificate{} }
func (m *PacemakerTimeoutCertificate) String() string { return proto.CompactTextString(m) }
func (*PacemakerTimeoutCertificate) ProtoMessage()    {}
func (*PacemakerTimeoutCertificate) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{4}
}

func (m *PacemakerTimeoutCertificate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PacemakerTimeoutCertificate.Unmarshal(m, b)
}
func (m *PacemakerTimeoutCertificate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PacemakerTimeoutCertificate.Marshal(b, m, deterministic)
}
func (m *PacemakerTimeoutCertificate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PacemakerTimeoutCertificate.Merge(m, src)
}
func (m *PacemakerTimeoutCertificate) XXX_Size() int {
	return xxx_messageInfo_PacemakerTimeoutCertificate.Size(m)
}
func (m *PacemakerTimeoutCertificate) XXX_DiscardUnknown() {
	xxx_messageInfo_PacemakerTimeoutCertificate.DiscardUnknown(m)
}

var xxx_messageInfo_PacemakerTimeoutCertificate proto.InternalMessageInfo

func (m *PacemakerTimeoutCertificate) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *PacemakerTimeoutCertificate) GetTimeouts() []*PacemakerTimeout {
	if m != nil {
		return m.Timeouts
	}
	return nil
}

type Block struct {
	// This block's id as a hash value
	Id []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Parent block id of this block as a hash value (all zeros to indicate the
	// genesis block)
	ParentId []byte `protobuf:"bytes,2,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	// Payload of the block (e.g. one or more transaction(s)
	Payload []byte `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	// The round of the block (internal monotonically increasing counter).
	Round uint64 `protobuf:"varint,4,opt,name=round,proto3" json:"round,omitempty"`
	// The height of the block (position in the chain).
	Height uint64 `protobuf:"varint,5,opt,name=height,proto3" json:"height,omitempty"`
	// The approximate physical microseconds since the epoch when the block was proposed
	TimestampUsecs uint64 `protobuf:"varint,6,opt,name=timestamp_usecs,json=timestampUsecs,proto3" json:"timestamp_usecs,omitempty"`
	// Contains the quorum certified ancestor and whether the quorum certified
	// ancestor was voted on successfully
	QuorumCert *QuorumCert `protobuf:"bytes,7,opt,name=quorum_cert,json=quorumCert,proto3" json:"quorum_cert,omitempty"`
	// Author of the block that can be validated by the author's public key and
	// the signature
	Author []byte `protobuf:"bytes,8,opt,name=author,proto3" json:"author,omitempty"`
	// Signature that the hash of this block has been authored by the owner of the
	// private key
	Signature            []byte   `protobuf:"bytes,9,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Block) Reset()         { *m = Block{} }
func (m *Block) String() string { return proto.CompactTextString(m) }
func (*Block) ProtoMessage()    {}
func (*Block) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{5}
}

func (m *Block) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Block.Unmarshal(m, b)
}
func (m *Block) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Block.Marshal(b, m, deterministic)
}
func (m *Block) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Block.Merge(m, src)
}
func (m *Block) XXX_Size() int {
	return xxx_messageInfo_Block.Size(m)
}
func (m *Block) XXX_DiscardUnknown() {
	xxx_messageInfo_Block.DiscardUnknown(m)
}

var xxx_messageInfo_Block proto.InternalMessageInfo

func (m *Block) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *Block) GetParentId() []byte {
	if m != nil {
		return m.ParentId
	}
	return nil
}

func (m *Block) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Block) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *Block) GetHeight() uint64 {
	if m != nil {
		return m.Height
	}
	return 0
}

func (m *Block) GetTimestampUsecs() uint64 {
	if m != nil {
		return m.TimestampUsecs
	}
	return 0
}

func (m *Block) GetQuorumCert() *QuorumCert {
	if m != nil {
		return m.QuorumCert
	}
	return nil
}

func (m *Block) GetAuthor() []byte {
	if m != nil {
		return m.Author
	}
	return nil
}

func (m *Block) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type QuorumCert struct {
	// Ancestor of this block (could be a parent)
	BlockId []byte `protobuf:"bytes,1,opt,name=block_id,json=blockId,proto3" json:"block_id,omitempty"`
	/// The execution state id of the corresponding block
	StateId []byte `protobuf:"bytes,2,opt,name=state_id,json=stateId,proto3" json:"state_id,omitempty"`
	Version uint64 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	/// The round of a certified block.
	Round uint64 `protobuf:"varint,4,opt,name=round,proto3" json:"round,omitempty"`
	// LedgerInfo with at least 2f+1 signatures. The LedgerInfo's consensus data
	// hash is a digest that covers ancestor_id, state_id and round.
	SignedLedgerInfo     *LedgerInfoWithSignatures `protobuf:"bytes,5,opt,name=signed_ledger_info,json=signedLedgerInfo,proto3" json:"signed_ledger_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *QuorumCert) Reset()         { *m = QuorumCert{} }
func (m *QuorumCert) String() string { return proto.CompactTextString(m) }
func (*QuorumCert) ProtoMessage()    {}
func (*QuorumCert) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{6}
}

func (m *QuorumCert) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_QuorumCert.Unmarshal(m, b)
}
func (m *QuorumCert) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_QuorumCert.Marshal(b, m, deterministic)
}
func (m *QuorumCert) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QuorumCert.Merge(m, src)
}
func (m *QuorumCert) XXX_Size() int {
	return xxx_messageInfo_QuorumCert.Size(m)
}
func (m *QuorumCert) XXX_DiscardUnknown() {
	xxx_messageInfo_QuorumCert.DiscardUnknown(m)
}

var xxx_messageInfo_QuorumCert proto.InternalMessageInfo

func (m *QuorumCert) GetBlockId() []byte {
	if m != nil {
		return m.BlockId
	}
	return nil
}

func (m *QuorumCert) GetStateId() []byte {
	if m != nil {
		return m.StateId
	}
	return nil
}

func (m *QuorumCert) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *QuorumCert) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *QuorumCert) GetSignedLedgerInfo() *LedgerInfoWithSignatures {
	if m != nil {
		return m.SignedLedgerInfo
	}
	return nil
}

type Vote struct {
	// The id of the proposed block.
	ProposedBlockId []byte `protobuf:"bytes,1,opt,name=proposed_block_id,json=proposedBlockId,proto3" json:"proposed_block_id,omitempty"`
	// The id of the state generated by the StateExecutor after executing the
	// proposed block.
	ExecutedStateId []byte `protobuf:"bytes,2,opt,name=executed_state_id,json=executedStateId,proto3" json:"executed_state_id,omitempty"`
	Version         uint64 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	Round           uint64 `protobuf:"varint,4,opt,name=round,proto3" json:"round,omitempty"`
	// Author of the vote.
	Author []byte `protobuf:"bytes,5,opt,name=author,proto3" json:"author,omitempty"`
	// The ledger info carried with the vote (corresponding to the block of a
	// potentially committed txn).
	LedgerInfo *LedgerInfo `protobuf:"bytes,6,opt,name=ledger_info,json=ledgerInfo,proto3" json:"ledger_info,omitempty"`
	// Signature of the ledger info.
	Signature            []byte   `protobuf:"bytes,7,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Vote) Reset()         { *m = Vote{} }
func (m *Vote) String() string { return proto.CompactTextString(m) }
func (*Vote) ProtoMessage()    {}
func (*Vote) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{7}
}

func (m *Vote) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Vote.Unmarshal(m, b)
}
func (m *Vote) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Vote.Marshal(b, m, deterministic)
}
func (m *Vote) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Vote.Merge(m, src)
}
func (m *Vote) XXX_Size() int {
	return xxx_messageInfo_Vote.Size(m)
}
func (m *Vote) XXX_DiscardUnknown() {
	xxx_messageInfo_Vote.DiscardUnknown(m)
}

var xxx_messageInfo_Vote proto.InternalMessageInfo

func (m *Vote) GetProposedBlockId() []byte {
	if m != nil {
		return m.ProposedBlockId
	}
	return nil
}

func (m *Vote) GetExecutedStateId() []byte {
	if m != nil {
		return m.ExecutedStateId
	}
	return nil
}

func (m *Vote) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *Vote) GetRound() uint64 {
	if m != nil {
		return m.Round
	}
	return 0
}

func (m *Vote) GetAuthor() []byte {
	if m != nil {
		return m.Author
	}
	return nil
}

func (m *Vote) GetLedgerInfo() *LedgerInfo {
	if m != nil {
		return m.LedgerInfo
	}
	return nil
}

func (m *Vote) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type RequestBlock struct {
	// The id of the requested block.
	BlockId              []byte   `protobuf:"bytes,1,opt,name=block_id,json=blockId,proto3" json:"block_id,omitempty"`
	NumBlocks            uint64   `protobuf:"varint,2,opt,name=num_blocks,json=numBlocks,proto3" json:"num_blocks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RequestBlock) Reset()         { *m = RequestBlock{} }
func (m *RequestBlock) String() string { return proto.CompactTextString(m) }
func (*RequestBlock) ProtoMessage()    {}
func (*RequestBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{8}
}

func (m *RequestBlock) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RequestBlock.Unmarshal(m, b)
}
func (m *RequestBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RequestBlock.Marshal(b, m, deterministic)
}
func (m *RequestBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RequestBlock.Merge(m, src)
}
func (m *RequestBlock) XXX_Size() int {
	return xxx_messageInfo_RequestBlock.Size(m)
}
func (m *RequestBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_RequestBlock.DiscardUnknown(m)
}

var xxx_messageInfo_RequestBlock proto.InternalMessageInfo

func (m *RequestBlock) GetBlockId() []byte {
	if m != nil {
		return m.BlockId
	}
	return nil
}

func (m *RequestBlock) GetNumBlocks() uint64 {
	if m != nil {
		return m.NumBlocks
	}
	return 0
}

type RespondBlock struct {
	Status BlockRetrievalStatus `protobuf:"varint,1,opt,name=status,proto3,enum=network.BlockRetrievalStatus" json:"status,omitempty"`
	// The responded block.
	Blocks               []*Block `protobuf:"bytes,2,rep,name=blocks,proto3" json:"blocks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RespondBlock) Reset()         { *m = RespondBlock{} }
func (m *RespondBlock) String() string { return proto.CompactTextString(m) }
func (*RespondBlock) ProtoMessage()    {}
func (*RespondBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{9}
}

func (m *RespondBlock) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespondBlock.Unmarshal(m, b)
}
func (m *RespondBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespondBlock.Marshal(b, m, deterministic)
}
func (m *RespondBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespondBlock.Merge(m, src)
}
func (m *RespondBlock) XXX_Size() int {
	return xxx_messageInfo_RespondBlock.Size(m)
}
func (m *RespondBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_RespondBlock.DiscardUnknown(m)
}

var xxx_messageInfo_RespondBlock proto.InternalMessageInfo

func (m *RespondBlock) GetStatus() BlockRetrievalStatus {
	if m != nil {
		return m.Status
	}
	return BlockRetrievalStatus_SUCCEEDED
}

func (m *RespondBlock) GetBlocks() []*Block {
	if m != nil {
		return m.Blocks
	}
	return nil
}

type RequestChunk struct {
	StartVersion         uint64      `protobuf:"varint,1,opt,name=start_version,json=startVersion,proto3" json:"start_version,omitempty"`
	Target               *QuorumCert `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
	BatchSize            uint64      `protobuf:"varint,3,opt,name=batch_size,json=batchSize,proto3" json:"batch_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *RequestChunk) Reset()         { *m = RequestChunk{} }
func (m *RequestChunk) String() string { return proto.CompactTextString(m) }
func (*RequestChunk) ProtoMessage()    {}
func (*RequestChunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{10}
}

func (m *RequestChunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RequestChunk.Unmarshal(m, b)
}
func (m *RequestChunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RequestChunk.Marshal(b, m, deterministic)
}
func (m *RequestChunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RequestChunk.Merge(m, src)
}
func (m *RequestChunk) XXX_Size() int {
	return xxx_messageInfo_RequestChunk.Size(m)
}
func (m *RequestChunk) XXX_DiscardUnknown() {
	xxx_messageInfo_RequestChunk.DiscardUnknown(m)
}

var xxx_messageInfo_RequestChunk proto.InternalMessageInfo

func (m *RequestChunk) GetStartVersion() uint64 {
	if m != nil {
		return m.StartVersion
	}
	return 0
}

func (m *RequestChunk) GetTarget() *QuorumCert {
	if m != nil {
		return m.Target
	}
	return nil
}

func (m *RequestChunk) GetBatchSize() uint64 {
	if m != nil {
		return m.BatchSize
	}
	return 0
}

type RespondChunk struct {
	TxnListWithProof     *TransactionListWithProof `protobuf:"bytes,1,opt,name=txn_list_with_proof,json=txnListWithProof,proto3" json:"txn_list_with_proof,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *RespondChunk) Reset()         { *m = RespondChunk{} }
func (m *RespondChunk) String() string { return proto.CompactTextString(m) }
func (*RespondChunk) ProtoMessage()    {}
func (*RespondChunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_56f0f2c53b3de771, []int{11}
}

func (m *RespondChunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RespondChunk.Unmarshal(m, b)
}
func (m *RespondChunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RespondChunk.Marshal(b, m, deterministic)
}
func (m *RespondChunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RespondChunk.Merge(m, src)
}
func (m *RespondChunk) XXX_Size() int {
	return xxx_messageInfo_RespondChunk.Size(m)
}
func (m *RespondChunk) XXX_DiscardUnknown() {
	xxx_messageInfo_RespondChunk.DiscardUnknown(m)
}

var xxx_messageInfo_RespondChunk proto.InternalMessageInfo

func (m *RespondChunk) GetTxnListWithProof() *TransactionListWithProof {
	if m != nil {
		return m.TxnListWithProof
	}
	return nil
}

func init() {
	proto.RegisterEnum("network.BlockRetrievalStatus", BlockRetrievalStatus_name, BlockRetrievalStatus_value)
	proto.RegisterType((*ConsensusMsg)(nil), "network.ConsensusMsg")
	proto.RegisterType((*Proposal)(nil), "network.Proposal")
	proto.RegisterType((*PacemakerTimeout)(nil), "network.PacemakerTimeout")
	proto.RegisterType((*NewRound)(nil), "network.NewRound")
	proto.RegisterType((*PacemakerTimeoutCertificate)(nil), "network.PacemakerTimeoutCertificate")
	proto.RegisterType((*Block)(nil), "network.Block")
	proto.RegisterType((*QuorumCert)(nil), "network.QuorumCert")
	proto.RegisterType((*Vote)(nil), "network.Vote")
	proto.RegisterType((*RequestBlock)(nil), "network.RequestBlock")
	proto.RegisterType((*RespondBlock)(nil), "network.RespondBlock")
	proto.RegisterType((*RequestChunk)(nil), "network.RequestChunk")
	proto.RegisterType((*RespondChunk)(nil), "network.RespondChunk")
}

func init() { proto.RegisterFile("consensus.proto", fileDescriptor_56f0f2c53b3de771) }

var fileDescriptor_56f0f2c53b3de771 = []byte{
	// 1002 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x56, 0x5b, 0x73, 0x1b, 0x35,
	0x14, 0x8e, 0x1d, 0xc7, 0x97, 0x53, 0x27, 0xb1, 0x95, 0x96, 0x71, 0x53, 0x3a, 0x74, 0x5c, 0x06,
	0x98, 0x32, 0x75, 0x20, 0x25, 0x6f, 0x3c, 0xc5, 0x49, 0x49, 0x86, 0xd4, 0x29, 0x72, 0x52, 0x66,
	0x78, 0xe8, 0x8e, 0xbc, 0xab, 0xd8, 0x22, 0xbb, 0xab, 0x8d, 0xa4, 0xcd, 0xa5, 0x2f, 0xfc, 0x06,
	0x78, 0xe3, 0xe7, 0xf0, 0xaf, 0xfa, 0xc8, 0xac, 0xa4, 0xbd, 0x78, 0xb1, 0xc3, 0xc0, 0x8b, 0xc7,
	0xe7, 0xea, 0xf3, 0x7d, 0xdf, 0x91, 0x64, 0xd8, 0x74, 0x79, 0x28, 0x69, 0x28, 0x63, 0x39, 0x88,
	0x04, 0x57, 0x1c, 0x35, 0x42, 0xaa, 0x6e, 0xb8, 0xb8, 0xdc, 0xee, 0xfa, 0xd4, 0x9b, 0x52, 0xe1,
	0xb0, 0xf0, 0x82, 0x9b, 0xd8, 0x76, 0x57, 0x09, 0x12, 0x4a, 0xe2, 0x2a, 0xc6, 0x43, 0xe3, 0xea,
	0xff, 0xb9, 0x0a, 0xed, 0x61, 0xda, 0xe2, 0x8d, 0x9c, 0xa2, 0x1d, 0x68, 0x46, 0x82, 0x47, 0x5c,
	0x12, 0xbf, 0x57, 0x79, 0x56, 0xf9, 0xea, 0xc1, 0x6e, 0x77, 0x60, 0x5b, 0x0e, 0xde, 0xda, 0xc0,
	0xd1, 0x0a, 0xce, 0x92, 0xd0, 0x73, 0xa8, 0x5d, 0x73, 0x45, 0x7b, 0x55, 0x9d, 0xbc, 0x9e, 0x25,
	0xbf, 0xe3, 0x8a, 0x1e, 0xad, 0x60, 0x1d, 0x44, 0xdf, 0xc3, 0xba, 0xa0, 0x57, 0x31, 0x95, 0xca,
	0x99, 0xf8, 0xdc, 0xbd, 0xec, 0xad, 0xea, 0xec, 0x47, 0x59, 0x36, 0x36, 0xd1, 0xfd, 0x24, 0x78,
	0xb4, 0x82, 0xdb, 0xa2, 0x60, 0x9b, 0x6a, 0x19, 0xf1, 0xd0, 0xb3, 0xd5, 0xb5, 0x7f, 0x54, 0xeb,
	0x68, 0xa1, 0x3a, 0xb7, 0xd1, 0x37, 0xd0, 0x0a, 0xe9, 0x8d, 0x23, 0x78, 0x1c, 0x7a, 0xbd, 0xb5,
	0x12, 0xa4, 0x11, 0xbd, 0xc1, 0x49, 0x20, 0x81, 0x14, 0xda, 0xef, 0xc5, 0x69, 0xdd, 0x59, 0x1c,
	0x5e, 0xf6, 0xea, 0x8b, 0xa7, 0x1d, 0x26, 0xc1, 0xc2, 0xb4, 0xda, 0x2e, 0x4e, 0x6b, 0xaa, 0x1b,
	0x8b, 0xa7, 0x2d, 0x54, 0xe7, 0xf6, 0x7e, 0x0b, 0x1a, 0x01, 0x95, 0x92, 0x4c, 0x69, 0xff, 0x63,
	0x05, 0x9a, 0x29, 0xe5, 0x68, 0x0f, 0x36, 0x0c, 0xe5, 0x34, 0x25, 0xc1, 0xa8, 0xb3, 0x91, 0xb5,
	0xd5, 0x68, 0xf1, 0x7a, 0x9a, 0x65, 0xc0, 0x6f, 0xa7, 0x72, 0x52, 0xa1, 0x15, 0x6a, 0xe3, 0xcc,
	0x46, 0x67, 0xb0, 0xa5, 0x58, 0x40, 0x79, 0xac, 0x9c, 0xab, 0x98, 0x8b, 0x38, 0x70, 0x5c, 0x2a,
	0x94, 0x95, 0xe6, 0xf3, 0x5c, 0x75, 0xe2, 0xd2, 0x80, 0x5c, 0x52, 0x71, 0x66, 0x92, 0x87, 0x54,
	0x28, 0x76, 0xc1, 0x5c, 0xa2, 0x28, 0xee, 0xda, 0x06, 0x3f, 0xe9, 0xfa, 0x24, 0x82, 0x86, 0xb0,
	0x35, 0x63, 0xd3, 0x59, 0x42, 0x5e, 0x61, 0x03, 0xad, 0x64, 0x5b, 0x59, 0xd7, 0xbc, 0x02, 0x77,
	0x6d, 0xfe, 0x89, 0x4e, 0x3f, 0x0e, 0x2f, 0x78, 0xff, 0x3d, 0x74, 0xca, 0x3f, 0x8b, 0x1e, 0xc2,
	0x9a, 0xd1, 0x30, 0x01, 0x5e, 0xc3, 0xc6, 0x40, 0x9f, 0x40, 0x9d, 0xc4, 0x6a, 0xc6, 0x53, 0x78,
	0xd6, 0x42, 0x9f, 0x42, 0x4b, 0xb2, 0x69, 0x48, 0x54, 0x2c, 0xa8, 0x86, 0xd4, 0xc6, 0xb9, 0xa3,
	0xff, 0x47, 0x15, 0x9a, 0xa9, 0xf4, 0xc5, 0x89, 0x8b, 0x3c, 0x54, 0xfe, 0x7d, 0xe2, 0x02, 0xec,
	0xd7, 0xd0, 0x8d, 0xd2, 0x89, 0x1d, 0xcb, 0x8a, 0x3d, 0x13, 0x8f, 0x97, 0x52, 0x89, 0x3b, 0x51,
	0x19, 0x65, 0x8e, 0x67, 0x75, 0x39, 0x9e, 0x5a, 0x09, 0xcf, 0x32, 0xd2, 0xd7, 0xfe, 0x13, 0xe9,
	0xbf, 0xc2, 0x93, 0x7b, 0xb4, 0x5e, 0xc2, 0xff, 0x1e, 0x34, 0x2d, 0x5a, 0xd9, 0xab, 0x3e, 0x5b,
	0xbd, 0x1f, 0x6e, 0x96, 0xda, 0xff, 0xbd, 0x0a, 0x6b, 0x66, 0x43, 0x37, 0xa0, 0xca, 0x4c, 0xcf,
	0x36, 0xae, 0x32, 0x0f, 0x3d, 0x81, 0x56, 0x44, 0x04, 0x0d, 0x95, 0xc3, 0xbc, 0x6c, 0x65, 0xb5,
	0xe3, 0xd8, 0x43, 0x3d, 0x68, 0x44, 0xe4, 0xce, 0xe7, 0xc4, 0xb3, 0xf4, 0xa4, 0x66, 0x3e, 0x5d,
	0xad, 0xb4, 0x1d, 0x33, 0xca, 0xa6, 0x33, 0xa5, 0xa9, 0xa8, 0x61, 0x6b, 0xa1, 0x2f, 0x61, 0x33,
	0x19, 0x45, 0x2a, 0x12, 0x44, 0x4e, 0x2c, 0xa9, 0x2b, 0xf5, 0x19, 0xaf, 0xe1, 0x8d, 0xcc, 0x7d,
	0x9e, 0x78, 0xd1, 0x77, 0xf0, 0xa0, 0xb8, 0x13, 0x8d, 0xe5, 0x84, 0xc2, 0x55, 0xbe, 0x0c, 0xb9,
	0x88, 0xcd, 0xe5, 0x22, 0xb6, 0xca, 0x4b, 0xf9, 0x57, 0x05, 0xa0, 0xb0, 0x51, 0x8f, 0xa1, 0xa9,
	0x0f, 0xba, 0x93, 0xd1, 0xd3, 0xd0, 0xf6, 0xb1, 0x97, 0x84, 0xa4, 0x22, 0x8a, 0xe6, 0x14, 0x35,
	0xb4, 0x6d, 0x18, 0xba, 0xa6, 0x42, 0x32, 0x1e, 0x6a, 0x86, 0x6a, 0x38, 0x35, 0x97, 0x30, 0xf4,
	0x06, 0x50, 0x32, 0x01, 0xf5, 0x16, 0x2c, 0xce, 0x67, 0x03, 0x75, 0x17, 0x51, 0x39, 0xc8, 0x77,
	0xe4, 0x67, 0xa6, 0x66, 0xe3, 0x74, 0x60, 0x89, 0x3b, 0xa6, 0xb4, 0xb0, 0x43, 0x1f, 0x2b, 0x50,
	0x4b, 0x6e, 0x7e, 0xf4, 0x02, 0xba, 0xf3, 0xf7, 0x55, 0x0e, 0x63, 0x73, 0xee, 0x8a, 0x3a, 0xf6,
	0x92, 0x5c, 0x7a, 0x4b, 0xdd, 0x58, 0x51, 0xcf, 0x29, 0xe1, 0xda, 0x4c, 0x03, 0xe3, 0xff, 0x89,
	0x2f, 0x97, 0x62, 0x6d, 0x4e, 0x8a, 0x5d, 0x78, 0x50, 0x04, 0x5c, 0xb7, 0xef, 0x42, 0x19, 0x30,
	0x06, 0x3f, 0xfb, 0x3e, 0x2f, 0x5f, 0xa3, 0x2c, 0xdf, 0x11, 0xb4, 0x8b, 0xaf, 0xd8, 0x7d, 0xfa,
	0x3d, 0x05, 0x08, 0xe3, 0xc0, 0xf0, 0x22, 0x35, 0xd2, 0x1a, 0x6e, 0x85, 0x71, 0xa0, 0x0b, 0x65,
	0x3f, 0x48, 0x3a, 0x15, 0x5e, 0xb0, 0x3d, 0xa8, 0x27, 0xb4, 0xc4, 0x52, 0xf7, 0xd9, 0xd8, 0x7d,
	0x5a, 0xba, 0xf3, 0xa9, 0x12, 0x8c, 0x5e, 0x13, 0x7f, 0xac, 0x93, 0xb0, 0x4d, 0x46, 0x5f, 0x40,
	0x3d, 0xfb, 0x85, 0xd5, 0x05, 0x4f, 0x85, 0x8d, 0xf6, 0x7f, 0xcb, 0x06, 0x37, 0x0f, 0xd8, 0x73,
	0x58, 0x97, 0x8a, 0x08, 0xe5, 0xa4, 0x44, 0x9b, 0x03, 0xdf, 0xd6, 0xce, 0x77, 0x96, 0xed, 0xaf,
	0xa1, 0xae, 0x88, 0x98, 0xd2, 0xf4, 0x92, 0x5b, 0x78, 0x26, 0x6c, 0x4a, 0x82, 0x77, 0x42, 0x94,
	0x3b, 0x73, 0x24, 0xfb, 0x40, 0xad, 0x6e, 0x2d, 0xed, 0x19, 0xb3, 0x0f, 0xb4, 0xff, 0x3e, 0xc3,
	0x6b, 0x06, 0x18, 0xc1, 0x96, 0xba, 0x0d, 0x1d, 0x9f, 0x49, 0xe5, 0xdc, 0x30, 0x35, 0x73, 0x22,
	0xc1, 0xf9, 0x85, 0xbd, 0x90, 0xd3, 0xa5, 0x3c, 0xcb, 0xff, 0xcb, 0x9c, 0x30, 0xa9, 0x92, 0xcd,
	0x7c, 0x9b, 0xa4, 0xe1, 0x8e, 0xba, 0x9d, 0xf7, 0xbc, 0x18, 0xc1, 0xc3, 0x45, 0x44, 0xa1, 0x75,
	0x68, 0x8d, 0xcf, 0x87, 0xc3, 0xc3, 0xc3, 0x83, 0xc3, 0x83, 0xce, 0x0a, 0xea, 0x40, 0xfb, 0xf8,
	0xc0, 0x19, 0x9d, 0x9e, 0x39, 0xaf, 0x4f, 0xcf, 0x47, 0x07, 0x9d, 0x0a, 0x7a, 0x04, 0xdd, 0xc4,
	0x3c, 0x1c, 0x9d, 0x9e, 0xff, 0x70, 0xe4, 0xec, 0x9f, 0x9c, 0x0e, 0x7f, 0x1c, 0x77, 0xaa, 0xfb,
	0xaf, 0x7e, 0xf9, 0x76, 0xca, 0xd4, 0x2c, 0x9e, 0x0c, 0x5c, 0x1e, 0xec, 0xb0, 0x20, 0x88, 0x15,
	0x99, 0x30, 0x9f, 0xa9, 0xbb, 0x97, 0x8c, 0xef, 0x5c, 0x93, 0xd8, 0x57, 0x2f, 0x7d, 0x36, 0x11,
	0x64, 0xc7, 0x7c, 0x4e, 0x45, 0xe4, 0x4e, 0xea, 0xfa, 0x0f, 0xd7, 0xab, 0xbf, 0x03, 0x00, 0x00,
	0xff, 0xff, 0xe4, 0xe0, 0xa5, 0x74, 0xb2, 0x09, 0x00, 0x00,
}
