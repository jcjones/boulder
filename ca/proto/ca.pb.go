// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.6
// source: ca.proto

package proto

import (
	proto "github.com/letsencrypt/boulder/core/proto"
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

type IssueCertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Csr            []byte `protobuf:"bytes,1,opt,name=csr,proto3" json:"csr,omitempty"`
	RegistrationID int64  `protobuf:"varint,2,opt,name=registrationID,proto3" json:"registrationID,omitempty"`
	OrderID        int64  `protobuf:"varint,3,opt,name=orderID,proto3" json:"orderID,omitempty"`
	IssuerNameID   int64  `protobuf:"varint,4,opt,name=issuerNameID,proto3" json:"issuerNameID,omitempty"`
}

func (x *IssueCertificateRequest) Reset() {
	*x = IssueCertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ca_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssueCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueCertificateRequest) ProtoMessage() {}

func (x *IssueCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ca_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueCertificateRequest.ProtoReflect.Descriptor instead.
func (*IssueCertificateRequest) Descriptor() ([]byte, []int) {
	return file_ca_proto_rawDescGZIP(), []int{0}
}

func (x *IssueCertificateRequest) GetCsr() []byte {
	if x != nil {
		return x.Csr
	}
	return nil
}

func (x *IssueCertificateRequest) GetRegistrationID() int64 {
	if x != nil {
		return x.RegistrationID
	}
	return 0
}

func (x *IssueCertificateRequest) GetOrderID() int64 {
	if x != nil {
		return x.OrderID
	}
	return 0
}

func (x *IssueCertificateRequest) GetIssuerNameID() int64 {
	if x != nil {
		return x.IssuerNameID
	}
	return 0
}

type IssuePrecertificateResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DER []byte `protobuf:"bytes,1,opt,name=DER,proto3" json:"DER,omitempty"`
}

func (x *IssuePrecertificateResponse) Reset() {
	*x = IssuePrecertificateResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ca_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssuePrecertificateResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssuePrecertificateResponse) ProtoMessage() {}

func (x *IssuePrecertificateResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ca_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssuePrecertificateResponse.ProtoReflect.Descriptor instead.
func (*IssuePrecertificateResponse) Descriptor() ([]byte, []int) {
	return file_ca_proto_rawDescGZIP(), []int{1}
}

func (x *IssuePrecertificateResponse) GetDER() []byte {
	if x != nil {
		return x.DER
	}
	return nil
}

type IssueCertificateForPrecertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DER            []byte   `protobuf:"bytes,1,opt,name=DER,proto3" json:"DER,omitempty"`
	SCTs           [][]byte `protobuf:"bytes,2,rep,name=SCTs,proto3" json:"SCTs,omitempty"`
	RegistrationID int64    `protobuf:"varint,3,opt,name=registrationID,proto3" json:"registrationID,omitempty"`
	OrderID        int64    `protobuf:"varint,4,opt,name=orderID,proto3" json:"orderID,omitempty"`
}

func (x *IssueCertificateForPrecertificateRequest) Reset() {
	*x = IssueCertificateForPrecertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ca_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IssueCertificateForPrecertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueCertificateForPrecertificateRequest) ProtoMessage() {}

func (x *IssueCertificateForPrecertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ca_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueCertificateForPrecertificateRequest.ProtoReflect.Descriptor instead.
func (*IssueCertificateForPrecertificateRequest) Descriptor() ([]byte, []int) {
	return file_ca_proto_rawDescGZIP(), []int{2}
}

func (x *IssueCertificateForPrecertificateRequest) GetDER() []byte {
	if x != nil {
		return x.DER
	}
	return nil
}

func (x *IssueCertificateForPrecertificateRequest) GetSCTs() [][]byte {
	if x != nil {
		return x.SCTs
	}
	return nil
}

func (x *IssueCertificateForPrecertificateRequest) GetRegistrationID() int64 {
	if x != nil {
		return x.RegistrationID
	}
	return 0
}

func (x *IssueCertificateForPrecertificateRequest) GetOrderID() int64 {
	if x != nil {
		return x.OrderID
	}
	return 0
}

// Exactly one of certDER or [serial and issuerID] must be set.
type GenerateOCSPRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// TODO(#5079): Remove certDER field.
	CertDER   []byte `protobuf:"bytes,1,opt,name=certDER,proto3" json:"certDER,omitempty"`
	Status    string `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	Reason    int32  `protobuf:"varint,3,opt,name=reason,proto3" json:"reason,omitempty"`
	RevokedAt int64  `protobuf:"varint,4,opt,name=revokedAt,proto3" json:"revokedAt,omitempty"`
	Serial    string `protobuf:"bytes,5,opt,name=serial,proto3" json:"serial,omitempty"`
	IssuerID  int64  `protobuf:"varint,6,opt,name=issuerID,proto3" json:"issuerID,omitempty"`
}

func (x *GenerateOCSPRequest) Reset() {
	*x = GenerateOCSPRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ca_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateOCSPRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateOCSPRequest) ProtoMessage() {}

func (x *GenerateOCSPRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ca_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateOCSPRequest.ProtoReflect.Descriptor instead.
func (*GenerateOCSPRequest) Descriptor() ([]byte, []int) {
	return file_ca_proto_rawDescGZIP(), []int{3}
}

func (x *GenerateOCSPRequest) GetCertDER() []byte {
	if x != nil {
		return x.CertDER
	}
	return nil
}

func (x *GenerateOCSPRequest) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

func (x *GenerateOCSPRequest) GetReason() int32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

func (x *GenerateOCSPRequest) GetRevokedAt() int64 {
	if x != nil {
		return x.RevokedAt
	}
	return 0
}

func (x *GenerateOCSPRequest) GetSerial() string {
	if x != nil {
		return x.Serial
	}
	return ""
}

func (x *GenerateOCSPRequest) GetIssuerID() int64 {
	if x != nil {
		return x.IssuerID
	}
	return 0
}

type OCSPResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Response []byte `protobuf:"bytes,1,opt,name=response,proto3" json:"response,omitempty"`
}

func (x *OCSPResponse) Reset() {
	*x = OCSPResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ca_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OCSPResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OCSPResponse) ProtoMessage() {}

func (x *OCSPResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ca_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OCSPResponse.ProtoReflect.Descriptor instead.
func (*OCSPResponse) Descriptor() ([]byte, []int) {
	return file_ca_proto_rawDescGZIP(), []int{4}
}

func (x *OCSPResponse) GetResponse() []byte {
	if x != nil {
		return x.Response
	}
	return nil
}

var File_ca_proto protoreflect.FileDescriptor

var file_ca_proto_rawDesc = []byte{
	0x0a, 0x08, 0x63, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x63, 0x61, 0x1a, 0x15,
	0x63, 0x6f, 0x72, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x91, 0x01, 0x0a, 0x17, 0x49, 0x73, 0x73, 0x75, 0x65, 0x43,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x63, 0x73, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x63, 0x73, 0x72, 0x12, 0x26, 0x0a, 0x0e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x72, 0x65, 0x67,
	0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x44, 0x12, 0x18, 0x0a, 0x07, 0x6f,
	0x72, 0x64, 0x65, 0x72, 0x49, 0x44, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x6f, 0x72,
	0x64, 0x65, 0x72, 0x49, 0x44, 0x12, 0x22, 0x0a, 0x0c, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x4e,
	0x61, 0x6d, 0x65, 0x49, 0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0c, 0x69, 0x73, 0x73,
	0x75, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x49, 0x44, 0x22, 0x2f, 0x0a, 0x1b, 0x49, 0x73, 0x73,
	0x75, 0x65, 0x50, 0x72, 0x65, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x44, 0x45, 0x52, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x44, 0x45, 0x52, 0x22, 0x92, 0x01, 0x0a, 0x28, 0x49,
	0x73, 0x73, 0x75, 0x65, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x46,
	0x6f, 0x72, 0x50, 0x72, 0x65, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x44, 0x45, 0x52, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x44, 0x45, 0x52, 0x12, 0x12, 0x0a, 0x04, 0x53, 0x43, 0x54,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x04, 0x53, 0x43, 0x54, 0x73, 0x12, 0x26, 0x0a,
	0x0e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x44, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x49, 0x44, 0x12, 0x18, 0x0a, 0x07, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x49, 0x44,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x49, 0x44, 0x22,
	0xb1, 0x01, 0x0a, 0x13, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4f, 0x43, 0x53, 0x50,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x65, 0x72, 0x74, 0x44,
	0x45, 0x52, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x65, 0x72, 0x74, 0x44, 0x45,
	0x52, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x41, 0x74, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x69, 0x73, 0x73, 0x75, 0x65,
	0x72, 0x49, 0x44, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x69, 0x73, 0x73, 0x75, 0x65,
	0x72, 0x49, 0x44, 0x22, 0x2a, 0x0a, 0x0c, 0x4f, 0x43, 0x53, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32,
	0x92, 0x02, 0x0a, 0x14, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x55, 0x0a, 0x13, 0x49, 0x73, 0x73, 0x75,
	0x65, 0x50, 0x72, 0x65, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12,
	0x1b, 0x2e, 0x63, 0x61, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x63,
	0x61, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x50, 0x72, 0x65, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12,
	0x66, 0x0a, 0x21, 0x49, 0x73, 0x73, 0x75, 0x65, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x50, 0x72, 0x65, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x12, 0x2c, 0x2e, 0x63, 0x61, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x43,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x50, 0x72, 0x65,
	0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x11, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x22, 0x00, 0x12, 0x3b, 0x0a, 0x0c, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x4f, 0x43, 0x53, 0x50, 0x12, 0x17, 0x2e, 0x63, 0x61, 0x2e, 0x47, 0x65, 0x6e,
	0x65, 0x72, 0x61, 0x74, 0x65, 0x4f, 0x43, 0x53, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x10, 0x2e, 0x63, 0x61, 0x2e, 0x4f, 0x43, 0x53, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x22, 0x00, 0x32, 0x4c, 0x0a, 0x0d, 0x4f, 0x43, 0x53, 0x50, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x6f, 0x72, 0x12, 0x3b, 0x0a, 0x0c, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74,
	0x65, 0x4f, 0x43, 0x53, 0x50, 0x12, 0x17, 0x2e, 0x63, 0x61, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72,
	0x61, 0x74, 0x65, 0x4f, 0x43, 0x53, 0x50, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x10,
	0x2e, 0x63, 0x61, 0x2e, 0x4f, 0x43, 0x53, 0x50, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6c, 0x65, 0x74, 0x73, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2f, 0x62, 0x6f, 0x75,
	0x6c, 0x64, 0x65, 0x72, 0x2f, 0x63, 0x61, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ca_proto_rawDescOnce sync.Once
	file_ca_proto_rawDescData = file_ca_proto_rawDesc
)

func file_ca_proto_rawDescGZIP() []byte {
	file_ca_proto_rawDescOnce.Do(func() {
		file_ca_proto_rawDescData = protoimpl.X.CompressGZIP(file_ca_proto_rawDescData)
	})
	return file_ca_proto_rawDescData
}

var file_ca_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_ca_proto_goTypes = []interface{}{
	(*IssueCertificateRequest)(nil),                  // 0: ca.IssueCertificateRequest
	(*IssuePrecertificateResponse)(nil),              // 1: ca.IssuePrecertificateResponse
	(*IssueCertificateForPrecertificateRequest)(nil), // 2: ca.IssueCertificateForPrecertificateRequest
	(*GenerateOCSPRequest)(nil),                      // 3: ca.GenerateOCSPRequest
	(*OCSPResponse)(nil),                             // 4: ca.OCSPResponse
	(*proto.Certificate)(nil),                        // 5: core.Certificate
}
var file_ca_proto_depIdxs = []int32{
	0, // 0: ca.CertificateAuthority.IssuePrecertificate:input_type -> ca.IssueCertificateRequest
	2, // 1: ca.CertificateAuthority.IssueCertificateForPrecertificate:input_type -> ca.IssueCertificateForPrecertificateRequest
	3, // 2: ca.CertificateAuthority.GenerateOCSP:input_type -> ca.GenerateOCSPRequest
	3, // 3: ca.OCSPGenerator.GenerateOCSP:input_type -> ca.GenerateOCSPRequest
	1, // 4: ca.CertificateAuthority.IssuePrecertificate:output_type -> ca.IssuePrecertificateResponse
	5, // 5: ca.CertificateAuthority.IssueCertificateForPrecertificate:output_type -> core.Certificate
	4, // 6: ca.CertificateAuthority.GenerateOCSP:output_type -> ca.OCSPResponse
	4, // 7: ca.OCSPGenerator.GenerateOCSP:output_type -> ca.OCSPResponse
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ca_proto_init() }
func file_ca_proto_init() {
	if File_ca_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ca_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssueCertificateRequest); i {
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
		file_ca_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssuePrecertificateResponse); i {
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
		file_ca_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IssueCertificateForPrecertificateRequest); i {
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
		file_ca_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateOCSPRequest); i {
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
		file_ca_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OCSPResponse); i {
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
			RawDescriptor: file_ca_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   2,
		},
		GoTypes:           file_ca_proto_goTypes,
		DependencyIndexes: file_ca_proto_depIdxs,
		MessageInfos:      file_ca_proto_msgTypes,
	}.Build()
	File_ca_proto = out.File
	file_ca_proto_rawDesc = nil
	file_ca_proto_goTypes = nil
	file_ca_proto_depIdxs = nil
}
