package shfe

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestLoginRequest(t *testing.T) {
	MSG := []byte{0x01, 0x11, 0x9B, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x97, 0x00, 0x30, 0x30, 0x37, 0x30, 0x63, 0x32, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x53, 0x48, 0x46, 0x45, 0x20, 0x41, 0x50,
		0x49, 0x54, 0x45, 0x53, 0x54, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x53, 0x48, 0x46, 0x45, 0x20, 0x55, 0x73, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("login request decode error", err)
	}
	if r.Name != "MDQPLoginRequest" {
		t.Error("invalid message type")
	}
	data, ok := r.Data.(*LoginRequest)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.UserID != "0070c2c" {
		t.Error("decode UserID field error")
	}

	if data.ParticipantID != "0070" {
		t.Error("decode ParticipantID field error")
	}

	if data.Password != "1" {
		t.Error("decode Password field error")
	}

	if data.Language != "0" {
		t.Error("decode Language field error")
	}

	if data.UserProductInfo != "SHFE APITESTER" {
		t.Error("decode UserProductInfo field error")

	}

	if data.InterfaceProductInfo != "SHFE User" {
		t.Error("decode InterfaceProductInfo field error")

	}
	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Login Request:\n%s\n", dataString)

}

func TestLoginResponse(t *testing.T) {
	MSG := []byte{0x01, 0x12, 0xD0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xD5, 0xFD, 0xC8, 0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x73, 0x00, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x31, 0x32, 0x00, 0x32, 0x31,
		0x3A, 0x30, 0x30, 0x3A, 0x31, 0x35, 0x00, 0x30, 0x30, 0x37, 0x30, 0x63, 0x32, 0x63, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x53, 0x48, 0x46, 0x45, 0x20, 0x4D, 0x61, 0x72, 0x6B, 0x65, 0x74, 0x20, 0x44, 0x61,
		0x74, 0x61, 0x20, 0x50, 0x6C, 0x61, 0x74, 0x66, 0x6F, 0x72, 0x6D, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32,
		0x30, 0x31, 0x32, 0x30, 0x31, 0x31, 0x31, 0x00}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("login response decode error", err)
	}
	if r.Name != "MDQPLoginResponse" {
		t.Error("invalid message type")
	}
	data, ok := r.Data.(*LoginResponse)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.ErrID != 0 {
		t.Error("decode ErrID field error")
	}

	if data.UserID != "0070c2c" {
		t.Error("decode UserID field error")
	}

	if data.ParticipantID != "0070" {
		t.Error("decode ParticipantID field error")
	}

	if data.LoginTime != "21:00:15" {
		t.Error("decode LoginTime field error")
	}

	if data.TradingDay != "20120112" {
		t.Error("decode ActionDay field error")
	}

	if data.ActionDay != "20120111" {
		t.Error("decode ActionDay field error")
	}
	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Login Response:\n%s\n", dataString)
}

func TestLogoutRequest(t *testing.T) {
	MSG := []byte{0x01, 0x13, 0x1F, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x04, 0x00, 0x1B, 0x00, 0x30, 0x30, 0x37, 0x30, 0x63, 0x32, 0x63, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("logout request decode error", err)
	}
	if r.Name != "MDQPLogoutRequest" {
		t.Error("invalid message type")
	}
	data, ok := r.Data.(*LogoutRequest)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.UserID != "0070c2c" {
		t.Error("decode UserID field error")
	}

	if data.ParticipantID != "0070" {
		t.Error("decode ParticipantID field error")
	}
	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Logout Request:\n%s\n", dataString)
}

func TestLogoutResponse(t *testing.T) {
	MSG := []byte{0x01, 0x14, 0x78, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xD5, 0xFD, 0xC8, 0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x05, 0x00, 0x1B, 0x00, 0x30, 0x30, 0x37, 0x30, 0x63, 0x32, 0x63, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x37, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("logout response decode error", err)
	}
	if r.Name != "MDQPLogoutResponse" {
		t.Error("invalid message type")
	}
	data, ok := r.Data.(*LogoutResponse)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.ErrID != 0 {
		t.Error("decode ErrID field error")
	}

	if data.UserID != "0070c2c" {
		t.Error("decode UserID field error")
	}

	if data.ParticipantID != "0070" {
		t.Error("decode ParticipantID field error")
	}
	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Logout Response:\n%s\n", dataString)
}

func TestSnapshotRequest(t *testing.T) {
	MSG := []byte{0x01, 0x31, 0x0A, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x10, 0x06, 0x00, 0xE9, 0x03, 0xFF, 0xFF, 0xFF, 0xFF}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("snapshot request decode error", err)
	}
	if r.Name != "MDQPSnapshotRequest" {
		t.Error("invalid message type:", r.Name)
	}
	data, ok := r.Data.(*SnapshotRequest)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.TopicID != 1001 {
		t.Error("decode topicID field error")
	}

	if data.SnapNo != -1 {
		t.Error("decode SnapNo field error")
	}

	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Snapshot Request:\n%s\n", dataString)
}

func TestSnapshotResponse(t *testing.T) {
	MSG := []byte{0x11, 0x32, 0xD1, 0x04, 0x02, 0x00, 0x00, 0x00,
		0x32, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
		0x32, 0x00, 0x09, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
		0x31, 0x00, 0x16, 0x00, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x31, 0x32, 0x00, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x31, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x06, 0x00, 0xE9, 0x03,
		0x01, 0x00, 0x00, 0x00, 0x03, 0x10, 0x25, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x16,
		0x00, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x31, 0x31, 0x00, 0x32, 0x31, 0x3A, 0x30, 0x30, 0x3A,
		0x30, 0x37, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x04, 0x10, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x01, 0x70, 0x00, 0x61, 0x6C, 0x31, 0x32, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x61, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x30, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x43, 0x4E, 0x59, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xD1, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x01, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x94, 0xD1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x40, 0x8F, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x48, 0xD2, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xD0, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x94, 0xD1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0xD1, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x40, 0x8F, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x31, 0x31, 0x00,
		0x32, 0x31, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x37, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x01, 0x01, 0x70, 0x00, 0x61, 0x6C, 0x31, 0x32, 0x30, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x61, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x30, 0x05, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x43, 0x4E, 0x59,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x9C, 0xD1,
		0x40, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x9A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xC0, 0x9C, 0xD1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x8F, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF,
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF,
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF,
		0x7F, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x50, 0xD2, 0x40, 0x00, 0x00, 0x00, 0x00, 0x80, 0xE7, 0xD0,
		0x40, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x9C, 0xD1, 0x40, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x9C, 0xD1,
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x8F, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF,
		0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x32, 0x30, 0x31, 0x32, 0x30, 0x31, 0x31,
		0x31, 0x00, 0x32, 0x31, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x37, 0x00, 0xF4, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01, 0x01, 0x70, 0x00, 0x61, 0x6C, 0x31, 0x32, 0x30, 0x33, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x30, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x43,
		0x4E, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xEF, 0xD0, 0x40, 0x02, 0x00, 0x00, 0x00, 0x02, 0x01, 0x9A, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xEF, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xEF, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x80, 0x9B, 0xD1, 0x40, 0x00, 0x00, 0x00, 0x00, 0x40,
		0x41, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xEF, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x32, 0x30, 0x31, 0x32, 0x30,
		0x31, 0x31, 0x31, 0x00, 0x32, 0x31, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x37, 0x00, 0xF4, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x70, 0x00, 0x61, 0x6C, 0x31, 0x32, 0x30, 0x34, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F,
		0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, 0x01, 0x00, 0x00,
		0x00, 0x43, 0x4E, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x9A, 0xD0, 0x40, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x9A, 0x00, 0x03, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9A, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xB2, 0x40, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0xD1, 0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xE0, 0xCF, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9A, 0xD0, 0x40, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x9A, 0xD0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xB2, 0x40, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEF, 0x7F, 0x32, 0x30, 0x31,
		0x32, 0x30, 0x31, 0x31, 0x31, 0x00, 0x32, 0x31, 0x3A, 0x30, 0x30, 0x3A, 0x30, 0x37, 0x00, 0xF4,
		0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}

	r, err := DecodeMDQP(MSG)

	if err != nil {
		t.Error("snapshot response decode error: ", err)
	}
	if r.Name != "MDQPSnapshotResponse" {
		t.Error("invalid message type:", r.Name)
	}
	data, ok := r.Data.(*SnapshotResponse)
	if !ok {
		t.Error("error in MDQP data type")
	}

	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Snapshot Response:\n%s\n", dataString)

}

func TestIncrRequest(t *testing.T) {
	MSG := []byte{0x01, 0x33, 0x0E, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x0A, 0x00, 0xE9, 0x03, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("Incr request decode error", err)
	}
	if r.Name != "MDQPIncrRequest" {
		t.Error("invalid message type:", r.Name)
	}
	data, ok := r.Data.(*IncrRequest)
	if !ok {
		t.Error("error in MDQP data type")
	}

	if data.TopicID != 1001 {
		t.Error("decode topicID field error")
	}

	if data.StartPktNo != 1 {
		t.Error("decode SnapNo field error")
	}

	if data.EndPktNo != 10 {
		t.Error("decode SnapNo field error")
	}

	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Incr Request:\n%s\n", dataString)
}

func TestIncrResponse(t *testing.T) {
	MSG := []byte{0x01, 0x34, 0xF4, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x01, 0x01, 0xD8, 0x00,
		0x01, 0x00, 0x00, 0x00, 0xE9, 0x03, 0xF4, 0x01, 0x01, 0x00, 0x00, 0x00, 0x6E, 0x86, 0x0D, 0x4F,
		0xB4, 0x2D, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x02, 0x15, 0x10, 0x02, 0x00, 0xA0, 0x02,
		0x16, 0x10, 0x02, 0x00, 0x9F, 0x02, 0x03, 0x00, 0x02, 0x00, 0x02, 0x02, 0x15, 0x10, 0x02, 0x00,
		0xA0, 0x02, 0x16, 0x10, 0x02, 0x00, 0xA1, 0x02, 0x03, 0x00, 0x02, 0x00, 0x04, 0x02, 0x15, 0x10,
		0x02, 0x00, 0x94, 0x02, 0x16, 0x10, 0x02, 0x00, 0x95, 0x02, 0x03, 0x00, 0x02, 0x00, 0x06, 0x02,
		0x15, 0x10, 0x02, 0x00, 0x90, 0x02, 0x16, 0x10, 0x02, 0x00, 0x8F, 0x02, 0x03, 0x00, 0x02, 0x00,
		0x08, 0x02, 0x15, 0x10, 0x02, 0x00, 0x8E, 0x02, 0x16, 0x10, 0x02, 0x00, 0x8F, 0x02, 0x03, 0x00,
		0x02, 0x00, 0x0A, 0x02, 0x15, 0x10, 0x02, 0x00, 0x8A, 0x02, 0x16, 0x10, 0x02, 0x00, 0x8B, 0x02,
		0x03, 0x00, 0x02, 0x00, 0x0C, 0x02, 0x15, 0x10, 0x02, 0x00, 0x96, 0x04, 0x16, 0x10, 0x02, 0x00,
		0x97, 0x04, 0x03, 0x00, 0x02, 0x00, 0x0E, 0x02, 0x15, 0x10, 0x02, 0x00, 0x96, 0x04, 0x16, 0x10,
		0x02, 0x00, 0x97, 0x04, 0x03, 0x00, 0x02, 0x00, 0x10, 0x02, 0x15, 0x10, 0x02, 0x00, 0x86, 0x02,
		0x16, 0x10, 0x02, 0x00, 0x87, 0x02, 0x03, 0x00, 0x02, 0x00, 0x12, 0x02, 0x15, 0x10, 0x02, 0x00,
		0x84, 0x02, 0x16, 0x10, 0x02, 0x00, 0x85, 0x02, 0x03, 0x00, 0x02, 0x00, 0x14, 0x02, 0x15, 0x10,
		0x02, 0x00, 0x88, 0x04, 0x16, 0x10, 0x02, 0x00, 0x89, 0x04, 0x03, 0x00, 0x02, 0x00, 0x16, 0x02,
		0x15, 0x10, 0x02, 0x00, 0x90, 0x02, 0x16, 0x10, 0x02, 0x00, 0x8F, 0x02}

	r, err := DecodeMDQP(MSG)
	if err != nil {
		t.Error("Incr response decode error", err)
	}
	if r.Name != "MDQPIncrResponse" {
		t.Error("invalid message type:", r.Name)
	}
	data, ok := r.Data.(*IncrResponse)
	if !ok {
		t.Error("error in MDQP data type")
	}

	dataString, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		t.Error("json marshal error:", err)
	}
	fmt.Printf("Incr Response:\n%s\n", dataString)
}