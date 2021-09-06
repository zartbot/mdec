package shfe

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/zartbot/mdec/exats"
	"github.com/zartbot/mdec/sink"
)

type MirpHdr struct {
	Flag           uint8
	TypeID         uint8
	Length         uint16
	PacketNo       int32
	TopicID        int16
	SnapMillisec   uint16
	SnapNo         int32
	SnapTime       uint32
	CommPhaseNo    uint16
	CenterChangeNo int8
}

type MirpMsg struct {
	Hdr  *MirpHdr
	Data []*MIRPField
}

func DecodeMIRP(pkt []byte) (*MirpMsg, error) {

	result := &MirpMsg{
		Data: make([]*MIRPField, 0),
	}
	pktLen := len(pkt)

	if pktLen <= 24 {
		return result, fmt.Errorf("invalid length")
	}
	result.Hdr = &MirpHdr{
		Flag:           pkt[0],
		TypeID:         pkt[1],
		Length:         binary.LittleEndian.Uint16(pkt[2:4]),
		PacketNo:       int32(binary.LittleEndian.Uint32(pkt[4:8])),
		TopicID:        int16(binary.LittleEndian.Uint16(pkt[8:10])),
		SnapMillisec:   binary.LittleEndian.Uint16(pkt[10:12]),
		SnapNo:         int32(binary.LittleEndian.Uint32(pkt[12:16])),
		SnapTime:       binary.LittleEndian.Uint32(pkt[16:20]),
		CommPhaseNo:    binary.LittleEndian.Uint16(pkt[20:22]),
		CenterChangeNo: int8(pkt[22]),
	}

	start := int(24)
	for start < pktLen-4 {
		f := DecodeMIRPField(pkt[start:])
		result.Data = append(result.Data, f)
		start = start + int(f.Size) + 4

	}

	return result, nil
}

type MIRPField struct {
	ID    int16
	Name  string
	Size  int16
	Value interface{}
}

func DecodeMIRPField(pkt []byte) *MIRPField {
	result := &MIRPField{
		ID:   int16(binary.LittleEndian.Uint16(pkt[0:2])),
		Size: int16(binary.LittleEndian.Uint16(pkt[2:4])),
	}

	switch result.ID {
	case 0x0003:
		//0x0003:MIRPInstrumentInfo
		result.Name = "MIRPInstrumentInfo"
		result.Value = DecodeMIRPInstrumentInfo(pkt[4 : 4+result.Size])
	case 0x1001:
		//0x1001: MIRPPriceChangeField
		result.Name = "MIRPPriceChange"
		result.Value = DecodeMIRPPriceChangeEvent(pkt[4 : 4+result.Size])
	case 0x1002:
		//0x1002: MIRPVolumeChangeField
		result.Name = "MIRPVolumeChange"
		result.Value = DecodeMIRPVolumeChangeEvent(pkt[4 : 4+result.Size])
	case 0x1011:
		//0x1011(4113):MIRPHighPriceOffset
		result.Name = "MIRPHighPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1012:
		//0x1012(4114):MIRPLowPriceOffset
		result.Name = "MIRPLowPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1013:
		//0x1013(4115):MIRPOpenPriceOffset
		result.Name = "MIRPOpenPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1014:
		//0x1014(4116):MIRPClosePriceOffset
		result.Name = "MIRPClosePriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1015:
		//0x1015(4117):MIRPUpperLimitPriceOffset
		result.Name = "MIRPUpperLimitPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1016:
		//0x1016(4118):MIRPLowerLimitPriceOffset
		result.Name = "MIRPLowerLimitPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1017:
		//0x1017(4119):MIRPSettlementPriceOffset
		result.Name = "MIRPSettlementPriceOffset"
		v, n := binary.Varint(pkt[4 : 4+result.Size])
		if n > 0 {
			result.Value = v
		}
	case 0x1018:
		//0x1018(4120):Delta
		if result.Size == 8 {
			bits := binary.LittleEndian.Uint64(pkt[4:12])
			result.Value = math.Float64frombits(bits)
		}
	}

	return result
}

type MIRPInstrumentInfo struct {
	Code     int64
	ChangeNo int64
}

func DecodeMIRPInstrumentInfo(data []byte) *MIRPInstrumentInfo {

	r := &MIRPInstrumentInfo{}
	v, n := binary.Varint(data)
	if n > 0 {
		r.Code = v
		r.ChangeNo, _ = binary.Varint(data[n:])
	}

	return r
}

type MIRPPriceChangeEvent struct {
	EventType   string
	MDEntryType string
	PriceLevel  int64
	PriceOffset int64
	Volume      int64
}

func DecodeMIRPPriceChangeEvent(data []byte) *MIRPPriceChangeEvent {

	r := &MIRPPriceChangeEvent{}

	switch data[0] {
	case '1':
		r.EventType = "add"
	case '2':
		r.EventType = "modify"
	case '3':
		r.EventType = "del"
	}

	switch data[1] {
	case '0':
		r.MDEntryType = "bid"
	case '1':
		r.MDEntryType = "ask"
	}

	v, n1 := binary.Varint(data[2:])
	if n1 < 0 {
		return r
	}
	r.PriceLevel = v
	v, n2 := binary.Varint(data[2+n1:])
	if n2 < 0 {
		return r
	}
	r.PriceOffset = v

	v, n3 := binary.Varint(data[2+n1+n2:])
	if n3 < 0 {
		return r
	}
	r.Volume = v

	return r
}

type MIRPVolumeChangeEvent struct {
	LastPriceOffset    int64
	MIRPVolumeChange   int64
	TurnoverOffset     int64
	OpenInterestChange int64
}

func DecodeMIRPVolumeChangeEvent(data []byte) *MIRPVolumeChangeEvent {

	r := &MIRPVolumeChangeEvent{}

	offset := int(0)
	v, n := binary.Varint(data[offset:])
	if n < 0 {
		return r
	}
	offset += n
	r.LastPriceOffset = v

	v, n = binary.Varint(data[offset:])
	if n < 0 {
		return r
	}
	offset += n
	r.MIRPVolumeChange = v

	v, n = binary.Varint(data[offset:])
	if n < 0 {
		return r
	}
	offset += n
	r.TurnoverOffset = v

	v, n = binary.Varint(data[offset:])
	if n < 0 {
		return r
	}
	r.OpenInterestChange = v
	return r
}

func MIRPDecodeAndSink(data []byte, ds chan *sink.DataStream, ts time.Time, hpt *exats.HPT, src, dst string) {

	msg, err := DecodeMIRP(data)
	if err != nil {
		return
	}

	exportRecord := sink.NewDataStream(1, "mirp", "local")
	exportRecord.TimeStamp = ts.UnixNano()
	exportRecord.RecordMap["CreateAt"] = ts

	if hpt != nil {
		exportRecord.RecordMap["picoSecond"] = hpt.TimeStamp.PicoSeconds
		exportRecord.RecordMap["picoEpoch"] = hpt.TimeStamp.Epoch
	}
	exportRecord.RecordMap["flowSrc"] = src
	exportRecord.RecordMap["flowDst"] = dst
	exportRecord.RecordMap["Hdr"] = msg.Hdr

	mdr := sink.NewDataStream(1, "mdr", "local")
	for idx, v := range msg.Data {
		//merge recode with field
		if v.ID == 0x0003 {
			//flush cache
			if idx != 0 {
				ds <- mdr
			}
			//build new cache
			field := v.Value.(*MIRPInstrumentInfo)
			mdr = sink.NewDataStream(1, fmt.Sprintf("mdr-%d", field.Code), "local")
			mdr.TimeStamp = ts.UnixNano()
			mdr.RecordMap["CreateAt"] = ts

			if hpt != nil {
				mdr.RecordMap["picoSecond"] = hpt.TimeStamp.PicoSeconds
				mdr.RecordMap["picoEpoch"] = hpt.TimeStamp.Epoch
			}
			mdr.RecordMap["flowSrc"] = src
			mdr.RecordMap["flowDst"] = dst
			mdr.RecordMap["ChangeNo"] = field.ChangeNo
		}
		if v.ID == 0x1001 {
			field := v.Value.(*MIRPPriceChangeEvent)
			key := fmt.Sprintf("%s_%s_level_%d_offset_%d", field.MDEntryType, field.EventType, field.PriceLevel, field.PriceOffset)
			mdr.RecordMap[key] = field.Volume
		}
		if v.ID == 0x1002 {
			field := v.Value.(*MIRPVolumeChangeEvent)
			key := fmt.Sprintf("%d", field.LastPriceOffset)
			mdr.RecordMap[key] = field
		}

		if v.ID >= 0x1011 && v.ID <= 0x1018 {
			mdr.RecordMap[v.Name] = v.Value
		}
	}
	//exportRecord.RecordMap["Data"] = msg.Data

	ds <- exportRecord
}
