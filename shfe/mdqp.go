package shfe

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/zartbot/mdec/sink"
)

type tcpStreamFactory struct {
	CurrentTimestamp time.Time
	DataChan         chan *sink.DataStream
	PicoSecond       uint64
	PicoEpoch        uint32
}

// tcpStream will handle the actual decoding of http requests.
type tcpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	timestamp      time.Time
	picosecond     uint64
	picoEpoch      uint32
	dataChan       chan *sink.DataStream
}

func (h *tcpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &tcpStream{
		net:        net,
		transport:  transport,
		r:          tcpreader.NewReaderStream(),
		timestamp:  h.CurrentTimestamp,
		picosecond: h.PicoSecond,
		picoEpoch:  h.PicoEpoch,
		dataChan:   h.DataChan,
	}
	go hstream.run()
	// Important... we must guarantee that data from the reader stream is read.
	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *tcpStream) run() {
	buf := bufio.NewReader(&h.r)
	remainCnt := 0
	data := bytes.NewBuffer(nil)

	for {
		if remainCnt != 0 {
			temp := make([]byte, remainCnt)
			n, err := buf.Read(temp)
			if err != nil {
				continue
			}
			data.Write(temp[0:n])
			remainCnt -= n
		} else {
			//remainCnt == 0, decode data
			if len(data.Bytes()) >= 8 {

				exportRecord := sink.NewDataStream(1, "mdqp", "local")
				exportRecord.TimeStamp = h.timestamp.UnixNano()
				exportRecord.RecordMap["CreateAt"] = h.timestamp
				exportRecord.RecordMap["picoSecond"] = h.picosecond
				exportRecord.RecordMap["picoEpoch"] = h.picoEpoch
				exportRecord.RecordMap["flowSrc"] = fmt.Sprintf("%s:%s", h.net.Src(), h.transport.Src())
				exportRecord.RecordMap["flowDst"] = fmt.Sprintf("%s:%s", h.net.Dst(), h.transport.Dst())

				msg, err := DecodeMDQP(data.Bytes())
				if err != nil {
					data.Reset()
					continue
				}

				exportRecord.RecordMap["Hdr"] = msg.Hdr
				exportRecord.RecordMap["Type"] = msg.Name

				if msg.Hdr.TypeID == 0x32 {
					snapResp := msg.Data.(*SnapshotResponse)
					exportRecord.RecordMap["MDQPSnapshotRespone_CenterChange"] = snapResp.CenterChange
					exportRecord.RecordMap["MDQPSnapshotRespone"] = snapResp.Hdr
					for _, v := range snapResp.InstrData {
						mData := sink.NewDataStream(1, fmt.Sprintf("%s-mdqp", v.InstrID), "local")
						mData.TimeStamp = h.timestamp.UnixNano()
						mData.RecordMap["CreateAt"] = h.timestamp
						mData.RecordMap["picoSecond"] = h.picosecond
						mData.RecordMap["picoEpoch"] = h.picoEpoch
						mData.RecordMap["flowSrc"] = fmt.Sprintf("%s:%s", h.net.Src(), h.transport.Src())
						mData.RecordMap["flowDst"] = fmt.Sprintf("%s:%s", h.net.Dst(), h.transport.Dst())
						mData.RecordMap["Data"] = v
						h.dataChan <- mData
					}
				} else if msg.Data != nil {
					exportRecord.RecordMap[msg.Name] = msg.Data
				}

				h.dataChan <- exportRecord
				data.Reset()
			}

			//then fetch next packet
			hdr, err := buf.Peek(8)
			if err != nil {
				continue
			}
			remainCnt = int(binary.LittleEndian.Uint16(hdr[2:4])) + 8
		}

	}
}

type MDQPDecoder struct {
	StreamFactory *tcpStreamFactory
	streamPool    *tcpassembly.StreamPool
	Assembler     *tcpassembly.Assembler
}

func NewMDQPDecoder(ch chan *sink.DataStream) *MDQPDecoder {
	r := &MDQPDecoder{
		StreamFactory: &tcpStreamFactory{
			DataChan: ch,
		},
	}
	r.streamPool = tcpassembly.NewStreamPool(r.StreamFactory)
	r.Assembler = tcpassembly.NewAssembler(r.streamPool)
	r.Assembler.AssemblerOptions = tcpassembly.AssemblerOptions{
		MaxBufferedPagesPerConnection: 4,
	}
	return r
}

type MDQPHdr struct {
	Version   uint8
	EndOfMsg  uint8
	TypeID    uint8
	Length    uint16
	RequestID int32
}

type MDQPMsg struct {
	Hdr  *MDQPHdr
	Name string
	Data interface{}
}

func Bytes2String(b []byte) string {
	c := bytes.Trim(b, "\x00")
	return *(*string)(unsafe.Pointer(&c))
}

func DecodeMDQP(pkt []byte) (*MDQPMsg, error) {
	result := &MDQPMsg{}
	pktLen := len(pkt)

	if pktLen < 8 {
		return result, fmt.Errorf("invalid length:%d", pktLen)
	}
	result.Hdr = &MDQPHdr{
		Version:   pkt[0] & 0x0f,
		EndOfMsg:  pkt[0] & 0x10 >> 4,
		TypeID:    pkt[1],
		Length:    binary.LittleEndian.Uint16(pkt[2:4]),
		RequestID: int32(binary.LittleEndian.Uint32(pkt[4:8])),
	}

	//validate Payload length before parsing field.

	if pkt[0] != 0x1 && pkt[0] != 0x11 {
		return result, fmt.Errorf("invalid packet flag")
	}

	if len(pkt) != int(8+result.Hdr.Length) {
		return result, fmt.Errorf("invalid packet legnth")
	}

	switch result.Hdr.TypeID {
	case 0x00:
		result.Name = "MDQPHeartBeat"
		//Nopayload for decode
	case 0x11:
		result.Name = "MDQPLoginRequest"
		//this field contains user privacy info, you may need to disable decode
		data, err := DecodeLoginRequest(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode login request error: %v", err)
		}
		result.Data = data
	case 0x12:
		result.Name = "MDQPLoginResponse"
		//this field contains user privacy info, you may need to disable decode
		data, err := DecodeLoginResponse(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode login response error: %v", err)
		}
		result.Data = data
	case 0x13:
		result.Name = "MDQPLogoutRequest"
		//this field contains user privacy info, you may need to disable decode
		data, err := DecodeLogoutRequest(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode logout request error: %v", err)
		}
		result.Data = data
	case 0x14:
		result.Name = "MDQPLogoutResponse"
		//this field contains user privacy info, you may need to disable decode
		data, err := DecodeLogoutResponse(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode logout response error: %v", err)
		}
		result.Data = data
	case 0x31:
		result.Name = "MDQPSnapshotRequest"
		data, err := DecodeSnapshotRequest(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode snapshot request error: %v", err)
		}
		result.Data = data
	case 0x32:
		result.Name = "MDQPSnapshotResponse"
		data, err := DecodeSnapshotResponse(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode snapshot response error: %v", err)
		}
		result.Data = data
	case 0x33:
		result.Name = "MDQPIncrRequest"
		data, err := DecodeIncrRequest(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode incr request error: %v", err)
		}
		result.Data = data
	case 0x34:
		result.Name = "MDQPIncrResponse"
		data, err := DecodeIncrResponse(pkt[8:])
		if err != nil {
			return result, fmt.Errorf("decode incr response error: %v", err)
		}
		result.Data = data
	}
	return result, nil
}

type LoginRequest struct {
	UserID               string
	ParticipantID        string
	Password             string
	Language             string
	UserProductInfo      string
	InterfaceProductInfo string
}

func DecodeLoginRequest(pkt []byte) (*LoginRequest, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x0002 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 151 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &LoginRequest{
		UserID:               Bytes2String(pkt[4:20]),
		ParticipantID:        Bytes2String(pkt[20:31]),
		Password:             Bytes2String(pkt[31:72]),
		Language:             string(pkt[72]),
		UserProductInfo:      Bytes2String(pkt[73:114]),
		InterfaceProductInfo: Bytes2String(pkt[114:155]),
	}

	return r, nil

}

type LoginResponse struct {
	ErrID             int32
	ErrMsg            string
	TradingDay        string
	LoginTime         string
	UserID            string
	ParticipantID     string
	TradingSystemName string
	ActionDay         string
}

func DecodeLoginResponse(pkt []byte) (*LoginResponse, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x0001 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 85 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &LoginResponse{
		ErrID:  int32(binary.LittleEndian.Uint32(pkt[4:8])),
		ErrMsg: Bytes2String(pkt[8:89]),
	}

	if r.ErrID == 0 && len(pkt) == 208 {
		/* 208
		    0x0001 4B Field Hdr + 4B[ErrID] + 81B[ErrMsg]
			0x0003 4B Field Hdr + 9B[TradingDay] ......+ 9B[ActionDay]*/
		if int16(binary.LittleEndian.Uint16(pkt[89:91])) == 0x0003 && binary.LittleEndian.Uint16(pkt[91:93]) == 115 {
			r.TradingDay = Bytes2String(pkt[93:102])
			r.LoginTime = Bytes2String(pkt[102:111])
			r.UserID = Bytes2String(pkt[111:127])
			r.ParticipantID = Bytes2String(pkt[127:138])
			r.TradingSystemName = Bytes2String(pkt[138:199])
			r.ActionDay = Bytes2String(pkt[199:208])
		}
	}
	return r, nil

}

type LogoutRequest struct {
	UserID        string
	ParticipantID string
}

func DecodeLogoutRequest(pkt []byte) (*LogoutRequest, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x0004 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 27 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &LogoutRequest{
		UserID:        Bytes2String(pkt[4:20]),
		ParticipantID: Bytes2String(pkt[20:31]),
	}

	return r, nil

}

type LogoutResponse struct {
	ErrID         int32
	ErrMsg        string
	UserID        string
	ParticipantID string
}

func DecodeLogoutResponse(pkt []byte) (*LogoutResponse, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x0001 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 85 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &LogoutResponse{
		ErrID:  int32(binary.LittleEndian.Uint32(pkt[4:8])),
		ErrMsg: Bytes2String(pkt[8:89]),
	}

	if r.ErrID == 0 && len(pkt) == 120 {
		/* 120
		    0x0001 4B Field Hdr + 4B[ErrID] + 81B[ErrMsg]
			0x0003 4B Field Hdr + 16B[UserID] + 11B[ParticipantID]*/
		if int16(binary.LittleEndian.Uint16(pkt[89:91])) == 0x0005 && binary.LittleEndian.Uint16(pkt[91:93]) == 27 {
			r.UserID = Bytes2String(pkt[93:109])
			r.ParticipantID = Bytes2String(pkt[109:120])
		}
	}
	return r, nil

}

type SnapshotRequest struct {
	TopicID int16
	SnapNo  int32
}

func DecodeSnapshotRequest(pkt []byte) (*SnapshotRequest, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x1001 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 6 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &SnapshotRequest{
		TopicID: int16(binary.LittleEndian.Uint16(pkt[4:6])),
		SnapNo:  int32(binary.LittleEndian.Uint32(pkt[6:10])),
	}

	return r, nil
}

type SnapshotResponseHdr struct {
	TopicID           int16
	SnapNo            int32
	TradingDay        string
	SettlementGroupID string
	SettlementID      int32
	//0x1003
	MarketDataDepth int32
	CipherAlgorithm string
	CipherKey       [16]byte
	CipherIV        [16]byte
	//0x1002
	SnapDate     string
	SnapTime     string
	SnapMillisec int32
	//0x1004
	PacketNo int32
}
type SnapshotResponse struct {
	CenterChange []*CenterChangeField
	Hdr          *SnapshotResponseHdr
	InstrData    map[int32]*InstrData
}

func DecodeSnapshotResponse(pkt []byte) (*SnapshotResponse, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	result := &SnapshotResponse{
		CenterChange: make([]*CenterChangeField, 0),
		Hdr:          &SnapshotResponseHdr{},
		InstrData:    make(map[int32]*InstrData),
	}

	start := int(0)
	for start < len(pkt)-4 {
		size, err := result.DecodeMDQPField(pkt[start:])
		if err != nil {
			return result, fmt.Errorf("decode field error: %v", err)
		}
		//set new offset
		start = start + int(size) + 4

	}

	return result, nil
}

type MDQPField struct {
	ID    int16
	Name  string
	Size  int16
	Value interface{}
}

type CenterChangeField struct {
	ChangeNo int8
	SnapNo   int32
	PacketNo int32
}

func DecodeMDQPCenterChangeField(pkt []byte) *CenterChangeField {
	return &CenterChangeField{
		ChangeNo: int8(pkt[0]),
		SnapNo:   int32(binary.LittleEndian.Uint32(pkt[1:5])),
		PacketNo: int32(binary.LittleEndian.Uint32(pkt[5:9])),
	}
}

func Bytes2Float64(b []byte) float64 {
	bits := binary.LittleEndian.Uint64(b)
	v := math.Float64frombits(bits)

	//This is a workaround fo
	if v == math.MaxFloat64 {
		v = -100000
	}
	return v
}

type InstrData struct {
	InstrID            string
	UnderlyingInstrID  string
	ProductClass       string
	StrikePrice        float64
	OptionsType        string
	VolMul             int32
	UnderlyingMul      float64
	IsTrading          int32
	CurrencyID         string
	PriceTick          float64
	CodecPrice         float64
	InstrNo            int32
	LastPrice          float64
	Volume             int32
	Turnover           float64
	OpenInterest       float64
	HighestPrice       float64
	LowestPrice        float64
	OpenPrice          float64
	ClosePrice         float64
	SettlementPrice    float64
	UpperLimitPrice    float64
	LowerLimitPrice    float64
	PreSettlementPrice float64
	PreClosePrice      float64
	PreOpenInterest    float64
	PreDelta           float64
	CurrDelta          float64
	ActionDay          string
	UpdateTime         string
	UpdateMilliSec     int32
	ChangeNo           int32
	PV                 []*InstrPV
}

type InstrPV struct {
	Direction string
	Price     float64
	Volume    int32
}

func (s *SnapshotResponse) DecodeMDQPField(pkt []byte) (int16, error) {
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldSize := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if len(pkt) < int(4+fieldSize) {
		return fieldSize, fmt.Errorf("decode MDQP field failed: invalid packet length")
	}
	switch fieldID {
	case 0x0032:
		//0x0032:CenterChangeField
		v := DecodeMDQPCenterChangeField(pkt[4 : 4+fieldSize])
		s.CenterChange = append(s.CenterChange, v)
	case 0x1001:
		s.Hdr.TopicID = int16(binary.LittleEndian.Uint16(pkt[4:6]))
		s.Hdr.SnapNo = int32(binary.LittleEndian.Uint32(pkt[6:10]))
	case 0x0031:
		//0x0031:Settlement Field
		s.Hdr.TradingDay = Bytes2String(pkt[4:13])
		s.Hdr.SettlementGroupID = Bytes2String(pkt[13:22])
		s.Hdr.SettlementID = int32(binary.LittleEndian.Uint32(pkt[22:26]))
	case 0x1003:
		//0x1003:Attribute Field
		s.Hdr.MarketDataDepth = int32(binary.LittleEndian.Uint32(pkt[4:8]))
		s.Hdr.CipherAlgorithm = string(pkt[8])
		copy(s.Hdr.CipherKey[:], pkt[9:25])
		copy(s.Hdr.CipherIV[:], pkt[25:41])

	case 0x1002:
		//0x1002:Timestamp Field
		s.Hdr.SnapDate = Bytes2String(pkt[4:13])
		s.Hdr.SnapTime = Bytes2String(pkt[13:22])
		s.Hdr.SnapMillisec = int32(binary.LittleEndian.Uint32(pkt[22:26]))
	case 0x1004:
		s.Hdr.PacketNo = int32(binary.LittleEndian.Uint32(pkt[4:8]))
	case 0x0101:
		record := &InstrData{
			InstrID:           Bytes2String(pkt[4:35]),
			UnderlyingInstrID: Bytes2String(pkt[35:66]),
			ProductClass:      string(pkt[66]),
			StrikePrice:       Bytes2Float64(pkt[67:75]),
			OptionsType:       string(pkt[75]),
			VolMul:            int32(binary.LittleEndian.Uint32(pkt[76:80])),
			UnderlyingMul:     Bytes2Float64(pkt[80:88]),
			IsTrading:         int32(binary.LittleEndian.Uint32(pkt[88:92])),
			CurrencyID:        Bytes2String(pkt[92:96]),
			PriceTick:         Bytes2Float64(pkt[96:104]),
			CodecPrice:        Bytes2Float64(pkt[104:112]),
			InstrNo:           int32(binary.LittleEndian.Uint32(pkt[112:116])),
			PV:                make([]*InstrPV, 0),
		}
		s.InstrData[record.InstrNo] = record
	case 0x0102:
		InstrNo := int32(binary.LittleEndian.Uint32(pkt[4:8]))
		r, ok := s.InstrData[InstrNo]
		if !ok {
			return fieldSize, fmt.Errorf("invalid 0x0102 field[instrID not found]")
		}

		r.LastPrice = Bytes2Float64(pkt[8:16])
		r.Volume = int32(binary.LittleEndian.Uint32(pkt[16:20]))
		r.Turnover = Bytes2Float64(pkt[20:28])
		r.OpenInterest = Bytes2Float64(pkt[28:36])
		r.HighestPrice = Bytes2Float64(pkt[36:44])
		r.LowestPrice = Bytes2Float64(pkt[44:52])
		r.OpenPrice = Bytes2Float64(pkt[52:60])
		r.ClosePrice = Bytes2Float64(pkt[60:68])
		r.SettlementPrice = Bytes2Float64(pkt[68:76])
		r.UpperLimitPrice = Bytes2Float64(pkt[76:84])
		r.LowerLimitPrice = Bytes2Float64(pkt[84:92])
		r.PreSettlementPrice = Bytes2Float64(pkt[92:100])
		r.PreClosePrice = Bytes2Float64(pkt[100:108])
		r.PreOpenInterest = Bytes2Float64(pkt[108:116])
		r.PreDelta = Bytes2Float64(pkt[116:124])
		r.CurrDelta = Bytes2Float64(pkt[124:132])
		r.ActionDay = Bytes2String(pkt[132:141])
		r.UpdateTime = Bytes2String(pkt[141:150])
		r.UpdateMilliSec = int32(binary.LittleEndian.Uint32(pkt[150:154]))
		r.ChangeNo = int32(binary.LittleEndian.Uint32(pkt[154:158]))

	case 0x0103:
		InstrNo := int32(binary.LittleEndian.Uint32(pkt[4:8]))
		r, ok := s.InstrData[InstrNo]
		if !ok {
			return fieldSize, fmt.Errorf("invalid 0x0102 field[instrID not found]")
		}
		record := &InstrPV{
			Direction: string(pkt[8]), //'0':bid , '1':ask
			Price:     Bytes2Float64(pkt[9:17]),
			Volume:    int32(binary.LittleEndian.Uint32(pkt[17:21])),
		}
		r.PV = append(r.PV, record)
	}

	return fieldSize, nil

}

type IncrRequest struct {
	TopicID    int16
	StartPktNo int32
	EndPktNo   int32
}

func DecodeIncrRequest(pkt []byte) (*IncrRequest, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldLength := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if fieldID != 0x0201 {
		return nil, fmt.Errorf("invalid fieldID:%d", fieldID)
	}
	if fieldLength != 10 {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	if int(fieldLength+4) > len(pkt) {
		return nil, fmt.Errorf("invalid field length: type:%d length:%d", fieldID, fieldLength)
	}

	r := &IncrRequest{
		TopicID:    int16(binary.LittleEndian.Uint16(pkt[4:6])),
		StartPktNo: int32(binary.LittleEndian.Uint32(pkt[6:10])),
		EndPktNo:   int32(binary.LittleEndian.Uint32(pkt[10:14])),
	}

	return r, nil
}

type IncrResponse struct {
	Data []*MirpMsg
}

func DecodeIncrResponse(pkt []byte) (*IncrResponse, error) {
	if len(pkt) < 4 {
		return nil, fmt.Errorf("invalid length")
	}
	result := &IncrResponse{
		Data: make([]*MirpMsg, 0),
	}

	start := int(0)
	for start < len(pkt)-4 {
		data, size, err := DecodeGenericField(pkt[start:])
		if err != nil {
			return result, fmt.Errorf("decode field error: %v", err)
		}
		msg, err := DecodeMIRP(data)
		if err != nil {
			return result, fmt.Errorf("decode mirp message error: %v", err)
		}
		result.Data = append(result.Data, msg)
		//set new offset
		start = start + int(size) + 4

	}

	return result, nil
}

func DecodeGenericField(pkt []byte) ([]byte, int16, error) {
	fieldID := int16(binary.LittleEndian.Uint16(pkt[0:2]))
	fieldSize := int16(binary.LittleEndian.Uint16(pkt[2:4]))

	if len(pkt) < int(4+fieldSize) {
		return nil, fieldSize, fmt.Errorf("decode MDQP generic field failed: invalid packet length")
	}
	if fieldID != 0x0000 {
		return nil, fieldSize, fmt.Errorf("decode MDQP generic field failed: invalid field ID")
	}

	return pkt[4:], fieldSize, nil
}
