package exats

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

//ExaTrailer is used to decode Exablaze timestamp trailer
type ExaTrailer struct {
	OriginFCS [4]byte
	DeviceID  uint8
	PortID    uint8
	EpochSec  [4]byte
	FracSec   [5]byte
	Reserved  uint8
}

//PicoSecondTimeStamp is used for picosecond timestamp
type PicoSecondTimeStamp struct {
	Epoch       uint32
	PicoSeconds uint64
}

//PicoSecondDuration is used for picsecond duration
type PicoSecondDuration struct {
	Epoch       int32
	PicoSeconds int64
}

//ExaTimeStamp is ?
type HPT struct {
	TimeStamp *PicoSecondTimeStamp
	DeviceID  uint8
	PortID    uint8
}

//Duration is used to calculate time duration between two PstimeT
func (e2 *PicoSecondTimeStamp) Duration(e1 *PicoSecondTimeStamp) *PicoSecondDuration {
	result := &PicoSecondDuration{
		Epoch:       int32(e2.Epoch - e1.Epoch),
		PicoSeconds: int64(e2.PicoSeconds - e1.PicoSeconds),
	}

	if result.PicoSeconds < 0 && result.Epoch > 0 {
		result.Epoch = result.Epoch - 1
		result.PicoSeconds = result.PicoSeconds + 1000000000000
	}
	return result
}

func (e *PicoSecondDuration) String() string {
	return fmt.Sprintf("Epoch: %d | PicoSec: %d", e.Epoch, e.PicoSeconds)
}

func (e *HPT) String() string {
	return fmt.Sprintf("Device: %d | Port: %d | Time:  %s | Epoch: %d | PicoSec: %d", e.DeviceID, e.PortID, time.Unix(int64(e.TimeStamp.Epoch), int64(e.TimeStamp.PicoSeconds/1000)).Local().String(), e.TimeStamp.Epoch, e.TimeStamp.PicoSeconds)
}

//DecodeExaTS is used to decode Exablaze HPT Timestamp trailer
func DecodeExaTS(pkt gopacket.Packet, freq uint64, lastTS time.Time, lastTick uint64) (time.Time, *HPT, error) {
	L1Len := len(pkt.Data())
	L2Len := int(0)

	//Check IPv4 Packet
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		L2Len = 14 + int(ip.Length)

	} else {
		//Check IPv6
		ipLayer = pkt.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			ip.NetworkFlow().Reverse().Src()
			L2Len = 14 + int(ip.Length)
		}
	}

	if L2Len < 60 {
		L2Len = 60
	}

	/* Normal packet L1Len-L2Len should be 4B(FCS)*/

	//Decode Exablaze HPT
	if (L1Len - L2Len) == 16 {
		temp := pkt.Data()[L1Len-16 : L1Len]

		// Src code from exablaze:
		//    uint32_t seconds_since_epoch = ntohl(trailer->seconds_since_epoch);
		// double frac_seconds = ldexp((uint64_t(trailer->frac_seconds[0]) << 32) |
		//     (uint64_t(trailer->frac_seconds[1]) << 24) | (uint64_t(trailer->frac_seconds[2]) << 16) |
		//    (uint64_t(trailer->frac_seconds[3]) << 8) | uint64_t(trailer->frac_seconds[4]), -40);

		frac := uint64(math.Ldexp(float64(uint64(temp[10])<<32|uint64(temp[11])<<24|uint64(temp[12])<<16|uint64(temp[13])<<8|uint64(temp[14])), -40) * 1000000000000)
		h := &HPT{
			DeviceID: uint8(temp[4]),
			PortID:   uint8(temp[5]),
			TimeStamp: &PicoSecondTimeStamp{
				Epoch:       binary.BigEndian.Uint32(temp[6:10]),
				PicoSeconds: frac,
			},
		}

		return time.Unix(int64(h.TimeStamp.Epoch), int64(h.TimeStamp.PicoSeconds/1000)), h, nil
	}

	if (L1Len - L2Len) == 12 {

		ticks := uint64(binary.BigEndian.Uint32(pkt.Data()[L1Len-8:]))
		// handle tick rollover
		if ticks < lastTick {
			ticks = 0x100000000
		}

		ticks -= lastTick
		return lastTS.Add(time.Duration(ticks * 1000000000 / freq)), nil, nil
	}

	//FCS Mdoe
	if (L1Len - L2Len) == 8 {
		ticks := uint64(binary.BigEndian.Uint32(pkt.Data()[L1Len-4:]))
		// handle tick rollover
		if ticks < lastTick {
			ticks = 0x100000000
		}

		ticks -= lastTick
		return lastTS.Add(time.Duration(ticks * 1000000000 / freq)), nil, nil
	}

	return time.Now(), nil, nil
}
