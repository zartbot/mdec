package sink

// DataStream is the basic structure for streaming data processinging.
type DataStream struct {
	ID        uint32
	TimeStamp int64
	Type      string
	Source    string
	RecordMap map[string]interface{}
}

type MapCallbackFunc func(*DataStream) *DataStream

func NewDataStream(id uint32, typearg string, src string) *DataStream {

	return &DataStream{
		ID:        id,
		Type:      typearg,
		Source:    src,
		RecordMap: make(map[string]interface{}),
	}
}

func (d *DataStream) Map(fn MapCallbackFunc) *DataStream {
	return fn(d)
}
