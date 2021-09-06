package sink

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/olivere/elastic"
	"github.com/sirupsen/logrus"
)

//InitElasticClient is a construct function for Client
func InitElasticClient(url string) (*elastic.Client, error) {
	var (
		err           error
		elasticClient *elastic.Client
	)
	for {
		elasticClient, err = elastic.NewClient(
			elastic.SetURL(url),
			elastic.SetSniff(false),
		)
		if err != nil {
			log.Println(err)
			time.Sleep(3 * time.Second)
		} else {
			break
		}
	}
	return elasticClient, err
}

//ElasticBulkProcessor elastic bulk import processor
type ElasticBulkProcessor struct {
	ID             uint32
	Name           string
	Input          <-chan *DataStream
	Parallelism    int
	C              *elastic.Client
	P              *elastic.BulkProcessor
	IndexPrefix    string
	Mapping        string
	PrefixTypeList []string
	FlushInterval  int
	StopChanList   chan struct{}
	CreateIdxFlag  chan struct{}
}

// Run starts the ElasticBulkProcessor.
func (b *ElasticBulkProcessor) Init() error {
	// Start bulk processor
	if b.FlushInterval < 100 {
		b.FlushInterval = 1000
	}
	p, err := b.C.BulkProcessor().
		Workers(b.Parallelism). // # of workers
		BulkActions(5000).      // # of queued requests before committed//
		//BulkSize(1024000000).                                             // # of bytes in requests before committed
		FlushInterval(time.Duration(b.FlushInterval) * time.Millisecond). // autocommit every interval milliseconds
		Do(context.Background())
	if err != nil {
		logrus.Fatal(err)
		return err
	}
	b.P = p
	// Start indexer that pushes data into bulk processor
	b.StopChanList = make(chan struct{})
	b.CreateIdxFlag = make(chan struct{})
	go b.ensureIndex()
	<-b.CreateIdxFlag
	logrus.Info("ElasticSearch Bulk Processor is running...")
	return nil
}

// Close the bulker.
func (b *ElasticBulkProcessor) Close() error {
	b.StopChanList <- struct{}{}
	<-b.StopChanList
	close(b.StopChanList)
	return nil
}

//Run is used bulkupload Record to ElasticSearch Server
func (b *ElasticBulkProcessor) Run() {
	var stop bool
	for !stop {
		select {
		case <-b.StopChanList:
			stop = true
		case d := <-b.Input:
			unixtime := time.Unix(0, d.TimeStamp)
			exporttime := unixtime.Format("2006.01.02")
			indexName := b.IndexPrefix + "-" + d.Type + "-" + exporttime
			r := elastic.NewBulkIndexRequest().Index(indexName).Type("_doc").Doc(d.RecordMap)
			/*
				str, err := json.MarshalIndent(d.RecordMap, "", "\t")

					if err == nil {
						logrus.Info(string(str))
					}*/

			b.P.Add(r)
		}
	}
	b.StopChanList <- struct{}{} // ack stopping
}

type CfgElasticSearchSink struct {
	ID             uint32
	Name           string
	Input          chan *DataStream
	Uri            string
	IndexPrefix    string
	PrefixTypeList []string
	Mapping        string
	FlushInterval  int
	Parallelism    int
}

//NewElasticSearchSink :Bulk import record to ElasticSearch
func NewElasticSearchSink(ec *CfgElasticSearchSink) (*ElasticBulkProcessor, error) {
	elasticClient, err := InitElasticClient(ec.Uri)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Info("ElasticSearch Server connected.....")
	BulkProcessor := &ElasticBulkProcessor{
		ID:             ec.ID,
		Name:           ec.Name,
		Input:          ec.Input,
		Parallelism:    ec.Parallelism,
		Mapping:        ec.Mapping,
		C:              elasticClient,
		IndexPrefix:    ec.IndexPrefix,
		PrefixTypeList: ec.PrefixTypeList,
		FlushInterval:  ec.FlushInterval,
	}
	err = BulkProcessor.Init()
	if err != nil {
		log.Fatal(err)
	}
	return BulkProcessor, err
}

func (b *ElasticBulkProcessor) ensureIndex() {
	const date = "2006.01.02"
	var indexname, nextindexname string
	startflag := true

	if len(b.IndexPrefix) < 1 {
		log.Fatal("No indexprefix name.")
		return
	}
	for {
		currentTick := time.Now().Format(date)
		nextTick := time.Now().Add(time.Duration(3600*24) * time.Second).Format(date)
		for _, item := range b.PrefixTypeList {
			indexname = fmt.Sprintf("%s-%s-%s", b.IndexPrefix, item, currentTick)
			nextindexname = fmt.Sprintf("%s-%s-%s", b.IndexPrefix, item, nextTick)
			//fmt.Println(indexname, nextindexname)

			exists, _ := b.C.IndexExists(indexname).Do(context.Background())
			if !exists {
				logrus.Info("Creating index:", indexname)
				_, err := b.C.CreateIndex(indexname).BodyString(b.Mapping).Do(context.Background())
				if err != nil {
					logrus.Warn(err)
				}
			}
			nextExists, _ := b.C.IndexExists(nextindexname).Do(context.Background())
			if !nextExists {
				logrus.Info("Preparing nextday index:", nextindexname)
				_, err := b.C.CreateIndex(nextindexname).BodyString(b.Mapping).Do(context.Background())
				if err != nil {
					logrus.Warn(err)
				}
			}
		}
		if startflag {
			b.CreateIdxFlag <- struct{}{}
			startflag = false
			logrus.Info("Index Created... ")
		}
		time.Sleep(120 * time.Second)
	}

}
