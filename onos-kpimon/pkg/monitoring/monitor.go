package monitoring

/*
#cgo CFLAGS: -I/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App  -I/opt/intel/sgxsdk/sgxsdk/include/tlibc -I/opt/intel/sgxsdk/sgxsdk/include/stlport 
#cgo LDFLAGS: -L/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring/App -L/go/src/github.com/onosproject/onos-kpimon/pkg/monitoring -lbridge -L/opt/intel/sgxsdk/sgxsdk/lib64 -lsgx_urts_sim -L/usr/lib -L/usr/local/lib
#include "App/App.h"
#include <stdlib.h>
*/
import "C"
import (
	"context"

	"github.com/onosproject/onos-kpimon/pkg/rnib"

	e2api "github.com/onosproject/onos-api/go/onos/e2t/e2/v1beta1"
	"github.com/onosproject/onos-kpimon/pkg/store/actions"

	topoapi "github.com/onosproject/onos-api/go/onos/topo"

	appConfig "github.com/onosproject/onos-kpimon/pkg/config"

	measurmentStore "github.com/onosproject/onos-kpimon/pkg/store/measurements"

	e2smkpmv2 "github.com/onosproject/onos-e2-sm/servicemodels/e2sm_kpm_v2_go/v2/e2sm-kpm-v2-go"
	e2smkpmv2sm "github.com/onosproject/onos-e2-sm/servicemodels/e2sm_kpm_v2_go/servicemodel"
	"google.golang.org/protobuf/proto"

	"github.com/onosproject/onos-lib-go/pkg/logging"

	"github.com/onosproject/onos-kpimon/pkg/broker"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

)

var log = logging.GetLogger()

// NewMonitor creates a new indication monitor
func NewMonitor(opts ...Option) *Monitor {
	options := Options{}

	for _, opt := range opts {
		opt.apply(&options)
	}

	return &Monitor{
		appConfig:        options.App.AppConfig,
		measurementStore: options.App.MeasurementStore,
		actionStore:      options.App.ActionStore,
		streamReader:     options.Monitor.StreamReader,
		nodeID:           options.Monitor.NodeID,
		measurements:     options.Monitor.Measurements,
		rnibClient:       options.App.RNIBClient,
	}
}

// Monitor indication monitor
type Monitor struct {
	streamReader     broker.StreamReader
	measurementStore measurmentStore.Store
	actionStore      actions.Store
	appConfig        *appConfig.AppConfig
	measurements     []*topoapi.KPMMeasurement
	nodeID           topoapi.ID
	rnibClient       rnib.Client
}
func GoPrint(str *C.char) {
	fmt.Println("[OCALL] Message from Enclave:", C.GoString(str))
}
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := aesGCM.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, err
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }

    return plaintext, nil
}
func (m *Monitor) processIndicationFormat1(ctx context.Context, indication e2api.Indication,
	measurements []*topoapi.KPMMeasurement, nodeID topoapi.ID) error {
	
	
	
	
	if C.initialize() < 0 {
		fmt.Println("Failed to initialize SGX enclave")
		
	}


	
	encryptionKey := []byte{
	0xa9, 0xf4, 0xb6, 0xc7, 0xd1, 0xe2, 0xf3, 0xa4,
	0xb5, 0xc6, 0xd7, 0xe8, 0xf9, 0xa0, 0xb1, 0xc2,
	0xd3, 0xe4, 0xf5, 0xa6, 0xb7, 0xc8, 0xd9, 0xe0,
	0xf1, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0xa8,
}



	log.Errorf("payload.....................................:", fmt.Sprintf("%x", indication.Payload))
	decryptedPayload, e := decrypt(indication.Payload, encryptionKey)
	if e != nil {
					log.Warn("Decryption failed:", e)
					
				}
	log.Errorf("Decrypted Data (Hex).....................................:", fmt.Sprintf("%x", decryptedPayload))

	
	var kpm2ServiceModel e2smkpmv2sm.Kpm2ServiceModel

	indMessageProto, e1 := kpm2ServiceModel.IndicationMessageASN1toProto(decryptedPayload)
	
	if e1 != nil {
					log.Warn("asn1to p failed:", e1)
					}
	
	
	
	indHeader := e2smkpmv2.E2SmKpmIndicationHeader{}
	err := proto.Unmarshal(indication.Header, &indHeader)
	if err != nil {
		log.Warn(err)
		return err
	}

	indMessage:= e2smkpmv2.E2SmKpmIndicationMessage{}
	err = proto.Unmarshal(indMessageProto, &indMessage)
	if err != nil {
		log.Warn(err)
		return err
	}

	
	

	indHdrFormat1 := indHeader.GetIndicationHeaderFormats().GetIndicationHeaderFormat1()
	indMsgFormat1 := indMessage.GetIndicationMessageFormats().GetIndicationMessageFormat1()
	log.Debugf("Received indication header format 1 %v:", indHdrFormat1)
	log.Debugf("Received indication message format 1: %v", indMsgFormat1)

	startTime := getTimeStampFromHeader(indHdrFormat1)
	startTimeUnixNano := toUnixNano(int64(startTime))

	granularity, err := m.appConfig.GetGranularityPeriod()
	if err != nil {
		log.Warn(err)
		return err
	}

	var cid string
	if indMsgFormat1.GetCellObjId() == nil {
		// Use the actions store to find cell object Id based on sub ID in action definition
		key := actions.NewKey(actions.SubscriptionID{
			SubID: indMsgFormat1.GetSubscriptId().GetValue(),
		})

		response, err := m.actionStore.Get(ctx, key)
		if err != nil {
			return err
		}

		actionDefinition := response.Value.(*e2smkpmv2.E2SmKpmActionDefinitionFormat1)
		cid = actionDefinition.GetCellObjId().GetValue()

	} else {
		cid = indMsgFormat1.GetCellObjId().Value
	}

	measDataItems := indMsgFormat1.GetMeasData().GetValue()
	measInfoList := indMsgFormat1.GetMeasInfoList().GetValue()

	measItems := make([]measurmentStore.MeasurementItem, 0)
	for i, measDataItem := range measDataItems {
		meadDataRecords := measDataItem.GetMeasRecord().GetValue()
		measRecords := make([]measurmentStore.MeasurementRecord, 0)
		for j, measDataRecord := range meadDataRecords {
			var measValue interface{}
			switch val := measDataRecord.MeasurementRecordItem.(type) {
			case *e2smkpmv2.MeasurementRecordItem_Integer:
				measValue = val.Integer

			case *e2smkpmv2.MeasurementRecordItem_Real:
				measValue = val.Real

			case *e2smkpmv2.MeasurementRecordItem_NoValue:
				measValue = val.NoValue
			default:
				measValue = 0
			}

			timeStamp := uint64(startTimeUnixNano) + granularity*uint64(1000000)*uint64(i)
			if measInfoList[j].GetMeasType().GetMeasName().GetValue() != "" {
				measName := measInfoList[j].GetMeasType().GetMeasName().GetValue()
				measRecord := measurmentStore.MeasurementRecord{
					Timestamp:        timeStamp,
					MeasurementName:  measName,
					MeasurementValue: measValue,
				}
				measRecords = append(measRecords, measRecord)
			} else if measInfoList[j].GetMeasType().GetMeasId() != nil {
				measID := measInfoList[j].GetMeasType().GetMeasId().String()
				log.Debugf("Received meas ID in indication message:", measID)
				log.Debugf("List of measurements:", measurements)
				measName := getMeasurementName(measID, measurements)
				measRecord := measurmentStore.MeasurementRecord{
					Timestamp:        timeStamp,
					MeasurementName:  measName,
					MeasurementValue: measValue,
				}
				measRecords = append(measRecords, measRecord)
			}
		}

		measItem := measurmentStore.MeasurementItem{
			MeasurementRecords: measRecords,
		}
		measItems = append(measItems, measItem)

	}

	cellID := measurmentStore.CellIdentity{
		CellID: cid,
	}

	measurementKey := measurmentStore.NewKey(cellID, string(nodeID))
	_, err = m.measurementStore.Put(ctx, measurementKey, measItems)
	if err != nil {
		log.Warn(err)
		return err
	}

	cellTopoID, err := m.rnibClient.GetCellTopoID(ctx, cellID.CellID, nodeID)
	if err != nil {
		return err
	}
	err = m.rnibClient.UpdateCellAspects(ctx, cellTopoID, measItems)
	if err != nil {
		return err
	}

	return nil
}

func (m *Monitor) processIndication(ctx context.Context, indication e2api.Indication,
	measurements []*topoapi.KPMMeasurement, nodeID topoapi.ID) error {
	err := m.processIndicationFormat1(ctx, indication, measurements, nodeID)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}

// Start start monitoring of indication messages for a given subscription ID
func (m *Monitor) Start(ctx context.Context) error {
	errCh := make(chan error)
	go func() {
		for {
			indMsg, err := m.streamReader.Recv(ctx)
			if err != nil {
				errCh <- err
			}
			err = m.processIndication(ctx, indMsg, m.measurements, m.nodeID)
			if err != nil {
				errCh <- err
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
