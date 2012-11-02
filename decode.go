// Copyright 2012 Andreas Louca. All rights reserved.
// Use of this source code is goverend by a BSD-style
// license that can be found in the LICENSE file.

package gosnmp

import (
	"encoding/asn1"
	"fmt"
)

type Asn1BER byte

const (
	NoSuchObject     Asn1BER = 0x00
	NoSuchInstance           = 0x01
	Integer                  = 0x02
	BitString                = 0x03
	OctetString              = 0x04
	Null                     = 0x05
	ObjectIdentifier         = 0x06
	Counter32                = 0x41
	Gauge32                  = 0x42
	TimeTicks                = 0x43
	Opaque                   = 0x44
	NsapAddress              = 0x45
	Counter64                = 0x46
	Uinteger32               = 0x47
)

// Different packet structure is needed during decode, to trick encoding/asn1 to decode the SNMP packet

type Variable struct {
	Name  []int
	Type  Asn1BER
	Value interface{}
}

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type PDU struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []VarBind
}
type PDUResponse struct {
	RequestId   int32
	ErrorStatus int
	ErrorIndex  int
	VarBindList []Variable
}

type Message struct {
	Version   int
	Community []uint8
	Data      asn1.RawValue
}

func decode(data []byte, pdu *PDUResponse) error {
	m := Message{}
	_, err := asn1.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}
	tag := m.Data.Tag
	switch tag {
	// SNMP Response
	case 0x20, 0x21, 0x22:

		var pdu PDU

		_, err = asn1.UnmarshalWithParams(m.Data.FullBytes, &pdu, fmt.Sprint("tag:",tag))
		if err != nil {
			return fmt.Errorf("Error decoding pdu: %#v, %#v, %s", m.Data.FullBytes, pdu, err)
		}

		// make response pdu
		var resp PDUResponse
		// Copy values from parsed pdu
		resp.RequestId = pdu.RequestId
		resp.ErrorIndex = pdu.ErrorIndex
		resp.ErrorStatus = pdu.ErrorStatus

		resp.VarBindList = make([]Variable, len(pdu.VarBindList))

		// Decode all vars
		for c, v := range pdu.VarBindList {

			err := decodeValue(v.Name, v.Value, &resp.VarBindList[c])
			if err != nil {
				return err
			}
		}

		pdu = &resp
		return
	}
	return fmt.Errorf("Unable to decode type: %#v\n", tag)
}

func decodeValue(name string, data *asn1.RawValue, retVal *Variable) (err error) {
	switch Asn1BER(data.Tag) {

	// simple values
	case Integer, OctetString:
		params, val = "", new(interface{})
	// 32 bit application values
	case Counter32, TimeTicks, Gauge32:
		params, val = fmt.Sprint("tag:", data.Tag), new(int32)
	// 64 bit application values
	case Counter64:
		params, val = fmt.Sprint("tag:", data.Tag), new(int64)
	case NoSuchInstance:
		return fmt.Errorf("No such instance")
	case NoSuchObject:
		return fmt.Errorf("No such object")
	default:
		return fmt.Errorf("Unable to decode %x - not implemented", data[0])
	}
	_, err = asn1.UnmarshalWithParams(m.Data.FullBytes, &val, fmt.Sprint("tag:",data.Tag))
	if err != nil {
		return
	}
	*retVal.Name = name
	*retVal.Type = Asn1BER(data.Tag)
	*retVal.Value = val

	return
}

// Parses UINT16
func ParseUint16(content []byte) int {
	number := uint8(content[1]) | uint8(content[0])<<8
	//fmt.Printf("\t%d\n", number)

	return int(number)
}
