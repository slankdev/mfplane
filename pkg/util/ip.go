/*
Copyright 2022 Hiroki Shirokura.
Copyright 2022 Keio University.
Copyright 2022 Wide Project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"net"

	netaddr "github.com/dspinhirne/netaddr-go"
)

func ConvertUint32ToIP(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func ConvertIPToUint32(ip net.IP) uint32 {
	var val uint32
	binary.Read(bytes.NewBuffer(ip.To4()), binary.LittleEndian, &val)
	return val
}

func UdpTransmit(local, remote string, buf *bytes.Buffer) error {
	laddr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return err
	}
	raddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

func Plen(mask net.IPMask) int {
	l := 0
	for _, m := range mask {
		l += bits.OnesCount8(uint8(m))
	}
	return l
}

func GetSubnet(cidrStr string, prefixlen uint) ([]string, error) {
	loc, err := netaddr.ParseIPv6Net(cidrStr)
	if err != nil {
		return nil, err
	}
	sids := []string{}
	for i := uint64(0); i < loc.SubnetCount(prefixlen); i++ {
		sid := loc.NthSubnet(32, i)
		sids = append(sids, sid.String())
	}
	return sids, nil
}

func MustParseMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}
