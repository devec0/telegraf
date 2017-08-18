package net

import (
	"fmt"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/inputs/system"
)

type NetIOStats struct {
	filter filter.Filter
	ps     system.PS

	skipChecks          bool
	IgnoreProtocolStats bool
	Interfaces          []string
}

func (_ *NetIOStats) Description() string {
	return "Read metrics about network interface usage"
}

var netSampleConfig = `
  ## By default, telegraf gathers stats from any up interface (excluding loopback)
  ## Setting interfaces will tell it to gather these explicit interfaces,
  ## regardless of status.
  ##
  # interfaces = ["eth0"]
  ##
  ## On linux systems telegraf also collects protocol stats.
  ## Setting ignore_protocol_stats to true will skip reporting of protocol metrics.
  ##
  # ignore_protocol_stats = false
  ##
`

func (_ *NetIOStats) SampleConfig() string {
	return netSampleConfig
}

func GetHostSysFS() string {
	sysPath := "/proc/sys"
	if sys := os.Getenv("HOST_SYS"); sys != "" {
		sysPath = sys
	}
	return sysPath
}

func (s *NetIOStats) Gather(acc telegraf.Accumulator) error {
	netio, err := s.ps.NetIO()
	if err != nil {
		return fmt.Errorf("error getting net io info: %s", err)
	}

	if s.filter == nil {
		if s.filter, err = filter.Compile(s.Interfaces); err != nil {
			return fmt.Errorf("error compiling filter: %s", err)
		}
	}

	interfaces, err := s.ps.NetInterfaces()
	if err != nil {
		return fmt.Errorf("error getting list of interfaces: %s", err)
	}
	interfaces := map[string]s.ps.Interface{}
	for _, iface := range interfaces {
		interfaces[iface.Name] = iface
	}

	for _, io := range netio {
		var iface s.ps.NetInterface
		if len(s.Interfaces) != 0 {
			var found bool

			if s.filter.Match(io.Name) {
				found = true
			}

			if !found {
				continue
			}
		} else if !s.skipChecks {
			iface, ok := interfaces[io.Name]
			if !ok {
				continue
			}

			if iface.Flags&net.FlagLoopback == net.FlagLoopback {
				continue
			}

			if iface.Flags&net.FlagUp == 0 {
				continue
			}
		}

		tags := map[string]string{
			"interface": io.Name,
			"state":     iface.state,
			"mtu":       iface.MTU,
		}

		// the following are only supported on Linux, for now, so check they have been populated
		if iface.duplex {
			tags["duplex"] = iface.duplex
		}
		if iface.speed {
			tags["speed"] = iface.speed
		}
		if iface.carrier {
			tags["carrier"] = iface.carrier
		}

		fields := map[string]interface{}{
			"bytes_sent":   io.BytesSent,
			"bytes_recv":   io.BytesRecv,
			"packets_sent": io.PacketsSent,
			"packets_recv": io.PacketsRecv,
			"err_in":       io.Errin,
			"err_out":      io.Errout,
			"drop_in":      io.Dropin,
			"drop_out":     io.Dropout,
			"mtu":          iface.MTU,
		}

		var state string
		if iface.Flags&net.FlagUp > 0 {
			state = "up"
		} else {
			state = "down"
		}

		// linux specific metrics from /sys
		if runtime.GOOS == "linux" {
			ifacePath := path.Join(GetHostSysFS(), "/class/net/") + io.Name

			carrier, err := internal.ReadLines(ifacePath + "/carrier")
			if err == nil {
				carrier := strings.TrimSpace(carrier[0])
				if carrier == "1" {
					tags["carrier"] = "up"
				} else {
					tags["carrier"] = "down"
				}
			}

			speed, err := internal.ReadLines(ifacePath + "/speed")
			if err == nil {
				speedUint64, err := strconv.ParseUint(strings.TrimSpace(speed[0]), 10, 64)
				if err == nil {
					tags["speed"] = speedUint64
				}
			}

			duplex, err := internal.ReadLines(ifacePath + "/duplex")
			if err == nil {
				tags["duplex"] = strings.TrimSpace(duplex[0])
			}
		}

		acc.AddCounter("net", fields, tags)

	}

	// Get system wide stats for different network protocols
	// (ignore these stats if the call fails)
	if !s.IgnoreProtocolStats {
		netprotos, _ := s.ps.NetProto()
		fields := make(map[string]interface{})
		for _, proto := range netprotos {
			for stat, value := range proto.Stats {
				name := fmt.Sprintf("%s_%s", strings.ToLower(proto.Protocol),
					strings.ToLower(stat))
				fields[name] = value
			}
		}
		tags := map[string]string{
			"interface": "all",
		}
		acc.AddFields("net", fields, tags)
	}

	return nil
}

func init() {
	inputs.Add("net", func() telegraf.Input {
		return &NetIOStats{ps: system.NewSystemPS()}
	})
}
