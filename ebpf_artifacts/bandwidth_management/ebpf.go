package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func attachEbpf(objs *programObjects) {

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	defer objs.Close()

	// EC2 Requirements https://trying2adult.com/what-is-xdp-and-how-do-you-use-it-in-linux-amazon-ec2-example/
	// sudo ethtool -L ens5 combined 1
	// sudo ip link set dev ens5 mtu 1500
	// sudo ethtool -l ens5
	// Attach count_packets to the network interface.
	// link, err := link.AttachXDP(link.XDPOptions{
	// 	Program:   objs.CountPackets,
	// 	Interface: iface.Index,
	// })
	// if err != nil {
	// 	panic(err.Error())
	// }
	// defer link.Close()

	rd, err := ringbuf.NewReader(objs.EventBuff)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stop

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	go func() {
		log.Println("Waiting for events..")
		var event programEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			log.Printf("Flow stopped. Exceeded max rate. Source IP address: %s, Destination IP address: %s, Current Count: %d\n", formatIp(event.Saddr), formatIp(event.Daddr), event.Count)
		}
	}()

	attachProgramToInterfacesLoop(objs.RateLimit, netlink.HANDLE_MIN_INGRESS)
}

func LoadMapSpecs() programMapSpecs {
	spec, err := loadProgram()
	if err != nil {
		panic(err.Error())
	}

	var specs programMapSpecs
	if err := spec.Assign(&specs); err != nil {
		panic(err)
	}

	return specs
}

func LoadObjects(opts *ebpf.CollectionOptions) *programObjects {
	var objs programObjects
	err := loadProgramObjects(&objs, opts)

	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		log.Fatalf("Verifier error loading eBPF objects: %+v\n", ve)
	} else if err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	return &objs
}

// Fetches all relevant network interfaces
// Can specify which network interfaces to fetch using the INTERFACE_SUBSTRING environment variable.
func getNetworkInterfaces() ([]net.Interface, error) {
	interfaceList, err := net.Interfaces()
	resultingList := make([]net.Interface, 0, 1)

	if err != nil {
		log.Fatalf("Getting interface: %s", err)
	}

	ifSubstring := ""
	if ifSubstring = os.Getenv("INTERFACE_SUBSTRING"); ifSubstring == "" {
		ifSubstring = "wlp"
	}

	log.Printf("Interface name: %s", ifSubstring)

	ifNames := strings.Split(ifSubstring, ",")

	for _, iface := range interfaceList {
		for _, ifName := range ifNames {
			if strings.Contains(iface.Name, ifName) {
				resultingList = append(resultingList, iface)
			}
		}

	}

	if len(resultingList) > 0 {
		return resultingList, nil
	} else {
		return resultingList, fmt.Errorf("interface not found with INTERFACE_SUBSTRING %s", os.Getenv("INTERFACE_SUBSTRING"))
	}
}

// Adds a qdics to a network interface
// Uses the clsact type
func addQDisc(iface net.Interface) (*netlink.GenericQdisc, error) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact", // https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
	}

	err := netlink.QdiscAdd(qdisc)
	return qdisc, err
}

func deleteQDisc(qdisc *netlink.GenericQdisc) error {
	return netlink.QdiscDel(qdisc)
}

// Adds a bpf filter containing the eBPF program to a network interface
// Direct action set to true, as recommneded by https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
func attachTCProgram(iface net.Interface, program ebpf.Program, attr netlink.FilterAttrs) error {

	return netlink.FilterAdd(&netlink.BpfFilter{
		FilterAttrs:  attr,
		Fd:           program.FD(),
		Name:         "rate_limiter",
		DirectAction: true,
	})
}

// Attaches the eBPF program to the Traffic Control hook on the network interfaces specified by INTERFACE_SUBSTRING
func attachProgramToInterfaces(program *ebpf.Program, parent uint32) []*netlink.GenericQdisc {
	ifaces, err := getNetworkInterfaces()
	qdiscs := []*netlink.GenericQdisc{}

	if err != nil {
		panic(err.Error())
	}

	for _, iface := range ifaces {

		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			log.Printf("Failed to get link: %v", err)
		}

		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			log.Printf("Failed to list filters: %v", err)
		}
		// Checks that the eBPF program does not already exists on the hook
		var pass = false
		for _, filter := range filters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if bpfFilter.Name == "rate_limiter" {
					pass = true
				}
			}
		}

		if pass {
			continue
		}

		var qdiscPass = false
		qdiscList, err := netlink.QdiscList(link)
		if err != nil {
			log.Printf("Failed to get qdisc: %v", err)
		}

		for _, qdisc := range qdiscList {
			if qdisc.Attrs().Parent == netlink.HANDLE_CLSACT {
				qdiscPass = true
			}
		}
		if !qdiscPass {
			qdisc, err := addQDisc(iface)
			if err != nil {
				log.Printf("Failed to add qdisc: %v", err)
			}
			qdiscs = append(qdiscs, qdisc)
		}

		err = attachTCProgram(iface, *program, netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    parent,
			Protocol:  unix.ETH_P_ALL,
		})
		if err != nil {
			log.Fatal("Attaching TC:", err)
		}

		log.Printf("Listening for incoming UDP or TCP packets on %s..\n", iface.Name)
	}

	return qdiscs
}

// Continously checks for new network interfaces, and attaches the eBPF program to them
func attachProgramToInterfacesLoop(program *ebpf.Program, parent uint32) {
	qdiscs := attachProgramToInterfaces(program, parent)

	// Removes the qdisc from the network interface when the application is stopped
	for _, qdisc := range qdiscs {
		defer deleteQDisc(qdisc)
	}

	tick := time.Tick(10 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			qdiscs := attachProgramToInterfaces(program, parent)
			for _, qdisc := range qdiscs {
				defer deleteQDisc(qdisc)
			}

		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}

func formatIp(sourceAddress [4]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", sourceAddress[0], sourceAddress[1], sourceAddress[2], sourceAddress[3])
}
