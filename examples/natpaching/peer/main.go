package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pion/ice/v2"
	"github.com/pion/randutil"
)

//nolint
var (
	isControlling     bool
	iceAgent          *ice.Agent
	remoteAuthChannel chan string
)

const serverHost = "home.wida.cool:16666"

//const serverHost = "localhost:16666"

func main() { //nolint
	var (
		err          error
		conn         *ice.Conn
		nodeID       string
		remoteNodeID string
	//	hascandidate bool
	)
	remoteAuthChannel = make(chan string, 3)

	flag.BoolVar(&isControlling, "controlling", false, "is ICE Agent controlling")
	flag.StringVar(&nodeID, "n", "node1", "node id")
	flag.StringVar(&remoteNodeID, "r", "node2", "remote node id")
	flag.Parse()

	if isControlling {
		fmt.Println("Local Agent is controlling")
	} else {
		fmt.Println("Local Agent is controlled")
	}
	fmt.Print("Press 'Enter' when both processes have started")
	if _, err = bufio.NewReader(os.Stdin).ReadBytes('\n'); err != nil {
		panic(err)
	}

	uri, _ := ice.ParseURL("turn:stun.wida.cool:3478")

	uri.Password = "wida"
	uri.Username = "wida"
	iceAgent, err = ice.NewAgent(&ice.AgentConfig{
		Urls:         []*ice.URL{uri},
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
	})
	if err != nil {
		panic(err)
	}

	go func() {

		for {
			r, err := http.PostForm("http://"+serverHost+"/getRemoteAuth", url.Values{
				"nodeID": {remoteNodeID},
			})
			if err != nil {
				panic(err)
			}

			buf, err := ioutil.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}

			if len(buf) != 0 {
				tmep := strings.SplitN(string(buf), "|", 2)
				remoteAuthChannel <- tmep[0]
				remoteAuthChannel <- tmep[1]

				break
			}

			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		for {
			r, err := http.PostForm("http://"+serverHost+"/getCandidate", url.Values{
				"nodeID": {remoteNodeID},
			})
			if err != nil {
				panic(err)
			}

			buf, err := ioutil.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}

			//fmt.Println(string(buf))
			if len(buf) != 0 {
				c, err := ice.UnmarshalCandidate(string(buf))
				if err != nil {
					log.Printf("[ERR] %s", err)
				}

				if err := iceAgent.AddRemoteCandidate(c); err != nil {
					log.Printf("[ERR] %s", err)
				}
				//hascandidate = true
			}

			time.Sleep(2 * time.Second)
		}

	}()

	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		_, err = http.PostForm("http://"+serverHost+"/setCandidate", //nolint
			url.Values{
				"nodeID":    {nodeID},
				"candidate": {c.Marshal()},
			})
		if err != nil {
			panic(err)
		}
	}); err != nil {
		panic(err)
	}

	// When ICE Connection state has change print to stdout
	if err = iceAgent.OnConnectionStateChange(func(c ice.ConnectionState) {
		fmt.Printf("ICE Connection State has changed: %s\n", c.String())
	}); err != nil {
		panic(err)
	}

	// Get the local auth details and send to remote peer
	localUfrag, localPwd, err := iceAgent.GetLocalUserCredentials()
	if err != nil {
		panic(err)
	}

	_, err = http.PostForm("http://"+serverHost+"/setRemoteAuth", //nolint
		url.Values{
			"nodeID": {nodeID},
			"ufrag":  {localUfrag},
			"pwd":    {localPwd},
		})
	if err != nil {
		panic(err)
	}

	remoteUfrag := <-remoteAuthChannel
	remotePwd := <-remoteAuthChannel

	fmt.Println(remoteUfrag, remotePwd)

	/* 	for !hascandidate {
		time.Sleep(1 * time.Second)
	} */

	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}

	// Start the ICE Agent. One side must be controlled, and the other must be controlling
	if isControlling {
		conn, err = iceAgent.Dial(context.TODO(), remoteUfrag, remotePwd)
	} else {
		conn, err = iceAgent.Accept(context.TODO(), remoteUfrag, remotePwd)
	}
	if err != nil {
		panic(err)
	}

	// Send messages in a loop to the remote peer
	go func() {
		for {
			time.Sleep(time.Second * 3)
			val, err := randutil.GenerateCryptoRandomString(15, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err != nil {
				panic(err)
			}
			if _, err = conn.Write([]byte(val)); err != nil {
				panic(err)
			}
			fmt.Printf("Sent: '%s'\n", val)
		}
	}()

	// Receive messages in a loop from the remote peer
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Received: '%s'\n", string(buf[:n]))
	}
}
