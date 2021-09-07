package main

import (
	"fmt"
	"net/http"
)

var candidateMap = make(map[string]string, 10)
var authMap = make(map[string]string)

func setRemoteAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}
	nodeID := r.PostForm["nodeID"][0]

	authMap[nodeID] = r.PostForm["ufrag"][0] + "|" + r.PostForm["pwd"][0]
	w.Write([]byte("ok"))
}

func getRemoteAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}
	nodeID := r.PostForm["nodeID"][0]
	if nodeID != "" {
		w.Write([]byte(authMap[nodeID]))
		return
	}
	w.Write([]byte(""))
}

// HTTP Listener to get ICE Candidate from remote Peer
func setCandidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}
	nodeID := r.PostForm["nodeID"][0]
	if nodeID != "" {
		candidateMap[nodeID] = r.PostForm["candidate"][0]
	}
	w.Write([]byte("ok"))
}

// HTTP Listener to get ICE Candidate from remote Peer
func getCandidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}
	nodeID := r.PostForm["nodeID"][0]
	w.Write([]byte(candidateMap[nodeID]))
}

func main() {
	http.HandleFunc("/setRemoteAuth", setRemoteAuth)
	http.HandleFunc("/getRemoteAuth", getRemoteAuth)
	http.HandleFunc("/setCandidate", setCandidate)
	http.HandleFunc("/getCandidate", getCandidate)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", 16666), nil); err != nil {
		panic(err)
	}
}
