package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"ssl-tools/internal/handler"
)

type RegionsConfig struct {
	Regions []Region `json:"regions"`
}

type Region struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Default bool   `json:"default,omitempty"`
}

func main() {
	port := flag.String("port", getEnv("PORT", "18700"), "服务端口")
	flag.Parse()

	r := mux.NewRouter()

	api := r.PathPrefix("/api").Subrouter()

	diagnoseHandler := handler.NewDiagnoseHandler()
	api.HandleFunc("/diagnose", applyCORS(diagnoseHandler.Handle)).Methods("GET", "OPTIONS")
	api.HandleFunc("/health", applyCORS(healthHandler)).Methods("GET", "OPTIONS")
	api.HandleFunc("/regions", applyCORS(regionsHandler)).Methods("GET", "OPTIONS")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("SSL Tools 启动，端口 %s", *port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("服务启动失败: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭服务...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("关闭失败: %v", err)
	}
	log.Println("服务已关闭")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func regionsHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("regions.json")
	if err != nil {
		http.Error(w, "regions config not found", http.StatusInternalServerError)
		return
	}
	var config RegionsConfig
	if err := json.Unmarshal(data, &config); err != nil {
		http.Error(w, "invalid regions config", http.StatusInternalServerError)
		return
	}
	currentID := ""
	reqHost := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		reqHost = fwd
	}
	for _, region := range config.Regions {
		if strings.Contains(region.URL, reqHost) {
			currentID = region.ID
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"regions": config.Regions,
		"current": currentID,
	})
}

func applyCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
