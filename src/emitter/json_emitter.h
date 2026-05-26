#pragma once
#include <string>
#include <unordered_map>
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"

// converts current flow stats + fairness report into a JSON string
std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport& report);

// starts a simple HTTP server on localhost:8080
// serves the latest JSON snapshot when React requests it
// runs in a background thread so capture can continue
void startHttpServer(int port);

// update the JSON that the server will serve
// called every second from main after recomputing stats
void updateSnapshot(const std::string& json);