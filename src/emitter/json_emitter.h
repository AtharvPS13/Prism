#pragma once
#include <string>
#include <unordered_map>
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include "analyser/classifier.h"
#include "analyser/topology.h"
#include "analyser/tcp_state.h"

std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport&    report,
    const TrafficClassifier& classifier,
    const TopologyInferrer&  topology,
    const TCPStateTracker&   tcp_tracker);

void startHttpServer(int port);
void updateSnapshot(const std::string& json);