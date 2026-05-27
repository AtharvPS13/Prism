#pragma once
#include <string>
#include <unordered_map>
#include "analyser/flow_tracker.h"
#include "analyser/fairness.h"
#include "analyser/classifier.h"

std::string buildJson(
    const std::unordered_map<std::string, FlowStats>& flows,
    const FairnessReport& report,
    const TrafficClassifier& classifier);

void startHttpServer(int port);
void updateSnapshot(const std::string& json);