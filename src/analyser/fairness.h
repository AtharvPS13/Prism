#pragma once
#include <unordered_map>
#include <string>
#include "flow_tracker.h"

// Result of fairness analysis
struct FairnessReport {
    double index;           // Jain's index 0.0 to 1.0
    std::string worst_hog;  // flow key of the biggest bandwidth hog
    long   hog_bytes;       // how many bytes that hog used
    int    total_flows;     // how many flows analysed
    double hog_percent;     // what % of total bandwidth the hog took
};

// takes the flow map from FlowTracker and computes fairness
FairnessReport computeFairness(
    const std::unordered_map<std::string, FlowStats>& flows);

// prints a human readable fairness report to terminal
void printFairnessReport(const FairnessReport& report);