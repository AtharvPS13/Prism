#include "fairness.h"
#include <iostream>
#include <iomanip>
#include <cmath>

FairnessReport computeFairness(
    const std::unordered_map<std::string, FlowStats>& flows)
{
    FairnessReport report;
    report.total_flows = 0;
    report.index       = 0.0;
    report.hog_bytes   = 0;
    report.hog_percent = 0.0;

    if (flows.empty()) return report;

    // Step 1: collect per-flow byte counts
    // we only count flows that actually transferred data
    double sum_x  = 0.0;  // sum of all bytes
    double sum_x2 = 0.0;  // sum of bytes squared
    long   total_bytes = 0;

    for (const auto& [key, flow] : flows) {
        if (flow.total_bytes <= 0) continue;

        double x = (double)flow.total_bytes;
        sum_x  += x;
        sum_x2 += x * x;
        total_bytes += flow.total_bytes;
        report.total_flows++;

        // track the biggest hog while we're iterating anyway
        // no extra pass needed — O(n) total
        if (flow.total_bytes > report.hog_bytes) {
            report.hog_bytes = flow.total_bytes;
            report.worst_hog = key;
        }
    }

    if (report.total_flows == 0) return report;

    // Step 2: apply Jain's formula
    // F = (sum_x)^2 / (n * sum_x^2)
    double n = (double)report.total_flows;
    report.index = (sum_x * sum_x) / (n * sum_x2);

    // Step 3: what % of total bandwidth did the hog take?
    if (total_bytes > 0)
        report.hog_percent = (report.hog_bytes * 100.0) / total_bytes;

    return report;
}

void printFairnessReport(const FairnessReport& report)
{
    std::cout << "\n========== FAIRNESS REPORT ==========\n";

    if (report.total_flows == 0) {
        std::cout << "No flows to analyse.\n";
        return;
    }

    // print the index with a visual bar so it's easy to read
    std::cout << "Flows analysed : " << report.total_flows << "\n";
    std::cout << "Fairness index : " << std::fixed << std::setprecision(3)
              << report.index << "  ";

    // visual bar — 20 chars wide
    int filled = (int)(report.index * 20);
    std::cout << "[";
    for (int i = 0; i < 20; i++)
        std::cout << (i < filled ? "█" : "░");
    std::cout << "]\n";

    // human readable verdict
    if      (report.index >= 0.9)
        std::cout << "Verdict        : FAIR — bandwidth well distributed\n";
    else if (report.index >= 0.7)
        std::cout << "Verdict        : MODERATE — some imbalance detected\n";
    else
        std::cout << "Verdict        : UNFAIR — significant hogging detected\n";

    std::cout << "\nBiggest hog    : " << report.worst_hog << "\n";
    std::cout << "Hog bytes      : " << report.hog_bytes << " bytes\n";
    std::cout << "Hog share      : " << std::fixed << std::setprecision(1)
              << report.hog_percent << "% of total traffic\n";
    std::cout << "=====================================\n";
}