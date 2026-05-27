#include "classifier.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

void TrafficClassifier::updateProfile(
    const std::string& flow_key,
    const std::string& src_ip,
    const std::string& flow_src_ip,
    int    size_bytes,
    double timestamp)
{
    FlowProfile& p = profiles[flow_key];

    // update packet size stats using running average
    int total_packets = p.forward_packets + p.backward_packets + 1;
    p.avg_packet_size += ((double)size_bytes - p.avg_packet_size) / total_packets;
    if (size_bytes < p.min_packet_size) p.min_packet_size = size_bytes;
    if (size_bytes > p.max_packet_size) p.max_packet_size = size_bytes;

    // track direction — is this packet going client→server or server→client?
    // we determine direction by comparing current src_ip to the flow's original src
    bool is_forward = (src_ip == flow_src_ip);
    if (is_forward) {
        p.forward_bytes   += size_bytes;
        p.forward_packets += 1;
    } else {
        p.backward_bytes   += size_bytes;
        p.backward_packets += 1;
    }

    // track inter-arrival time
    // IAT = time between consecutive packets in this flow
    if (p.last_packet_time > 0.0) {
        double iat_ms = (timestamp - p.last_packet_time) * 1000.0;
        if (iat_ms > 0 && iat_ms < 10000) {
            p.iat_samples++;
            // running average IAT
            p.avg_iat += (iat_ms - p.avg_iat) / p.iat_samples;
        }
    }
    p.last_packet_time = timestamp;

    // count small packets (under 100 bytes = likely control/ACK/gaming)
    if (size_bytes < 100) p.small_packet_count++;
}

ClassificationResult TrafficClassifier::classify(
    const std::string& flow_key) const
{
    ClassificationResult result;
    result.type       = TrafficType::UNKNOWN;
    result.label      = "UNKNOWN";
    result.confidence = 0.0;
    result.reason     = "insufficient data";

    auto it = profiles.find(flow_key);
    if (it == profiles.end()) return result;

    const FlowProfile& p = it->second;
    int total_packets = p.forward_packets + p.backward_packets;
    if (total_packets < 3) return result; // need minimum samples

    // compute key ratios for classification
    double total_bytes   = p.forward_bytes + p.backward_bytes;

    // backward ratio: how much data flows server→client
    // high = streaming or download, low = upload or gaming
    double backward_ratio = (total_bytes > 0)
        ? (double)p.backward_bytes / total_bytes : 0.5;

    // small packet ratio: high = gaming/voip, low = file transfer
    double small_ratio = (double)p.small_packet_count / total_packets;

    // now apply classification rules
    // these thresholds come from network traffic research papers

    // GAMING: tiny packets, very frequent, roughly equal directions
    // games send position updates ~30ms, small UDP-like bursts
    if (p.avg_packet_size < 150 &&
        p.avg_iat < 50 &&
        small_ratio > 0.5 &&
        backward_ratio > 0.3 && backward_ratio < 0.7)
    {
        result.type       = TrafficType::GAMING;
        result.label      = "GAMING";
        result.confidence = 0.75 + (small_ratio - 0.5) * 0.5;
        result.reason     = "small packets (" +
                            std::to_string((int)p.avg_packet_size) +
                            "B avg), fast IAT (" +
                            std::to_string((int)p.avg_iat) + "ms)";
        return result;
    }

    // VOIP: very small packets, very regular timing, bidirectional
    // voice calls send ~160 byte RTP packets every 20ms
    if (p.avg_packet_size < 250 &&
        p.avg_iat < 30 &&
        backward_ratio > 0.35 && backward_ratio < 0.65)
    {
        result.type       = TrafficType::VOIP;
        result.label      = "VOIP";
        result.confidence = 0.80;
        result.reason     = "regular tiny packets (" +
                            std::to_string((int)p.avg_iat) + "ms IAT)";
        return result;
    }

    // STREAMING: large packets, mostly server→client, steady flow
    // video streams send near-MTU packets continuously in one direction
    if (p.avg_packet_size > 800 &&
        backward_ratio > 0.75 &&
        small_ratio < 0.2)
    {
        result.type       = TrafficType::STREAMING;
        result.label      = "STREAMING";
        result.confidence = 0.70 + (backward_ratio - 0.75) * 0.6;
        result.reason     = "large packets (" +
                            std::to_string((int)p.avg_packet_size) +
                            "B), " +
                            std::to_string((int)(backward_ratio * 100)) +
                            "% server→client";
        return result;
    }

    // FILE TRANSFER: large packets, sustained, can be either direction
    // SCP/FTP sends near-MTU packets continuously
    if (p.avg_packet_size > 800 &&
        total_packets > 10 &&
        small_ratio < 0.15)
    {
        result.type       = TrafficType::FILE_TRANSFER;
        result.label      = "FILE TRANSFER";
        result.confidence = 0.70;
        result.reason     = "large sustained packets (" +
                            std::to_string((int)p.avg_packet_size) + "B avg)";
        return result;
    }

    // BROWSING: burst pattern — small request, large response, then quiet
    // HTTP request is tiny, response can be large, then connection idle
    if (p.avg_packet_size > 200 &&
        p.avg_packet_size < 900 &&
        backward_ratio > 0.55)
    {
        result.type       = TrafficType::BROWSING;
        result.label      = "BROWSING";
        result.confidence = 0.65;
        result.reason     = "request/response pattern, " +
                            std::to_string((int)(backward_ratio * 100)) +
                            "% server→client";
        return result;
    }

    // didn't match any pattern
    result.type       = TrafficType::UNKNOWN;
    result.label      = "UNKNOWN";
    result.confidence = 0.0;
    result.reason     = "no pattern matched (avg size: " +
                        std::to_string((int)p.avg_packet_size) + "B)";
    return result;
}

std::vector<std::pair<std::string, ClassificationResult>>
TrafficClassifier::classifyAll() const
{
    std::vector<std::pair<std::string, ClassificationResult>> results;
    for (const auto& [key, profile] : profiles)
        results.push_back({key, classify(key)});
    return results;
}

void TrafficClassifier::printClassifications() const
{
    std::cout << "\n========== TRAFFIC CLASSIFICATION ==========\n";
    std::cout << std::left
              << std::setw(45) << "Flow"
              << std::setw(16) << "Type"
              << std::setw(12) << "Confidence"
              << "Reason\n";
    std::cout << std::string(100, '-') << "\n";

    for (const auto& [key, result] : classifyAll()) {
        std::cout << std::left
                  << std::setw(45) << key
                  << std::setw(16) << result.label
                  << std::setw(12) << (std::to_string(
                                       (int)(result.confidence * 100)) + "%")
                  << result.reason << "\n";
    }
    std::cout << "============================================\n";
}

const FlowProfile* TrafficClassifier::getProfile(
    const std::string& key) const
{
    auto it = profiles.find(key);
    if (it == profiles.end()) return nullptr;
    return &it->second;
}