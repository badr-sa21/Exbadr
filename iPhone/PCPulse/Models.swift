import Foundation

struct PCPulseStatus: Codable {
    let ok: Bool
    let timestamp: Int
    let pc_name: String
    let os: String
    let cpu_name: String
    let cpu_percent: Double
    let ram: RAMInfo
    let drives: [DriveInfo]
    let uptime_seconds: Int
}

struct RAMInfo: Codable {
    let total_gb: Double
    let used_gb: Double
    let available_gb: Double
    let percent: Double
}

struct DriveInfo: Codable, Identifiable {
    var id: String { name }
    let name: String
    let mountpoint: String
    let total_gb: Double
    let used_gb: Double
    let free_gb: Double
    let percent: Double
}

struct PairConfig: Codable, Equatable {
    let baseURL: String
    let token: String
}
