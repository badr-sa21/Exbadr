import SwiftUI

struct ContentView: View {
    @StateObject private var client = PCPulseClient()
    @State private var showingScanner = false
    @State private var scanMessage: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 18) {
                    header

                    if let status = client.status {
                        statusCards(status)
                        driveCards(status.drives)
                    } else {
                        emptyState
                    }

                    if let error = client.lastError {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }

                    controls
                }
                .padding()
            }
            .navigationTitle("PC Pulse")
            .sheet(isPresented: $showingScanner) {
                QRScannerView { code in
                    guard let config = PairStore.parsePairURL(code) else {
                        scanMessage = "That QR is not a PC Pulse pairing code."
                        return
                    }
                    client.pair(config)
                    scanMessage = "PC paired."
                }
                .ignoresSafeArea()
            }
            .alert("PC Pulse", isPresented: Binding(
                get: { scanMessage != nil },
                set: { if !$0 { scanMessage = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(scanMessage ?? "")
            }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text(client.status?.pc_name ?? "Your PC")
                    .font(.title2.bold())

                HStack(spacing: 7) {
                    Circle()
                        .fill(client.isConnected ? Color.green : Color.secondary)
                        .frame(width: 9, height: 9)
                    Text(client.connectionText)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button {
                Task { await client.refresh() }
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.title3)
                    .frame(width: 44, height: 44)
            }
            .buttonStyle(.bordered)
        }
    }

    @ViewBuilder
    private func statusCards(_ s: PCPulseStatus) -> some View {
        HStack(spacing: 12) {
            MetricCard(
                title: "CPU",
                value: String(format: "%.0f%%", s.cpu_percent),
                progress: s.cpu_percent / 100,
                icon: "cpu"
            )

            MetricCard(
                title: "RAM",
                value: String(format: "%.0f%%", s.ram.percent),
                progress: s.ram.percent / 100,
                icon: "memorychip"
            )
        }

        VStack(alignment: .leading, spacing: 8) {
            Label("System", systemImage: "desktopcomputer")
                .font(.headline)

            Text(s.os)
                .foregroundStyle(.secondary)

            Text("Uptime: \(formatUptime(s.uptime_seconds))")
                .foregroundStyle(.secondary)

            Text("\(String(format: "%.1f", s.ram.used_gb)) / \(String(format: "%.1f", s.ram.total_gb)) GB RAM")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 20))
    }

    @ViewBuilder
    private func driveCards(_ drives: [DriveInfo]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Storage")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)

            ForEach(drives) { drive in
                VStack(alignment: .leading, spacing: 9) {
                    HStack {
                        Text(drive.name)
                            .font(.headline)
                        Spacer()
                        Text("\(String(format: "%.1f", drive.free_gb)) GB free")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    ProgressView(value: drive.percent, total: 100)

                    Text("\(String(format: "%.1f", drive.used_gb)) / \(String(format: "%.1f", drive.total_gb)) GB used")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding()
                .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 18))
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 54))
            Text("Pair your PC")
                .font(.title3.bold())
            Text("Run PC Pulse on Windows, then scan its QR code.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 38)
    }

    private var controls: some View {
        VStack(spacing: 12) {
            Button {
                showingScanner = true
            } label: {
                Label("Scan PC QR", systemImage: "qrcode.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            if client.status != nil || client.isConnected {
                Button(role: .destructive) {
                    client.forget()
                } label: {
                    Label("Forget PC", systemImage: "trash")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func formatUptime(_ seconds: Int) -> String {
        var s = seconds
        let days = s / 86400
        s %= 86400
        let hours = s / 3600
        s %= 3600
        let minutes = s / 60

        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        return "\(minutes)m"
    }
}

struct MetricCard: View {
    let title: String
    let value: String
    let progress: Double
    let icon: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: icon)
                .font(.headline)

            Text(value)
                .font(.system(size: 34, weight: .bold, design: .rounded))

            ProgressView(value: min(max(progress, 0), 1))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 20))
    }
}
