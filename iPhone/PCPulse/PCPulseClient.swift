import Foundation

@MainActor
final class PCPulseClient: ObservableObject {
    @Published var status: PCPulseStatus?
    @Published var connectionText = "Not connected"
    @Published var isConnected = false
    @Published var lastError: String?

    private var config: PairConfig?
    private var timer: Timer?

    init() {
        self.config = PairStore.load()
        if config != nil {
            connectionText = "Ready"
            start()
        }
    }

    func pair(_ config: PairConfig) {
        self.config = config
        PairStore.save(config)
        connectionText = "Connecting…"
        start()
    }

    func forget() {
        timer?.invalidate()
        timer = nil
        PairStore.clear()
        config = nil
        status = nil
        isConnected = false
        connectionText = "Not connected"
        lastError = nil
    }

    func start() {
        timer?.invalidate()
        Task { await refresh() }

        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { await self?.refresh() }
        }
    }

    func refresh() async {
        guard let config else { return }

        guard let url = URL(string: config.baseURL + "/api/status") else {
            lastError = "Invalid PC address"
            return
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 4
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue(config.token, forHTTPHeaderField: "X-PCPulse-Token")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard
                let http = response as? HTTPURLResponse,
                http.statusCode == 200
            else {
                throw URLError(.badServerResponse)
            }

            let decoded = try JSONDecoder().decode(PCPulseStatus.self, from: data)
            status = decoded
            isConnected = true
            connectionText = "Connected"
            lastError = nil
        } catch {
            isConnected = false
            connectionText = "Disconnected"
            lastError = error.localizedDescription
        }
    }
}
