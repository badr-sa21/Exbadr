import Foundation

enum PairStore {
    private static let key = "pcpulse_pair_config"

    static func save(_ config: PairConfig) {
        if let data = try? JSONEncoder().encode(config) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    static func load() -> PairConfig? {
        guard
            let data = UserDefaults.standard.data(forKey: key),
            let config = try? JSONDecoder().decode(PairConfig.self, from: data)
        else { return nil }
        return config
    }

    static func clear() {
        UserDefaults.standard.removeObject(forKey: key)
    }

    static func parsePairURL(_ text: String) -> PairConfig? {
        guard
            let components = URLComponents(string: text),
            components.scheme == "http",
            let host = components.host,
            let port = components.port
        else { return nil }

        let items = Dictionary(
            uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
                item.value.map { (item.name, $0) }
            }
        )

        guard let token = items["token"], !token.isEmpty else { return nil }
        let baseURL = "http://\(host):\(port)"
        return PairConfig(baseURL: baseURL, token: token)
    }
}
