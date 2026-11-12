import Foundation

enum HeliosContainer {
    static func url() throws -> URL {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "HeliosAppGroup") as? String,
              let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw error("无法打开共享存储，请检查 App Group 配置")
        }
        return url
    }

    static func error(_ message: String) -> NSError {
        NSError(domain: "com.helios.mobile", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
