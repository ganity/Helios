import UIKit

@_cdecl("helios_swift_command")
func heliosSwiftCommand(_ pointer: UnsafePointer<CChar>?) {
    guard let pointer else { return }
    let json = String(cString: pointer)
    DispatchQueue.main.async { VPNController.shared.command(json) }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var host: UnsafeMutableRawPointer?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let controller = UIViewController()
        controller.overrideUserInterfaceStyle = .dark
        controller.view.backgroundColor = UIColor(red: 12 / 255, green: 23 / 255, blue: 19 / 255, alpha: 1)
        window.rootViewController = controller
        self.window = window
        window.makeKeyAndVisible()
        do {
            let directory = try HeliosContainer.url().appendingPathComponent("Helios", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
            helios_ios_register(heliosSwiftCommand)
            VPNController.shared.start()
            host = directory.path.withCString {
                helios_ui_create($0, Double(controller.view.bounds.width), Double(controller.view.bounds.height))
            }
            guard let host, let pointer = helios_ui_view(host) else {
                throw HeliosContainer.error("无法启动 NSH 界面")
            }
            let view = Unmanaged<UIView>.fromOpaque(pointer).takeUnretainedValue()
            controller.view.addSubview(view)
            view.translatesAutoresizingMaskIntoConstraints = false
            NSLayoutConstraint.activate([
                view.leadingAnchor.constraint(equalTo: controller.view.safeAreaLayoutGuide.leadingAnchor),
                view.trailingAnchor.constraint(equalTo: controller.view.safeAreaLayoutGuide.trailingAnchor),
                view.topAnchor.constraint(equalTo: controller.view.safeAreaLayoutGuide.topAnchor),
                view.bottomAnchor.constraint(equalTo: controller.view.safeAreaLayoutGuide.bottomAnchor)
            ])
            if let url = options?[.url] as? URL { open(url) }
        } catch {
            let label = UILabel()
            label.text = error.localizedDescription
            label.textColor = .white
            label.numberOfLines = 0
            label.frame = controller.view.bounds.insetBy(dx: 24, dy: 64)
            controller.view.addSubview(label)
        }
        return true
    }

    func application(_ app: UIApplication, open url: URL,
                     options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool { open(url) }

    @discardableResult private func open(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "helios", url.absoluteString.utf8.count <= 16384 else { return false }
        VPNController.shared.publish(["link": url.absoluteString])
        return true
    }

    func applicationDidBecomeActive(_ application: UIApplication) { VPNController.shared.resume() }
    func applicationDidEnterBackground(_ application: UIApplication) { VPNController.shared.pause() }
}
