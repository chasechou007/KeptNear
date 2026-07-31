import AppKit
import Foundation
@preconcurrency import UserNotifications

private let approvalNotificationIdentifierPrefix = "keptnear.pending-request."

@MainActor
protocol ApprovalNotificationScheduling: AnyObject {
    func prepare()
    func postPendingRequest(identifier: String, title: String, body: String)
    func reconcile(activeRequestIdentifiers: Set<String>)
}

@MainActor
final class MacApprovalNotificationScheduler: ApprovalNotificationScheduling {
    private let center: UNUserNotificationCenter
    private let applicationIsActive: @MainActor () -> Bool

    init(
        center: UNUserNotificationCenter = .current(),
        applicationIsActive: @escaping @MainActor () -> Bool = {
            NSApp?.isActive ?? true
        }
    ) {
        self.center = center
        self.applicationIsActive = applicationIsActive
    }

    func prepare() {
        center.getNotificationSettings { [center] settings in
            guard settings.authorizationStatus == .notDetermined else { return }
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
    }

    func postPendingRequest(identifier: String, title: String, body: String) {
        guard !applicationIsActive() else { return }

        let notificationIdentifier = approvalNotificationIdentifierPrefix + identifier
        center.getNotificationSettings { [center] settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                content.sound = .default
                center.add(
                    UNNotificationRequest(
                        identifier: notificationIdentifier,
                        content: content,
                        trigger: nil
                    )
                )
            case .denied, .notDetermined:
                break
            @unknown default:
                break
            }
        }
    }

    func reconcile(activeRequestIdentifiers: Set<String>) {
        let active = Set(
            activeRequestIdentifiers.map { approvalNotificationIdentifierPrefix + $0 }
        )
        center.getPendingNotificationRequests { [center] requests in
            let stale = requests
                .map(\.identifier)
                .filter {
                    $0.hasPrefix(approvalNotificationIdentifierPrefix) && !active.contains($0)
                }
            center.removePendingNotificationRequests(withIdentifiers: stale)
        }
        center.getDeliveredNotifications { [center] notifications in
            let stale = notifications
                .map { $0.request.identifier }
                .filter {
                    $0.hasPrefix(approvalNotificationIdentifierPrefix) && !active.contains($0)
                }
            center.removeDeliveredNotifications(withIdentifiers: stale)
        }
    }
}
