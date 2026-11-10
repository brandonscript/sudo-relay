import AppKit

@MainActor
public final class NativeReviewForm: NSView {
    public let share = NSButton(checkboxWithTitle: "Share command output with the agent (test preference)", target: nil, action: nil)
    public let requestText = NSTextView(frame: NSRect(x: 0, y: 0, width: 532, height: 96))
    public let approve = NSButton(title: "Approve with Touch ID", target: nil, action: nil)
    public let deny = NSButton(title: "Deny", target: nil, action: nil)
    public let expiry = NSTextField(labelWithString: "")
    private let review: AuthenticatedReview
    private let details: String
    public override var isFlipped: Bool { true }

    public init(review: AuthenticatedReview) throws {
        self.review = review; details = try review.reviewText()
        super.init(frame: NSRect(x: 0, y: 0, width: 580, height: 466))
        let icon = NSImageView(frame: NSRect(x: 24, y: 21, width: 24, height: 24))
        icon.image = NSImage(systemSymbolName: "shield", accessibilityDescription: nil)?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 24, weight: .regular))
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.contentTintColor = .labelColor
        addSubview(icon)
        let title = label("Approval test", frame: NSRect(x: 58, y: 21, width: 240, height: 30))
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        expiry.frame = NSRect(x: 324, y: 24, width: 232, height: 22)
        expiry.alignment = .right; expiry.textColor = .secondaryLabelColor
        expiry.font = .monospacedDigitSystemFont(ofSize: 13, weight: .regular)
        expiry.setAccessibilityLabel("Approval time remaining")
        addSubview(expiry)
        label("\(review.request.machine) · \(review.request.operatingSystem) · \(review.request.account)", frame: NSRect(x: 24, y: 77, width: 532, height: 22), muted: true)
        label("What you’re approving", frame: NSRect(x: 24, y: 116, width: 532, height: 22), muted: true)
        let purpose = label("Record one signed test receipt for the command below. Nothing runs.", frame: NSRect(x: 24, y: 144, width: 532, height: 40))
        purpose.font = .systemFont(ofSize: 15)
        purpose.lineBreakMode = .byWordWrapping; purpose.maximumNumberOfLines = 2
        label("Example command · Not executed", frame: NSRect(x: 24, y: 191, width: 532, height: 22), muted: true)
        requestText.string = review.commandText()
        requestText.isEditable = false; requestText.isSelectable = true
        requestText.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        requestText.textColor = .labelColor; requestText.backgroundColor = .controlBackgroundColor
        requestText.textContainer?.widthTracksTextView = true
        requestText.isHorizontallyResizable = false; requestText.isVerticallyResizable = true
        requestText.textContainerInset = NSSize(width: 12, height: 12)
        let scroll = NSScrollView(frame: NSRect(x: 24, y: 218, width: 532, height: 96))
        scroll.documentView = requestText; scroll.hasVerticalScroller = true; scroll.borderType = .noBorder
        scroll.backgroundColor = .controlBackgroundColor
        scroll.wantsLayer = true; scroll.layer?.cornerRadius = 12; scroll.layer?.masksToBounds = true
        addSubview(scroll)
        let detailsButton = NSButton(title: "Details…", target: self, action: #selector(showDetails))
        detailsButton.frame = NSRect(x: 24, y: 325, width: 100, height: 28)
        addSubview(detailsButton)
        share.frame = NSRect(x: 24, y: 365, width: 532, height: 26); share.state = .off
        addSubview(share)
        approve.frame = NSRect(x: 24, y: 410, width: 414, height: 32)
        deny.frame = NSRect(x: 450, y: 410, width: 106, height: 32)
        for button in [approve, deny] { button.bezelStyle = .rounded; button.controlSize = .large; addSubview(button) }
        approve.keyEquivalent = "\r"; approve.keyEquivalentModifierMask = []
        deny.keyEquivalent = "\u{1b}"; deny.keyEquivalentModifierMask = []
        refresh(now: Int64(Date().timeIntervalSince1970))
    }

    @available(*, unavailable)
    public required init?(coder: NSCoder) { fatalError("Not supported") }

    @discardableResult
    private func label(_ text: String, frame: NSRect, muted: Bool = false) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.frame = frame
        label.textColor = muted ? .secondaryLabelColor : .labelColor
        addSubview(label)
        return label
    }

    public func refresh(now: Int64) {
        let remaining = max(0, review.request.expiresAt - now)
        expiry.stringValue = remaining == 0 ? "Approval expired" : "Approve within \(remaining / 60):\(String(format: "%02d", remaining % 60))"
        deny.title = remaining == 0 ? "Close" : "Deny"
        approve.isEnabled = now >= review.request.createdAt && now < review.request.expiresAt
        share.isEnabled = approve.isEnabled
    }

    @objc private func showDetails() {
        let alert = NSAlert()
        alert.messageText = "Test request details"
        alert.informativeText = details
        alert.addButton(withTitle: "Back to review")
        alert.runModal()
    }
}

@MainActor
public final class NativeReviewPanel: NSPanel, NSWindowDelegate {
    public let form: NativeReviewForm

    public init(review: AuthenticatedReview) throws {
        form = try NativeReviewForm(review: review)
        super.init(contentRect: form.bounds, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        title = "Approval test"; titleVisibility = .hidden
        contentView = form; delegate = self
        isReleasedWhenClosed = false
        defaultButtonCell = form.approve.cell as? NSButtonCell
        form.approve.target = self; form.approve.action = #selector(approveReview)
        form.deny.target = self; form.deny.action = #selector(denyReview)
    }

    public func runReview() -> Bool {
        let timer = Timer(timeInterval: 1, target: self, selector: #selector(updateExpiry), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .modalPanel)
        defer { timer.invalidate(); orderOut(nil) }
        center(); makeKeyAndOrderFront(nil)
        return NSApplication.shared.runModal(for: self) == .OK
    }

    @objc private func updateExpiry() { form.refresh(now: Int64(Date().timeIntervalSince1970)) }
    @objc private func approveReview() {
        updateExpiry()
        if form.approve.isEnabled { NSApplication.shared.stopModal(withCode: .OK) }
    }
    @objc private func denyReview() { NSApplication.shared.stopModal(withCode: .cancel) }
    public func windowWillClose(_ notification: Notification) { denyReview() }
}
